use super::*;
use std::net::Ipv4Addr;

#[derive(Default)]
struct ReservationTracker {
    mark_calls: usize,
    release_calls: usize,
    conservative_calls: usize,
    settled: Vec<ModelUsage>,
    observed: Vec<ModelUsage>,
    fail_mark: bool,
}

impl EgressRequestAuthorizer for ReservationTracker {
    fn authorize(
        &mut self,
        _method: &str,
        _path: &str,
        _body_digest: [u8; 32],
        _model_budget: Option<ModelBudgetRequest>,
    ) -> Result<(), String> {
        Ok(())
    }

    fn record_response(&mut self) -> Result<(), String> {
        Ok(())
    }

    fn mark_model_request_send_attempted(&mut self) -> Result<(), String> {
        self.mark_calls += 1;
        if self.fail_mark {
            Err("send transition refused".to_owned())
        } else {
            Ok(())
        }
    }

    fn record_model_usage(&mut self, usage: ModelUsage) -> Result<(), String> {
        self.settled.push(usage);
        Ok(())
    }

    fn release_model_reservation(&mut self) -> Result<(), String> {
        self.release_calls += 1;
        Ok(())
    }

    fn commit_model_reservation_conservatively(&mut self) -> Result<(), String> {
        self.conservative_calls += 1;
        Ok(())
    }

    fn commit_model_reservation_observed(&mut self, usage: ModelUsage) -> Result<(), String> {
        self.observed.push(usage);
        Ok(())
    }
}

#[test]
fn definitely_unsent_model_request_is_the_only_refund_path() {
    let mut authorizer = ReservationTracker {
        fail_mark: true,
        ..ReservationTracker::default()
    };
    let error = begin_model_send(&mut authorizer, true).unwrap_err();
    assert!(error.to_string().contains("send transition refused"));
    assert_eq!(authorizer.mark_calls, 1);
    assert_eq!(authorizer.release_calls, 1);
    assert_eq!(authorizer.conservative_calls, 0);
    assert!(authorizer.settled.is_empty());
}

#[test]
fn model_preparation_failure_releases_before_any_send_transition() {
    let target = ConnectionTarget {
        server_name: "api.anthropic.com".to_owned(),
        resolved_ip: Ipv4Addr::new(93, 184, 216, 34).into(),
        port: 443,
    };
    let body = br#"{"model":"claude-opus-5","max_tokens":32}"#;
    let request = format!(
        "POST /v1/messages HTTP/1.1\r\nHost: api.anthropic.com\r\n\
         Authorization: Bearer {}\r\nContent-Length: {}\r\n\r\n{}",
        SystemEgressConnector::MODEL_SENTINEL,
        body.len(),
        std::str::from_utf8(body).unwrap()
    );
    let mut authorizer = ReservationTracker::default();
    let result = prepare_upstream_request_with_authorizer(
        &target,
        &CredentialVault::new(),
        request.as_bytes(),
        &mut authorizer,
        false,
    );
    let Err(error) = result else {
        panic!("credential injection without a binding must fail");
    };

    assert!(error.to_string().contains("sentinel has no binding"));
    assert_eq!(authorizer.mark_calls, 0);
    assert_eq!(authorizer.release_calls, 1);
    assert_eq!(authorizer.conservative_calls, 0);
}

#[test]
fn ambiguous_model_transport_failure_keeps_the_conservative_charge() {
    let mut authorizer = ReservationTracker::default();
    begin_model_send(&mut authorizer, true).unwrap();
    let original = TlsError("upstream response: connection reset".to_owned());
    let returned = commit_after_possible_send(&mut authorizer, true, original.clone());
    assert_eq!(returned, original);
    assert_eq!(authorizer.mark_calls, 1);
    assert_eq!(authorizer.release_calls, 0);
    assert_eq!(authorizer.conservative_calls, 1);
    assert!(authorizer.settled.is_empty());
}

#[test]
fn complete_model_response_settles_actual_usage() {
    let mut authorizer = ReservationTracker::default();
    let body = br#"{"usage":{"input_tokens":3,"output_tokens":1}}"#;
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        std::str::from_utf8(body).unwrap()
    );
    settle_complete_model_response(&mut authorizer, response.as_bytes()).unwrap();
    assert_eq!(
        authorizer.settled,
        [ModelUsage {
            input_tokens: 3,
            output_tokens: 1,
        }]
    );
    assert_eq!(authorizer.release_calls, 0);
    assert_eq!(authorizer.conservative_calls, 0);
}

#[test]
fn complete_non_success_response_is_not_refunded() {
    let mut authorizer = ReservationTracker::default();
    let body = br#"{"type":"error","usage":{"input_tokens":1,"output_tokens":1}}"#;
    let response = format!(
        "HTTP/1.1 400 Bad Request\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        std::str::from_utf8(body).unwrap()
    );
    settle_complete_model_response(&mut authorizer, response.as_bytes()).unwrap();
    assert_eq!(authorizer.release_calls, 0);
    assert_eq!(authorizer.conservative_calls, 1);
    assert!(authorizer.settled.is_empty());
}

#[test]
fn partial_usage_cannot_reduce_the_conservative_reservation() {
    for body in [
        br#"{"usage":{}}"#.as_slice(),
        br#"{"usage":{"input_tokens":3}}"#.as_slice(),
        br#"{"usage":{"output_tokens":1}}"#.as_slice(),
        br#"{"amazon-bedrock-invocationMetrics":{"inputTokenCount":3}}"#.as_slice(),
    ] {
        let mut authorizer = ReservationTracker::default();
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            std::str::from_utf8(body).unwrap()
        );
        let error = settle_complete_model_response(&mut authorizer, response.as_bytes())
            .expect_err("partial usage must fail closed");
        assert!(error.to_string().contains("incomplete trusted usage"));
        assert_eq!(authorizer.release_calls, 0);
        assert_eq!(authorizer.conservative_calls, 1);
        assert!(authorizer.settled.is_empty());
    }
}

const STREAM_HEAD: &str = "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\n";
const MESSAGE_START: &str = "data: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":1200,\"cache_read_input_tokens\":300,\"output_tokens\":1}}}\n\n";

fn interrupted(partial: &str) -> ReservationTracker {
    let mut authorizer = ReservationTracker::default();
    let failure = RelayFailure {
        error: TlsError("upstream response: timed out".to_owned()),
        partial: partial.as_bytes().to_vec(),
    };
    let error = commit_after_interrupted_response(&mut authorizer, true, failure);
    assert!(error.to_string().contains("timed out"));
    authorizer
}

#[test]
fn an_interrupted_stream_is_charged_its_stated_input_and_streamed_output() {
    let delta = "data: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"0123456789\"}}\n\n";
    // The last event is cut off mid-line and must be ignored, not fail.
    let partial =
        format!("{STREAM_HEAD}{MESSAGE_START}{delta}{delta}data: {{\"type\":\"content_blo");
    let authorizer = interrupted(&partial);
    assert_eq!(authorizer.conservative_calls, 0);
    assert_eq!(
        authorizer.observed,
        [ModelUsage {
            input_tokens: 1_500,
            output_tokens: 20 + INTERRUPTED_OUTPUT_MARGIN_TOKENS,
        }]
    );
}

#[test]
fn an_interrupted_stream_without_stated_input_keeps_the_full_charge() {
    for partial in [
        String::new(),
        "HTTP/1.1 200 OK\r\nContent-Type: text/event-".to_owned(),
        STREAM_HEAD.to_owned(),
        format!(
            "HTTP/1.1 529 Overloaded\r\nContent-Type: text/event-stream\r\n\r\n{MESSAGE_START}"
        ),
        format!("{STREAM_HEAD}data: {{not json}}\n\n{MESSAGE_START}"),
    ] {
        let authorizer = interrupted(&partial);
        assert_eq!(authorizer.conservative_calls, 1, "{partial:?}");
        assert!(authorizer.observed.is_empty());
    }
}

#[test]
fn an_interrupted_chunked_stream_counts_only_complete_chunks() {
    let head =
        "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n";
    let partial = format!(
        "{head}{:x}\r\n{MESSAGE_START}\r\n40\r\ndata: trunc",
        MESSAGE_START.len()
    );
    let authorizer = interrupted(&partial);
    assert_eq!(
        authorizer.observed,
        [ModelUsage {
            input_tokens: 1_500,
            output_tokens: 1 + INTERRUPTED_OUTPUT_MARGIN_TOKENS,
        }]
    );
}
