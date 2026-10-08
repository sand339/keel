#![doc = "`OpenRouter` runs are priced, pinned, and routed only as admitted."]

use keel_secrets::{
    ConnectionTarget, OPENROUTER_HOST, SystemEgressConnector, openrouter_snapshot,
    runtime_model_provider, sanitize_model_request, validate_model_tariff,
};
use std::net::{IpAddr, Ipv4Addr};

#[test]
fn openrouter_runs_are_priced_pinned_and_routed_only_as_admitted() {
    // SAFETY: this binary's only test sets the variables before any other
    // thread exists or reads the environment.
    unsafe {
        std::env::set_var("KEEL_MODEL_AUTH", "openrouter");
        std::env::set_var("KEEL_OPENROUTER_TARIFF", "anthropic/claude-sonnet-4.6=7,17");
    }
    let provider = runtime_model_provider().expect("provider");
    assert_eq!(provider.host, OPENROUTER_HOST);
    assert_eq!(
        provider.sentinel,
        SystemEgressConnector::OPENROUTER_SENTINEL
    );
    assert_eq!(provider.region, None);
    assert_eq!(
        openrouter_snapshot(),
        Some(("anthropic/claude-sonnet-4.6".to_owned(), 7, 17))
    );
    validate_model_tariff(&provider, "anthropic/claude-sonnet-4.6").expect("pinned model");
    validate_model_tariff(&provider, "anthropic/claude-sonnet-4.6[1m]")
        .expect("long-context marker");
    assert!(
        validate_model_tariff(&provider, "openai/gpt-5").is_err(),
        "a model outside the snapshot has no price"
    );

    let target = ConnectionTarget {
        server_name: OPENROUTER_HOST.to_owned(),
        resolved_ip: IpAddr::V4(Ipv4Addr::new(104, 18, 2, 115)),
        port: 443,
    };
    let body = serde_json::json!({
        "model": "anthropic/claude-sonnet-4.6",
        "max_tokens": 1024,
        "messages": [{"role": "user", "content": "hi"}],
        "models": ["openai/gpt-5"],
        "route": "fallback",
        "provider": {"order": ["some-cheaper-host"]},
        "plugins": [{"id": "web"}],
    });
    let sanitized =
        sanitize_model_request(&target, "/api/v1/messages", body.to_string().as_bytes())
            .expect("admitted endpoint");
    assert_eq!(
        sanitized.stripped,
        ["models", "plugins", "provider", "route"]
    );
    let forwarded: serde_json::Value = serde_json::from_slice(&sanitized.body).expect("JSON");
    assert_eq!(forwarded["model"], "anthropic/claude-sonnet-4.6");
    assert!(
        sanitize_model_request(&target, "/api/v1/chat/completions", b"{}").is_err(),
        "only the Messages endpoint is admitted"
    );
}
