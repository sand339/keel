#![doc = "Phase 0 local transparent-egress compatibility server."]

use keel_conn::{Destination, ReplayStream, accept_stream};
use keel_secrets::{TestMitmCa, forward_http_once, terminate_http_once, terminate_stream_once};
use std::{
    env,
    error::Error,
    fs, io,
    net::{Ipv4Addr, TcpListener, TcpStream},
    path::PathBuf,
    thread,
    time::Duration,
};

fn main() -> Result<(), Box<dyn Error>> {
    let mut arguments = env::args_os().skip(1);
    let ready_file = PathBuf::from(
        arguments
            .next()
            .ok_or("usage: keel-egress-spike READY_FILE CA_FILE STOP_FILE")?,
    );
    let ca_file = PathBuf::from(
        arguments
            .next()
            .ok_or("usage: keel-egress-spike READY_FILE CA_FILE STOP_FILE")?,
    );
    let stop_file = PathBuf::from(
        arguments
            .next()
            .ok_or("usage: keel-egress-spike READY_FILE CA_FILE STOP_FILE")?,
    );
    if arguments.next().is_some() {
        return Err("usage: keel-egress-spike READY_FILE CA_FILE STOP_FILE".into());
    }

    let ca = TestMitmCa::generate()?;
    let front_config = ca.server_config("localhost")?;
    let upstream_config = ca.server_config("upstream.keel.test")?;
    let upstream_root = ca.certificate_der();
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    listener.set_nonblocking(true)?;
    let port = listener.local_addr()?.port();
    let upstream_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    upstream_listener.set_nonblocking(true)?;
    let upstream_address = upstream_listener.local_addr()?;
    fs::write(&ca_file, ca.certificate_pem())?;
    fs::write(&ready_file, format!("{port}\n"))?;
    eprintln!("keel egress compatibility server listening on https://localhost:{port}");

    let upstream_stop = stop_file.clone();
    let upstream = thread::spawn(move || -> Result<(), String> {
        while !upstream_stop.exists() {
            match upstream_listener.accept() {
                Ok((stream, _)) => {
                    stream
                        .set_nonblocking(false)
                        .map_err(|error| error.to_string())?;
                    terminate_http_once(stream, upstream_config.clone(), |request| {
                        response(request, port)
                    })
                    .map_err(|error| error.to_string())?;
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(20));
                }
                Err(error) => return Err(error.to_string()),
            }
        }
        Ok(())
    });

    while !stop_file.exists() {
        match listener.accept() {
            Ok((stream, _)) => {
                stream.set_nonblocking(false)?;
                let stream = accept_tls_stream(stream)?;
                terminate_stream_once(stream, front_config.clone(), |request| {
                    match TcpStream::connect(upstream_address)
                        .map_err(|error| error.to_string())
                        .and_then(|upstream_stream| {
                            forward_http_once(
                                request,
                                upstream_stream,
                                "upstream.keel.test",
                                upstream_root.clone(),
                            )
                            .map_err(|error| error.to_string())
                        }) {
                        Ok(response) => response,
                        Err(error) => {
                            eprintln!("upstream relay failed: {error}");
                            http_response("text/plain", b"Keel Phase 0 upstream relay failed")
                        }
                    }
                })?;
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(20));
            }
            Err(error) => return Err(error.into()),
        }
    }
    upstream
        .join()
        .map_err(|_| "upstream compatibility server panicked")?
        .map_err(|error| format!("upstream compatibility server: {error}"))?;
    Ok(())
}

fn accept_tls_stream(stream: TcpStream) -> Result<ReplayStream<TcpStream>, Box<dyn Error>> {
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    let accepted = accept_stream(stream, 64 * 1024)?;
    let expected = Destination::Tls {
        host: "localhost".to_owned(),
        port: 443,
    };
    if accepted.destination() != &expected {
        return Err(format!(
            "unexpected intercepted destination: {:?}",
            accepted.destination()
        )
        .into());
    }
    Ok(accepted.into_parts().1)
}

fn response(request: &[u8], port: u16) -> Vec<u8> {
    let request_line = request
        .split(|byte| *byte == b'\n')
        .next()
        .map(|line| String::from_utf8_lossy(line).trim().to_owned())
        .unwrap_or_default();
    eprintln!("{request_line}");

    if request_line.starts_with("GET /info/refs?service=git-upload-pack ") {
        let mut body = pkt_line(b"# service=git-upload-pack\n");
        body.extend_from_slice(b"00000000");
        return http_response("application/x-git-upload-pack-advertisement", &body);
    }
    if request_line.starts_with("GET /config.json ") {
        return http_response(
            "application/json",
            format!(
                r#"{{"dl":"https://localhost:{port}/api/v1/crates","api":"https://localhost:{port}"}}"#
            )
            .as_bytes(),
        );
    }
    if request_line.starts_with("GET /api/v1/crates?") {
        return http_response("application/json", br#"{"crates":[],"meta":{"total":0}}"#);
    }
    if request_line.starts_with("POST /v1/messages") {
        return http_response(
            "text/event-stream",
            concat!(
                "event: message_start\n",
                "data: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_keel_phase0\",\"type\":\"message\",\"role\":\"assistant\",\"content\":[],\"model\":\"sonnet\",\"stop_reason\":null,\"stop_sequence\":null,\"usage\":{\"input_tokens\":1,\"output_tokens\":0}}}\n\n",
                "event: content_block_start\n",
                "data: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n",
                "event: content_block_delta\n",
                "data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"keel-pass\"}}\n\n",
                "event: content_block_stop\n",
                "data: {\"type\":\"content_block_stop\",\"index\":0}\n\n",
                "event: message_delta\n",
                "data: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\",\"stop_sequence\":null},\"usage\":{\"output_tokens\":1}}\n\n",
                "event: message_stop\n",
                "data: {\"type\":\"message_stop\"}\n\n",
            )
            .as_bytes(),
        );
    }
    http_response("application/json", br#"{"keel":"pass"}"#)
}

fn pkt_line(payload: &[u8]) -> Vec<u8> {
    let length = payload.len() + 4;
    let mut packet = format!("{length:04x}").into_bytes();
    packet.extend_from_slice(payload);
    packet
}

fn http_response(content_type: &str, body: &[u8]) -> Vec<u8> {
    let mut response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    response.extend_from_slice(body);
    response
}
