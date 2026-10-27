mod support;

use quayside::{
    config::{Config, RegistryConfig},
    error::Code,
    registry::Registry,
};
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use support::{Response, Server};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn client(server: &Server, token_host: &str, retries: usize) -> Registry {
    let mut config = Config::default();
    config.transfer.max_retries = retries;
    config.transfer.connect_timeout = "2s".into();
    config.transfer.metadata_timeout = "5s".into();
    for host in [&server.host, token_host] {
        config.registries.insert(
            host.to_owned(),
            RegistryConfig {
                plain_http: true,
                auth_hosts: vec![token_host.to_owned()],
                ..Default::default()
            },
        );
    }
    Registry::new(
        &server.host,
        Arc::new(config),
        None,
        Arc::new(AtomicBool::new(false)),
    )
    .unwrap()
}

#[tokio::test]
async fn token_requests_retry_timeouts_and_closed_connections_within_the_retry_budget() {
    for (status, retries, succeeds) in [(Some(408), 1, true), (None, 1, true), (None, 0, false)] {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let host = listener.local_addr().unwrap().to_string();
        let attempts = Arc::new(AtomicUsize::new(0));
        let count = attempts.clone();
        let token_server = tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut headers = Vec::new();
                while !headers.ends_with(b"\r\n\r\n") {
                    headers.push(stream.read_u8().await.unwrap());
                    assert!(headers.len() <= 8192);
                }
                let first = count.fetch_add(1, Ordering::SeqCst) == 0;
                if first && status.is_none() {
                    // A token service can close a pooled connection before returning headers.
                    continue;
                }
                let status = if first { status.unwrap() } else { 200 };
                let body = if status == 200 {
                    r#"{"token":"verified","expires_in":60}"#
                } else {
                    ""
                };
                stream
                    .write_all(
                        format!(
                            "HTTP/1.1 {status} Test\r\nConnection: close\r\nRetry-After: 0\r\nContent-Length: {}\r\n\r\n{body}",
                            body.len()
                        )
                        .as_bytes(),
                    )
                    .await
                    .unwrap();
            }
        });
        let realm = format!("http://{host}/token");
        let server = Server::new(move |request| {
            assert_eq!(request.path, "/v2/");
            if request.headers.get("authorization").map(String::as_str) == Some("Bearer verified") {
                Response::new(200, vec![])
            } else {
                Response::new(401, vec![])
                    .header("WWW-Authenticate", &format!("Bearer realm=\"{realm}\""))
            }
        });
        let result = client(&server, &host, retries).ping().await;
        token_server.abort();
        if succeeds {
            assert!(result.unwrap());
            assert_eq!(attempts.load(Ordering::SeqCst), 2);
        } else {
            assert_eq!(result.unwrap_err().code, Code::Network);
            assert_eq!(attempts.load(Ordering::SeqCst), 1);
        }
    }
}

#[tokio::test]
async fn rejected_token_credentials_are_not_retried() {
    for status in [401, 403] {
        let token_server = Server::new(move |_| Response::new(status, vec![]));
        let realm = format!("http://{}/token", token_server.host);
        let server = Server::new(move |_| {
            Response::new(401, vec![])
                .header("WWW-Authenticate", &format!("Bearer realm=\"{realm}\""))
        });
        let error = client(&server, &token_server.host, 2)
            .ping()
            .await
            .unwrap_err();
        assert_eq!(
            error.code,
            if status == 401 {
                Code::Unauthorized
            } else {
                Code::Forbidden
            }
        );
        assert_eq!(token_server.connections.load(Ordering::SeqCst), 1);
    }
}
