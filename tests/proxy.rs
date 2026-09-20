mod support;
use serde_json::json;
use std::{
    fs,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};
use support::{Harness, Response, Server};

#[test]
fn docker_proxy_is_used_env_overrides_and_no_proxy_bypasses() {
    let seen = Arc::new(AtomicUsize::new(0));
    let count = seen.clone();
    let proxy = Server::new(move |request| {
        assert!(request.path.starts_with("http://registry.invalid/"));
        count.fetch_add(1, Ordering::SeqCst);
        Response::new(200, b"{}".to_vec())
    });
    let override_count = Arc::new(AtomicUsize::new(0));
    let count = override_count.clone();
    let other = Server::new(move |_| {
        count.fetch_add(1, Ordering::SeqCst);
        Response::new(200, b"{}".to_vec())
    });
    let local = Server::new(|_| Response::new(200, b"{}".to_vec()));
    let harness = Harness::new(&[("registry.invalid", true), (&local.host, true)]);
    let daemon = harness.daemon_config();
    fs::write(
        &daemon,
        serde_json::to_vec(&json!({"proxies":{
        "http-proxy":format!("http://{}",proxy.host),"no-proxy":"127.0.0.1,localhost"
    },"insecure-registries":["registry.invalid"],"registry-mirrors":["https://ignored.invalid"]}))
        .unwrap(),
    )
    .unwrap();
    harness.json(&["registry", "ping", "registry.invalid"], 0);
    assert_eq!(seen.load(Ordering::SeqCst), 1);
    let output = harness
        .command(&["registry", "ping", "registry.invalid"])
        .env("HTTP_PROXY", format!("http://{}", other.host))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(override_count.load(Ordering::SeqCst), 1);
    harness.json(&["registry", "ping", &local.host], 0);
    assert_eq!(seen.load(Ordering::SeqCst), 1);
    // Empty explicit proxy disables daemon fallback; local access must be direct even without no_proxy.
    fs::write(
        &daemon,
        serde_json::to_vec(&json!({"proxies":{"http-proxy":format!("http://{}",proxy.host)}}))
            .unwrap(),
    )
    .unwrap();
    let output = harness
        .command(&["registry", "ping", &local.host])
        .env("http_proxy", "")
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_eq!(seen.load(Ordering::SeqCst), 1);
}

#[test]
fn unrelated_docker_fields_are_ignored_and_proxy_secrets_are_not_logged() {
    let server = Server::new(|_| Response::new(200, b"{}".to_vec()));
    let mut harness = Harness::new(&[(&server.host, false)]);
    let daemon = harness.daemon_config();
    fs::write(
        &daemon,
        serde_json::to_vec(&json!({
            "insecure-registries":[server.host],"registry-mirrors":["http://ignored.invalid"],
            "proxies":{"http-proxy":"invalid proxy secret-password"}
        }))
        .unwrap(),
    )
    .unwrap();
    // Docker insecure-registries must not enable HTTP: a TLS request to this HTTP server fails.
    harness.json(&["registry", "ping", &server.host], 6);
    harness
        .config
        .registries
        .get_mut(&server.host)
        .unwrap()
        .plain_http = true;
    let output = harness.output(
        &[
            "--json",
            "--log-level",
            "debug",
            "registry",
            "ping",
            &server.host,
        ],
        2,
    );
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!text.contains("secret-password"));
    assert!(text.contains("invalid proxy URL"));
    assert!(text.contains("daemon.json"));
}

#[test]
fn docker_https_proxy_is_used_for_connect_tunnel() {
    let connections = Arc::new(AtomicUsize::new(0));
    let seen = connections.clone();
    let proxy = Server::new(move |request| {
        assert_eq!(request.method, "CONNECT");
        assert_eq!(request.path, "registry.invalid:443");
        seen.fetch_add(1, Ordering::SeqCst);
        // No external network: prove the selected HTTPS proxy receives the tunnel request.
        Response::new(502, vec![])
    });
    let harness = Harness::new(&[("registry.invalid", false)]);
    fs::write(
        harness.daemon_config(),
        serde_json::to_vec(&json!({
            "proxies":{"https-proxy":format!("http://{}",proxy.host)}
        }))
        .unwrap(),
    )
    .unwrap();
    harness.json(&["registry", "ping", "registry.invalid"], 6);
    assert_eq!(connections.load(Ordering::SeqCst), 1);
}

#[test]
fn connection_errors_show_safe_destination_proxy_source_and_typed_reason() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap().to_string();
    drop(listener);
    let harness = Harness::new(&[(&address, true)]);
    let daemon = harness.daemon_config();
    fs::write(
        &daemon,
        serde_json::to_vec(&json!({"proxies": {
            "https-proxy": format!("http://{address}"),
            "http-proxy": format!("http://{address}")
        }}))
        .unwrap(),
    )
    .unwrap();
    let output = harness.output(&["registry", "ping", "docker.io"], 6);
    let text = String::from_utf8(output.stderr).unwrap();
    assert!(
        text.contains("Unable to connect to Docker Hub (registry-1.docker.io:443)"),
        "{text}"
    );
    assert!(
        text.contains(&format!("Proxy: {address} (from {})", daemon.display())),
        "{text}"
    );
    assert!(text.contains("Reason: Connection refused"), "{text}");
    assert!(!text.contains("private-user"));
    assert!(!text.contains("secret-password"));
    let output = harness
        .command(&["registry", "ping", "docker.io"])
        .env("HTTPS_PROXY", format!("http://{address}"))
        .output()
        .unwrap();
    let text = String::from_utf8(output.stderr).unwrap();
    assert!(
        text.contains(&format!("Proxy: {address} (from HTTPS_PROXY)")),
        "{text}"
    );
    for rule in ["*", "127.0.0.1", "127.0.0.0/8", &address] {
        let output = harness
            .command(&["--json", "registry", "ping", &address])
            .env("NO_PROXY", rule)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(6));
        let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        let message = value["error"]["message"].as_str().unwrap();
        assert!(message.contains("Reason: Connection refused"), "{message}");
        assert!(!message.contains("Proxy:"), "{message}");
        assert_eq!(value["error"]["code"], "NETWORK");
    }
}

#[test]
fn docker_cidr_rules_bypass_local_ips_and_preserve_proxy_for_other_hosts() {
    let seen = Arc::new(AtomicUsize::new(0));
    let count = seen.clone();
    let proxy = Server::new(move |request| {
        assert!(request.path.starts_with("http://registry.invalid/"));
        count.fetch_add(1, Ordering::SeqCst);
        Response::new(200, b"{}".to_vec())
    });
    let local = Server::new(|_| Response::new(200, b"{}".to_vec()));
    let harness = Harness::new(&[("registry.invalid", true), (&local.host, true)]);
    let daemon = harness.daemon_config();
    fs::write(&daemon, serde_json::to_vec(&json!({"proxies":{
        "http-proxy":format!("http://{}",proxy.host),
        "no-proxy":"*.example.com,*.example.org,*.region.example.org,*.example.net,192.0.2.0/24,198.51.100.0/24,127.0.0.0/8,::1/128"
    }})).unwrap()).unwrap();
    harness.json(&["registry", "ping", "registry.invalid"], 0);
    harness.json(&["registry", "ping", &local.host], 0);
    assert_eq!(seen.load(Ordering::SeqCst), 1);
    let output = harness
        .command(&["registry", "ping", &local.host])
        .env("NO_PROXY", "127.0.0.1/99")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    let text = String::from_utf8(output.stderr).unwrap();
    assert!(text.contains("Invalid no_proxy rule:"), "{text}");
}

#[test]
fn native_cidr_routing_does_not_resolve_hostnames_and_reports_invalid_rules() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let literal = address.to_string();
    let hostname = format!("localhost:{}", address.port());
    drop(listener);
    let ipv6 = std::net::TcpListener::bind("[::1]:0")
        .ok()
        .map(|listener| listener.local_addr().unwrap().to_string());
    let seen = Arc::new(AtomicUsize::new(0));
    let count = seen.clone();
    let proxy = Server::new(move |_| {
        count.fetch_add(1, Ordering::SeqCst);
        Response::new(200, b"{}".to_vec())
    });
    let mut hosts = vec![(literal.as_str(), true), (hostname.as_str(), true)];
    if let Some(host) = &ipv6 {
        hosts.push((host.as_str(), true));
    }
    let harness = Harness::new(&hosts);
    fs::write(
        harness.daemon_config(),
        serde_json::to_vec(&json!({"proxies":{
            "http-proxy":format!("http://{}",proxy.host),
            "no-proxy":"127.0.0.42/8,::1/128"
        }}))
        .unwrap(),
    )
    .unwrap();
    // A matching literal bypasses the healthy proxy and reaches a refused direct connection.
    for host in std::iter::once(&literal).chain(ipv6.iter()) {
        let value = harness.json(&["registry", "ping", host], 6);
        let message = value["error"]["message"].as_str().unwrap();
        assert!(message.contains("Connection refused"), "{message}");
        assert!(!message.contains("Proxy:"), "{message}");
    }
    assert_eq!(seen.load(Ordering::SeqCst), 0);
    // CIDR matching must not resolve localhost into a loopback address and bypass the proxy.
    harness.json(&["registry", "ping", &hostname], 0);
    let output = harness
        .command(&["registry", "ping", &literal])
        .env("NO_PROXY", "192.0.2.0/24")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(seen.load(Ordering::SeqCst), 2);
    for rule in [
        "127.0.0.1/33",
        "::1/129",
        "127.0.0.1/8:80",
        "[::1]/128",
        "secret.invalid/24",
    ] {
        let output = harness
            .command(&["registry", "ping", &literal])
            .env("NO_PROXY", rule)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2));
        let text = String::from_utf8(output.stderr).unwrap();
        assert!(text.contains("Invalid no_proxy rule:"), "{text}");
        assert!(!text.contains(rule), "{text}");
    }
    assert_eq!(seen.load(Ordering::SeqCst), 2);
}
