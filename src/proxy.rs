//! Resolve proxy settings and describe routing without exposing proxy credentials.
use crate::docker_config::DaemonConfig;

pub(crate) struct Proxy {
    pub url: Option<String>,
    pub no_proxy: Option<String>,
    pub source: Option<String>,
}

fn choose(scheme: &str, docker: &DaemonConfig, get: impl Fn(&str) -> Option<String>) -> Proxy {
    let names = if scheme == "https" {
        ["https_proxy", "HTTPS_PROXY", "all_proxy", "ALL_PROXY"]
    } else {
        ["http_proxy", "HTTP_PROXY", "all_proxy", "ALL_PROXY"]
    };
    let env = names
        .iter()
        .find_map(|key| get(key).map(|value| (value, (*key).to_owned())));
    let source = env
        .as_ref()
        .map(|(_, key)| key.clone())
        .or_else(|| docker.source.clone());
    let url = env.map(|(value, _)| value).or_else(|| {
        if scheme == "https" {
            docker.proxies.https_proxy.clone()
        } else {
            docker.proxies.http_proxy.clone()
        }
    });
    // An explicitly empty environment variable overrides the daemon default too.
    Proxy {
        source,
        url: url.filter(|s| !s.is_empty()),
        no_proxy: ["no_proxy", "NO_PROXY"]
            .iter()
            .find_map(|key| get(key))
            .or_else(|| docker.proxies.no_proxy.clone()),
    }
}
pub(crate) fn for_scheme(scheme: &str) -> Proxy {
    choose(scheme, crate::docker_config::defaults(), |key| {
        std::env::var(key).ok()
    })
}

// Diagnostic matching only: reqx owns routing but does not expose its bypass matcher.
// Match literal destination IPs, without resolving hostnames locally.
fn cidr(rule: &str) -> Option<(std::net::IpAddr, u32)> {
    let (ip, prefix) = rule.split_once('/')?;
    let ip: std::net::IpAddr = ip.parse().ok()?;
    let prefix: u32 = prefix.parse().ok()?;
    (prefix <= if ip.is_ipv4() { 32 } else { 128 }).then_some((ip, prefix))
}
fn cidr_matches(network: std::net::IpAddr, prefix: u32, target: &url::Url) -> bool {
    let Some(host) = target.host_str() else {
        return false;
    };
    let Ok(ip) = host.trim_matches(['[', ']']).parse::<std::net::IpAddr>() else {
        return false;
    };
    match (network, ip) {
        (std::net::IpAddr::V4(a), std::net::IpAddr::V4(b)) => {
            prefix == 0 || (u32::from(a) >> (32 - prefix)) == (u32::from(b) >> (32 - prefix))
        }
        (std::net::IpAddr::V6(a), std::net::IpAddr::V6(b)) => {
            prefix == 0 || (u128::from(a) >> (128 - prefix)) == (u128::from(b) >> (128 - prefix))
        }
        _ => false,
    }
}

impl Proxy {
    /// Pass every supported rule, including CIDRs, through to reqx for validation and routing.
    pub(crate) fn transport_rules(&self) -> impl Iterator<Item = &str> {
        self.no_proxy
            .as_deref()
            .unwrap_or_default()
            .split(',')
            .map(str::trim)
            .filter(|rule| !rule.is_empty())
    }

    pub(crate) fn description(&self, target: &url::Url) -> Option<String> {
        if self
            .no_proxy
            .as_deref()
            .is_some_and(|rules| rules.split(',').any(|rule| bypasses(rule, target)))
        {
            return None;
        }
        let proxy = url::Url::parse(self.url.as_deref()?).ok()?;
        let endpoint = crate::error::endpoint(&proxy);
        Some(match &self.source {
            Some(source) => format!("{endpoint} (from {source})"),
            None => endpoint,
        })
    }
}

// Match CIDRs plus reqx's wildcard, domain suffix, IP and optional port rules.
// Configuration validity is checked by reqx when the client is built.
fn bypasses(rule: &str, target: &url::Url) -> bool {
    let rule = rule.trim();
    if let Some((network, prefix)) = cidr(rule) {
        return cidr_matches(network, prefix, target);
    }
    if rule == "*" {
        return true;
    }
    let (host, port) = if rule.contains("://") {
        let Ok(url) = url::Url::parse(rule) else {
            return false;
        };
        (
            url.host_str().unwrap_or_default().to_owned(),
            url.port_or_known_default(),
        )
    } else {
        let rule = rule
            .strip_prefix("*.")
            .unwrap_or_else(|| rule.trim_start_matches('.'));
        if let Some(bracketed) = rule.strip_prefix('[') {
            let Some((host, suffix)) = bracketed.split_once(']') else {
                return false;
            };
            (
                host.to_owned(),
                suffix.strip_prefix(':').and_then(|p| p.parse().ok()),
            )
        } else if rule.matches(':').count() == 1 {
            let (host, port) = rule.rsplit_once(':').unwrap();
            (host.to_owned(), port.parse().ok())
        } else {
            (rule.to_owned(), None)
        }
    };
    let normalize = |s: &str| {
        s.trim_matches(['[', ']'])
            .trim_start_matches("*.")
            .trim_start_matches('.')
            .trim_end_matches('.')
            .to_ascii_lowercase()
    };
    let host = normalize(&host);
    let target_host = normalize(target.host_str().unwrap_or_default());
    let matches = match (
        host.parse::<std::net::IpAddr>(),
        target_host.parse::<std::net::IpAddr>(),
    ) {
        (Ok(a), Ok(b)) => a == b,
        (Ok(_), _) | (_, Ok(_)) => false,
        _ => {
            !host.is_empty()
                && (target_host == host
                    || target_host
                        .strip_suffix(&host)
                        .is_some_and(|p| p.ends_with('.')))
        }
    };
    matches && port.is_none_or(|p| Some(p) == target.port_or_known_default())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cidr_boundaries_and_address_families() {
        for (rule, target, expected) in [
            ("192.0.2.0/24", "http://192.0.2.255", true),
            ("192.0.2.0/24", "http://198.51.100.0", false),
            ("192.0.2.90/24", "http://192.0.2.1", true),
            ("127.0.0.1/32", "http://127.0.0.2", false),
            ("0.0.0.0/0", "http://1.2.3.4", true),
            ("0.0.0.0/0", "http://example.com", false),
            ("::/0", "http://[::1]", true),
            ("::/0", "http://127.0.0.1", false),
            ("::1/128", "http://[::1]", true),
            ("::1/128", "http://[::2]", false),
            ("2001:db8::/32", "http://[2001:db8::ffff]", true),
            ("2001:db8::/32", "http://[2001:db9::1]", false),
        ] {
            assert_eq!(
                bypasses(rule, &url::Url::parse(target).unwrap()),
                expected,
                "{rule}: {target}"
            );
        }
        for rule in [
            "127.0.0.1/33",
            "::1/129",
            "localhost/24",
            "1.2.3.4/-1",
            "1.2.3.4/",
        ] {
            assert!(cidr(rule).is_none(), "{rule}");
        }
    }
    #[test]
    fn proxy_description_excludes_credentials_and_url_details() {
        let proxy = Proxy {
            url: Some("http://private-user:secret-password@localhost:7890/private?secret".into()),
            no_proxy: None,
            source: Some("HTTPS_PROXY".into()),
        };
        assert_eq!(
            proxy
                .description(&url::Url::parse("https://example.com").unwrap())
                .as_deref(),
            Some("localhost:7890 (from HTTPS_PROXY)")
        );
    }
    #[test]
    fn diagnostic_bypass_matches_supported_reqx_rules() {
        for (rule, target, expected) in [
            (".example.com", "https://sub.example.com", true),
            ("example.com", "https://notexample.com", false),
            ("*.EXAMPLE.com.", "https://example.com", true),
            ("example.com:80", "https://example.com", false),
            ("https://example.com", "https://sub.example.com", true),
            ("http://example.com", "https://example.com", false),
            ("[::1]:443", "https://[::1]", true),
            ("::1", "https://[::1]:444", true),
            ("127.0.0.1", "http://other.127.0.0.1.example.com", false),
        ] {
            assert_eq!(
                bypasses(rule, &url::Url::parse(target).unwrap()),
                expected,
                "{rule}: {target}"
            );
        }
    }
    #[test]
    fn environment_precedence_and_empty_overrides() {
        let docker = DaemonConfig {
            proxies: crate::docker_config::Proxies {
                http_proxy: Some("http://docker:1".into()),
                https_proxy: Some("http://docker:2".into()),
                no_proxy: Some("docker.local".into()),
            },
            ..Default::default()
        };
        let p = choose("https", &docker, |_| None);
        assert_eq!(p.url.as_deref(), Some("http://docker:2"));
        let p = choose("http", &docker, |key| match key {
            "HTTP_PROXY" => Some("http://env:1".into()),
            _ => None,
        });
        assert_eq!(p.url.as_deref(), Some("http://env:1"));
        assert_eq!(p.no_proxy.as_deref(), Some("docker.local"));
        let p = choose("https", &docker, |key| match key {
            "https_proxy" | "no_proxy" => Some(String::new()),
            "HTTPS_PROXY" => Some("http://upper:1".into()),
            _ => None,
        });
        assert!(p.url.is_none());
        assert_eq!(p.no_proxy.as_deref(), Some(""));
        let p = choose("https", &docker, |key| {
            (key == "ALL_PROXY").then(|| "http://all:1".into())
        });
        assert_eq!(p.url.as_deref(), Some("http://all:1"));
    }
}
