use crate::{Error, Result, digest::Digest};
use regex::Regex;
use serde::Serialize;
use std::{fmt, str::FromStr, sync::OnceLock};
use url::Url;

/// A normalized registry reference with a repository and tag or digest selector.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Reference {
    /// Registry hostname and optional port, without a scheme or repository.
    pub registry: String,
    /// Repository path within the registry, without a tag or digest.
    pub repository: String,
    /// Tag name or algorithm-prefixed digest; defaults to latest when omitted in the input.
    pub selector: String,
    /// Whether the input explicitly supplied its tag or digest selector.
    pub explicit: bool,
}

/// Validate and normalize a registry authority, including supported Docker Hub aliases.
pub fn registry_name(input: &str) -> Result<String> {
    if input.is_empty()
        || input.chars().any(char::is_whitespace)
        || input.contains(['/', '@', '?', '#', '%', '\\'])
    {
        return Err(Error::input(
            "registry must be a hostname and optional port; do not include a URL scheme",
        ));
    }
    let url = Url::parse(&format!("https://{input}/"))?;
    if url.host_str().is_none() || !url.username().is_empty() || url.password().is_some() {
        return Err(Error::input("invalid registry hostname"));
    }
    // URL parsing removes scheme-default ports. A registry authority must retain an explicit
    // port because its configured transport can be plain HTTP, including on port 443.
    let explicit_port = if input.starts_with('[') {
        input
            .split_once(']')
            .and_then(|(_, suffix)| suffix.strip_prefix(':'))
    } else {
        input.rsplit_once(':').map(|(_, port)| port)
    };
    let port = explicit_port
        .map(|port| {
            port.parse::<u16>()
                .map_err(|_| Error::input("invalid registry port"))
        })
        .transpose()?;
    let mut name = url[url::Position::BeforeHost..url::Position::AfterHost].to_ascii_lowercase();
    if name == "index.docker.io" || name == "registry-1.docker.io" {
        name = "docker.io".into();
    }
    if let Some(port) = port {
        name.push_str(&format!(":{port}"));
    }
    Ok(name)
}

/// Reject repository paths outside the supported Distribution reference syntax.
pub fn validate_repository(repo: &str) -> Result<()> {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| {
        Regex::new(r"^[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*$").expect("constant regex")
    });
    if repo.is_empty() || repo.len() > 255 || !repo.split('/').all(|s| re.is_match(s)) {
        return Err(Error::input(
            "invalid repository path (lowercase OCI repository name required)",
        ));
    }
    Ok(())
}

/// Validate a registry tag's syntax and length.
pub fn validate_tag(tag: &str) -> Result<()> {
    static RE: OnceLock<Regex> = OnceLock::new();
    if !RE
        .get_or_init(|| Regex::new(r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$").expect("constant regex"))
        .is_match(tag)
    {
        return Err(Error::input("invalid image tag"));
    }
    Ok(())
}

impl FromStr for Reference {
    type Err = Error;
    fn from_str(input: &str) -> Result<Self> {
        if input.contains("://") || input.chars().any(char::is_whitespace) {
            return Err(Error::input(
                "use registry/repository:tag, without URL scheme",
            ));
        }
        let (registry, rest) = input.split_once('/').ok_or_else(|| {
            Error::input("a fully qualified registry/repository reference is required")
        })?;
        let registry = registry_name(registry)?;
        let (name_tag, digest) = match rest.split_once('@') {
            Some((n, d)) => {
                let _: Digest = d.parse()?;
                (n, Some(d))
            }
            None => (rest, None),
        };
        let (repository, tag) = match name_tag.rsplit_once(':') {
            Some((n, t)) => {
                validate_tag(t)?;
                (n, Some(t))
            }
            None => (name_tag, None),
        };
        validate_repository(repository)?;
        let repository = if (registry == "docker.io" || registry.starts_with("docker.io:"))
            && !repository.contains('/')
        {
            format!("library/{repository}")
        } else {
            repository.to_owned()
        };
        Ok(Self {
            registry,
            repository,
            selector: digest.or(tag).unwrap_or("latest").into(),
            explicit: digest.is_some() || tag.is_some(),
        })
    }
}
impl Reference {
    /// Return the selector as a digest when it is a supported digest rather than a tag.
    pub fn digest(&self) -> Option<Digest> {
        self.selector.parse().ok()
    }
    /// Clone this reference with an explicit content-digest selector.
    pub fn pinned(&self, digest: &Digest) -> Self {
        Self {
            selector: digest.to_string(),
            explicit: true,
            ..self.clone()
        }
    }
    /// Require an explicitly supplied tag or digest before a destination write.
    pub fn require_destination(&self) -> Result<()> {
        if !self.explicit {
            return Err(Error::input(
                "destination must explicitly specify a tag or digest",
            ));
        }
        Ok(())
    }
    /// Reject references with explicit tag or digest selectors for repository-only commands.
    pub fn require_repository(&self) -> Result<()> {
        if self.explicit {
            return Err(Error::input(
                "this command expects a repository, without tag or digest",
            ));
        }
        Ok(())
    }
    /// Return the registry/repository reference without any selector.
    pub fn repository_ref(&self) -> String {
        format!("{}/{}", self.registry, self.repository)
    }
}
impl fmt::Display for Reference {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let sep = if self.digest().is_some() { '@' } else { ':' };
        write!(
            f,
            "{}/{}{}{}",
            self.registry, self.repository, sep, self.selector
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn explicit_ports_survive_transport_selection_and_docker_aliases() {
        assert_eq!(registry_name("EXAMPLE.COM:443").unwrap(), "example.com:443");
        assert_eq!(registry_name("[::1]:443").unwrap(), "[::1]:443");
        assert_eq!(
            registry_name("example.com:0443").unwrap(),
            "example.com:443"
        );
        assert!(registry_name("example.com:").is_err());
        assert!(registry_name("[::1]:").is_err());
        let r: Reference = "registry-1.docker.io:443/node:v1".parse().unwrap();
        assert_eq!(r.registry, "docker.io:443");
        assert_eq!(r.repository, "library/node");
    }
    #[test]
    fn host_port_and_tag() {
        let r: Reference = "localhost:5000/team/app:v1".parse().unwrap();
        assert_eq!(r.registry, "localhost:5000");
        assert_eq!(r.repository, "team/app");
        assert_eq!(r.selector, "v1");
    }
    #[test]
    fn docker_default_namespace() {
        assert_eq!(
            "docker.io/alpine".parse::<Reference>().unwrap().repository,
            "library/alpine"
        );
    }
    #[test]
    fn ipv6_host() {
        assert_eq!(
            "[::1]:5000/app:v1".parse::<Reference>().unwrap().registry,
            "[::1]:5000"
        );
    }
    #[test]
    fn digest_wins_over_tag() {
        let d = Digest::sha256(b"x");
        let r: Reference = format!("example.com/a:v1@{d}").parse().unwrap();
        assert_eq!(r.digest(), Some(d));
    }
    #[test]
    fn destination_needs_tag() {
        assert!(
            "example.com/app"
                .parse::<Reference>()
                .unwrap()
                .require_destination()
                .is_err()
        );
    }
    #[test]
    fn rejects_invalid_inputs() {
        for v in [
            "alpine",
            "https://a.com/b:v1",
            "a.com/../b:v1",
            "a.com/App:v1",
            "a.com/a?x:v1",
            "user@a.com/a:v1",
            "a.com/a:",
        ] {
            assert!(v.parse::<Reference>().is_err(), "{v}");
        }
    }
}
