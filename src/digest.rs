use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256, Sha512};
use std::{fmt, io::Read, path::Path, str::FromStr};

/// A validated SHA-256 or SHA-512 digest in algorithm:hex form.
///
/// ```
/// use quayside::digest::Digest;
///
/// let digest = Digest::sha256(b"payload");
/// assert!(digest.verify(b"payload").is_ok());
/// assert!(digest.verify(b"different payload").is_err());
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Digest(String);

impl Digest {
    /// Compute the SHA-256 digest of a complete byte slice.
    pub fn sha256(bytes: &[u8]) -> Self {
        Self(format!("sha256:{}", hex::encode(Sha256::digest(bytes))))
    }
    /// Borrow the complete algorithm-prefixed digest string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
    /// Return the digest algorithm name.
    pub fn algorithm(&self) -> &str {
        self.0.split_once(':').expect("validated digest").0
    }
    /// Return the hexadecimal digest value without its algorithm prefix.
    pub fn encoded(&self) -> &str {
        self.0.split_once(':').expect("validated digest").1
    }
    /// Create an incremental hasher using this digest's algorithm.
    pub fn hasher(&self) -> Hasher {
        Hasher::new(self.algorithm())
    }
    /// Verify that a byte slice matches this digest, returning an integrity error on mismatch.
    pub fn verify(&self, bytes: &[u8]) -> Result<()> {
        let mut h = self.hasher();
        h.update(bytes);
        h.verify(self)
    }
    /// Stream a file through verification and enforce its expected size and digest.
    pub fn verify_file(&self, path: &Path, expected_size: u64) -> Result<()> {
        let mut f = std::fs::File::open(path)?;
        if f.metadata()?.len() != expected_size {
            return Err(Error::integrity(format!("size mismatch for {self}")));
        }
        let mut h = self.hasher();
        let mut buf = [0u8; 64 * 1024];
        let mut size = 0u64;
        loop {
            let n = f.read(&mut buf)?;
            if n == 0 {
                break;
            }
            size += n as u64;
            if size > expected_size {
                return Err(Error::integrity("blob grew during verification"));
            }
            h.update(&buf[..n]);
        }
        if size != expected_size {
            return Err(Error::integrity("blob changed during verification"));
        }
        h.verify(self)
    }
}
impl FromStr for Digest {
    type Err = Error;
    fn from_str(value: &str) -> Result<Self> {
        let (alg, value_hex) = value
            .split_once(':')
            .ok_or_else(|| Error::input("digest requires algorithm:hex"))?;
        let len = match alg {
            "sha256" => 64,
            "sha512" => 128,
            _ => {
                return Err(Error::unsupported(format!(
                    "unsupported digest algorithm: {alg}"
                )));
            }
        };
        if value_hex.len() != len
            || !value_hex
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        {
            return Err(Error::input(format!("invalid {alg} digest")));
        }
        Ok(Self(value.to_owned()))
    }
}
impl TryFrom<String> for Digest {
    type Error = Error;
    fn try_from(s: String) -> Result<Self> {
        s.parse()
    }
}
impl From<Digest> for String {
    fn from(d: Digest) -> String {
        d.0
    }
}
impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Incremental SHA-256 or SHA-512 computation without buffering the complete payload.
pub enum Hasher {
    /// Incremental SHA-256 state.
    Sha256(Sha256),
    /// Incremental SHA-512 state.
    Sha512(Sha512),
}
impl Hasher {
    fn new(alg: &str) -> Self {
        match alg {
            "sha512" => Self::Sha512(Sha512::new()),
            _ => Self::Sha256(Sha256::new()),
        }
    }
    /// Feed another payload chunk into the running hash.
    pub fn update(&mut self, bytes: &[u8]) {
        match self {
            Self::Sha256(h) => h.update(bytes),
            Self::Sha512(h) => h.update(bytes),
        }
    }
    /// Finalize the running hash and return its algorithm-prefixed digest.
    pub fn finish(self) -> Digest {
        match self {
            Self::Sha256(h) => Digest(format!("sha256:{}", hex::encode(h.finalize()))),
            Self::Sha512(h) => Digest(format!("sha512:{}", hex::encode(h.finalize()))),
        }
    }
    /// Finalize the incremental hash and compare it with an expected digest.
    pub fn verify(self, expected: &Digest) -> Result<()> {
        if self.finish() != *expected {
            Err(Error::integrity(format!("digest mismatch for {expected}")))
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sha256_vector() {
        assert_eq!(
            Digest::sha256(b"abc").as_str(),
            "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
    #[test]
    fn corruption_fails() {
        assert!(Digest::sha256(b"abc").verify(b"abd").is_err());
    }
    #[test]
    fn rejects_paths() {
        assert!("sha256:../../etc/passwd".parse::<Digest>().is_err());
    }
    #[test]
    fn rejects_uppercase() {
        assert!(
            format!("sha256:{}", "A".repeat(64))
                .parse::<Digest>()
                .is_err()
        );
    }
    #[test]
    fn sha512_works() {
        let d: Digest = format!("sha512:{}", hex::encode(Sha512::digest(b"abc")))
            .parse()
            .unwrap();
        d.verify(b"abc").unwrap();
    }
}
