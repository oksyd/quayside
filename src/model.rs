use crate::{Error, Result, digest::Digest};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::{collections::BTreeMap, fmt, str::FromStr};

/// Media type for an OCI image manifest.
pub const OCI_MANIFEST: &str = "application/vnd.oci.image.manifest.v1+json";
/// Media type for an OCI image index.
pub const OCI_INDEX: &str = "application/vnd.oci.image.index.v1+json";
/// Media type for a Docker schema-2 image manifest.
pub const DOCKER_MANIFEST: &str = "application/vnd.docker.distribution.manifest.v2+json";
/// Media type for a Docker schema-2 manifest list.
pub const DOCKER_INDEX: &str = "application/vnd.docker.distribution.manifest.list.v2+json";
/// HTTP Accept value advertising the supported image and index manifest formats.
pub const ACCEPT_MANIFEST: &str = "application/vnd.oci.image.index.v1+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.docker.distribution.manifest.v2+json";

/// OCI platform metadata used for explicit image selection.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Platform {
    /// Target operating system name.
    pub os: String,
    /// Target CPU architecture name.
    pub architecture: String,
    /// Optional architecture variant, such as arm v7 or arm64 v8.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub variant: Option<String>,
    /// Optional operating-system version advertised by the image.
    #[serde(
        rename = "os.version",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub os_version: Option<String>,
    /// Optional operating-system features advertised by the image.
    #[serde(rename = "os.features", default, skip_serializing_if = "Vec::is_empty")]
    pub os_features: Vec<String>,
    /// Unknown JSON properties retained when reading and writing this object.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}
impl Platform {
    /// Compare operating system and architecture, also checking the requested variant when supplied.
    pub fn matches(&self, wanted: &Platform) -> bool {
        self.os == wanted.os
            && self.architecture == wanted.architecture
            && wanted
                .variant
                .as_ref()
                .is_none_or(|v| self.variant.as_ref() == Some(v))
    }
    /// Parse platform metadata from an image configuration, requiring OS and architecture.
    pub fn from_config(config: &Value) -> Result<Self> {
        let os = config
            .get("os")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| Error::input("image config has no operating system"))?;
        let arch = config
            .get("architecture")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| Error::input("image config has no architecture"))?;
        let mut p: Self = format!("{os}/{arch}").parse()?;
        p.variant = config
            .get("variant")
            .and_then(Value::as_str)
            .map(str::to_owned);
        p.os_version = config
            .get("os.version")
            .and_then(Value::as_str)
            .map(str::to_owned);
        p.os_features = config
            .get("os.features")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default();
        Ok(p)
    }
}
impl FromStr for Platform {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        let parts: Vec<_> = s.split('/').collect();
        if !(2..=3).contains(&parts.len())
            || parts.iter().any(|s| {
                s.is_empty()
                    || !s
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-' || b == b'.')
            })
        {
            return Err(Error::input("platform must be os/architecture[/variant]"));
        }
        Ok(Self {
            os: parts[0].into(),
            architecture: parts[1].into(),
            variant: parts.get(2).map(|s| (*s).to_string()),
            os_version: None,
            os_features: vec![],
            extra: Map::new(),
        })
    }
}
impl fmt::Display for Platform {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.os, self.architecture)?;
        if let Some(v) = &self.variant {
            write!(f, "/{v}")?;
        }
        Ok(())
    }
}

/// An OCI content descriptor with preserved extension fields.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Descriptor {
    /// Media type identifying the referenced content format.
    pub media_type: String,
    /// Expected algorithm-prefixed content digest.
    pub digest: Digest,
    /// Expected payload length in bytes.
    pub size: u64,
    /// Optional platform metadata for the referenced manifest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub platform: Option<Platform>,
    /// Descriptor annotations keyed by their original names.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub annotations: BTreeMap<String, String>,
    /// Alternative content URLs advertised by the descriptor; not automatically trusted or followed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub urls: Vec<String>,
    /// Optional base64-encoded inline payload as carried in the descriptor.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<String>,
    /// Unknown JSON properties retained when reading and writing this object.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}
impl Descriptor {
    /// Construct a descriptor with empty optional metadata and extension fields.
    pub fn new(media_type: impl Into<String>, digest: Digest, size: u64) -> Self {
        Self {
            media_type: media_type.into(),
            digest,
            size,
            platform: None,
            annotations: BTreeMap::new(),
            urls: vec![],
            data: None,
            extra: Map::new(),
        }
    }
    /// Decode and verify inline descriptor data, returning None when no inline data is present.
    pub fn embedded(&self) -> Result<Option<Bytes>> {
        self.data
            .as_ref()
            .map(|s| {
                let bytes = STANDARD
                    .decode(s)
                    .map_err(|_| Error::integrity("invalid descriptor embedded data"))?;
                self.verify(&bytes)?;
                Ok(Bytes::from(bytes))
            })
            .transpose()
    }
    /// Check a payload against the descriptor's declared size and digest.
    pub fn verify(&self, bytes: &[u8]) -> Result<()> {
        if bytes.len() as u64 != self.size {
            return Err(Error::integrity(format!(
                "descriptor size mismatch: {}",
                self.digest
            )));
        }
        self.digest.verify(bytes)
    }
}

/// The supported structural categories of OCI and Docker manifests.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ManifestKind {
    /// An image or artifact manifest containing payload descriptors.
    Image,
    /// An OCI image index or Docker manifest list referencing child manifests.
    Index,
}
/// A parsed manifest retaining original bytes for exact digest-preserving publication.
#[derive(Clone, Debug)]
pub struct Manifest {
    /// Original manifest bytes; these are never regenerated for transparent copying.
    pub raw: Bytes,
    /// Parsed JSON metadata used for inspection and dependency discovery.
    pub value: Value,
    /// Verified descriptor of the original manifest bytes.
    pub descriptor: Descriptor,
    /// Structural category used when traversing this manifest.
    pub kind: ManifestKind,
}
impl Manifest {
    /// Parse manifest bytes and validate optional media-type and digest expectations.
    pub fn parse(
        raw: Bytes,
        content_type: Option<&str>,
        expected: Option<&Digest>,
    ) -> Result<Self> {
        if let Some(d) = expected {
            d.verify(&raw)?;
        }
        let value: Value = serde_json::from_slice(&raw)?;
        if value.get("schemaVersion").and_then(Value::as_u64) != Some(2) {
            return Err(Error::unsupported(
                "only OCI and Docker schema 2 manifests/indexes are supported",
            ));
        }
        let media_type = value
            .get("mediaType")
            .and_then(Value::as_str)
            .or_else(|| content_type.map(|s| s.split(';').next().unwrap_or(s).trim()))
            .unwrap_or(if value.get("manifests").is_some() {
                OCI_INDEX
            } else {
                OCI_MANIFEST
            });
        let kind = match media_type {
            OCI_MANIFEST | DOCKER_MANIFEST => ManifestKind::Image,
            OCI_INDEX | DOCKER_INDEX => ManifestKind::Index,
            _ => {
                return Err(Error::unsupported(format!(
                    "unsupported manifest media type: {media_type}"
                )));
            }
        };
        let descriptor = Descriptor::new(
            media_type,
            expected.cloned().unwrap_or_else(|| Digest::sha256(&raw)),
            raw.len() as u64,
        );
        let result = Self {
            raw,
            value,
            descriptor,
            kind,
        };
        // Validate all known required fields without serializing the original document again.
        match kind {
            ManifestKind::Index => {
                result.children()?;
            }
            ManifestKind::Image => {
                result.blobs()?;
            }
        }
        Ok(result)
    }
    /// OCI image manifests also carry non-image artifacts with opaque configs.
    pub fn is_artifact(&self) -> Result<bool> {
        if self.kind != ManifestKind::Image || self.descriptor.media_type != OCI_MANIFEST {
            return Ok(false);
        }
        Ok(self.value.get("artifactType").is_some_and(|v| !v.is_null())
            || !matches!(
                self.config()?.media_type.as_str(),
                "application/vnd.oci.image.config.v1+json"
                    | "application/vnd.docker.container.image.v1+json"
            ))
    }

    /// Borrow the verified content digest of the original manifest bytes.
    pub fn digest(&self) -> &Digest {
        &self.descriptor.digest
    }
    /// Return child manifest descriptors for an index; image manifests have no children.
    pub fn children(&self) -> Result<Vec<Descriptor>> {
        if self.kind != ManifestKind::Index {
            return Ok(vec![]);
        }
        let v = self
            .value
            .get("manifests")
            .ok_or_else(|| Error::input("index has no manifests array"))?;
        serde_json::from_value(v.clone()).map_err(Into::into)
    }
    /// Return the configuration descriptor of an image or artifact manifest.
    pub fn config(&self) -> Result<Descriptor> {
        if self.kind != ManifestKind::Image {
            return Err(Error::input(
                "an index has no image config; select a platform",
            ));
        }
        serde_json::from_value(
            self.value
                .get("config")
                .cloned()
                .ok_or_else(|| Error::input("manifest has no config"))?,
        )
        .map_err(Into::into)
    }
    /// Return configuration and layer descriptors for a supported image or artifact manifest.
    pub fn blobs(&self) -> Result<Vec<Descriptor>> {
        if self.kind != ManifestKind::Image {
            return Ok(vec![]);
        }
        let mut blobs = vec![self.config()?];
        let layers = self
            .value
            .get("layers")
            .ok_or_else(|| Error::input("manifest has no layers array"))?;
        blobs.extend(serde_json::from_value::<Vec<Descriptor>>(layers.clone())?);
        Ok(blobs)
    }
    /// Reject manifest formats or payload features this transfer implementation cannot preserve.
    pub fn check_transfer_supported(&self) -> Result<()> {
        if self.value.get("subject").is_some_and(|v| !v.is_null()) {
            return Err(Error::unsupported(
                "manifest has subject: v0.1 does not implement referrer registration; refusing an incomplete transfer",
            ));
        }
        Ok(())
    }
    /// Compare this manifest's bytes and media type with an expected descriptor.
    pub fn verify_descriptor(&self, expected: &Descriptor) -> Result<()> {
        expected.embedded()?;
        expected.verify(&self.raw)?;
        if expected.media_type != self.descriptor.media_type {
            return Err(Error::integrity(
                "manifest media type does not match its parent descriptor",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn preserves_raw_bytes() {
        let raw = Bytes::from_static(b"{\n  \"schemaVersion\": 2, \"mediaType\": \"application/vnd.oci.image.index.v1+json\", \"manifests\": [], \"future\": true\n}");
        let m = Manifest::parse(raw.clone(), None, None).unwrap();
        assert_eq!(m.raw, raw);
        assert_eq!(m.value["future"], true);
    }
    #[test]
    fn artifact_classification_preserves_image_validation() {
        let mut value = serde_json::json!({
            "schemaVersion":2,"mediaType":OCI_MANIFEST,
            "config":Descriptor::new("application/vnd.oci.image.config.v1+json", Digest::sha256(b"{}"), 2),
            "layers":[]
        });
        let parse = |v: &Value| {
            Manifest::parse(Bytes::from(serde_json::to_vec(v).unwrap()), None, None).unwrap()
        };
        assert!(!parse(&value).is_artifact().unwrap());
        value["artifactType"] = Value::from("application/example");
        assert!(parse(&value).is_artifact().unwrap());
        value.as_object_mut().unwrap().remove("artifactType");
        value["config"]["mediaType"] = Value::from("application/vnd.aquasec.trivy.config.v1+json");
        assert!(parse(&value).is_artifact().unwrap());
        value["mediaType"] = Value::from(DOCKER_MANIFEST);
        assert!(!parse(&value).is_artifact().unwrap());
    }

    #[test]
    fn platform_matching() {
        let full: Platform = "linux/arm64/v8".parse().unwrap();
        let p: Platform = "linux/arm64".parse().unwrap();
        assert!(full.matches(&p));
        assert!(!full.matches(&"linux/arm64/v9".parse().unwrap()));
    }
    #[test]
    fn embedded_data_checks_digest() {
        let mut d = Descriptor::new("application/octet-stream", Digest::sha256(b"abc"), 3);
        d.data = Some(STANDARD.encode(b"abd"));
        assert!(d.embedded().is_err());
    }
}
