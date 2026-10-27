use crate::{Error, Result, digest::Digest};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use bytes::Bytes;
use serde::{Deserialize, Deserializer, Serialize};
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
    #[serde(deserialize_with = "deserialize_platform_component")]
    pub os: String,
    /// Target CPU architecture name.
    #[serde(deserialize_with = "deserialize_platform_component")]
    pub architecture: String,
    /// Optional architecture variant, such as arm v7 or arm64 v8.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_platform_variant"
    )]
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
    /// Return the local container platform; supported macOS hosts run Linux containers.
    pub fn native() -> Result<Self> {
        native_platform(std::env::consts::OS, std::env::consts::ARCH)?.parse()
    }
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
        for (field, name) in [("os", "operating system"), ("architecture", "architecture")] {
            if !config
                .get(field)
                .and_then(Value::as_str)
                .is_some_and(|value| !value.is_empty())
            {
                return Err(Error::input(format!("image config has no {name}")));
            }
        }
        // Retain only platform metadata, rather than copying image layers, history or secrets.
        // OCI config optional properties may be null, which is equivalent to absence.
        let fields = ["os", "architecture", "variant", "os.version", "os.features"]
            .into_iter()
            .filter_map(|name| {
                config
                    .get(name)
                    .filter(|value| !value.is_null())
                    .map(|value| (name.to_owned(), value.clone()))
            })
            .collect();
        serde_json::from_value(Value::Object(fields)).map_err(Into::into)
    }
}

fn valid_platform_component(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
}

fn deserialize_platform_component<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<String, D::Error> {
    let value = String::deserialize(deserializer)?;
    if !valid_platform_component(&value) {
        return Err(serde::de::Error::custom("invalid platform component"));
    }
    Ok(value)
}

fn deserialize_platform_variant<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Option<String>, D::Error> {
    let value = Option::<String>::deserialize(deserializer)?;
    if value
        .as_deref()
        .is_some_and(|value| !valid_platform_component(value))
    {
        return Err(serde::de::Error::custom("invalid platform variant"));
    }
    Ok(value)
}

fn native_platform(os: &str, architecture: &str) -> Result<&'static str> {
    match (os, architecture) {
        ("linux", "x86_64") => Ok("linux/amd64"),
        ("linux" | "macos", "aarch64") => Ok("linux/arm64"),
        _ => Err(Error::input(
            "cannot determine the local container platform; use --platform or --all",
        )),
    }
}
impl FromStr for Platform {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        let parts: Vec<_> = s.split('/').collect();
        if !(2..=3).contains(&parts.len()) || parts.iter().any(|s| !valid_platform_component(s)) {
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
            .map(|value| {
                value
                    .as_str()
                    .ok_or_else(|| Error::input("manifest mediaType must be a string"))
            })
            .transpose()?
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
        if result
            .value
            .get("artifactType")
            .is_some_and(|value| !value.as_str().is_some_and(|value| !value.is_empty()))
        {
            return Err(Error::input(
                "manifest artifactType must be a nonempty string",
            ));
        }
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
    /// Return the optional subject association without treating it as a content dependency.
    pub fn subject(&self) -> Result<Option<Descriptor>> {
        self.value
            .get("subject")
            .filter(|value| !value.is_null())
            .map(|value| serde_json::from_value(value.clone()).map_err(Into::into))
            .transpose()
    }

    pub(crate) fn referrer_descriptor(&self) -> Result<Descriptor> {
        let mut descriptor = self.descriptor.clone();
        descriptor.platform = None;
        descriptor.annotations = self
            .value
            .get("annotations")
            .map(|value| serde_json::from_value(value.clone()))
            .transpose()?
            .unwrap_or_default();
        let artifact_type = self
            .value
            .get("artifactType")
            .map(|value| {
                value
                    .as_str()
                    .ok_or_else(|| Error::input("manifest artifactType must be a string"))
            })
            .transpose()?
            .filter(|value| !value.is_empty());
        let artifact_type = match artifact_type {
            Some(value) => Some(value.to_owned()),
            None if self.kind == ManifestKind::Image => Some(self.config()?.media_type),
            None => None,
        };
        if let Some(value) = artifact_type {
            descriptor.extra.insert("artifactType".into(), value.into());
        }
        Ok(descriptor)
    }

    /// Validate optional subject and registration metadata before transferring content.
    pub fn check_transfer_supported(&self) -> Result<()> {
        if let Some(subject) = self.subject()? {
            subject.embedded()?;
            self.referrer_descriptor()?;
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
    fn subject_registration_validates_metadata_and_preserves_bytes() {
        let subject = Descriptor::new(OCI_MANIFEST, Digest::sha256(b"subject"), 7);
        let value = serde_json::json!({
            "schemaVersion": 2, "mediaType": OCI_MANIFEST, "subject": subject,
            "config": Descriptor::new("application/example", Digest::sha256(b"{}"), 2),
            "layers": [], "annotations": {"example.title": "proof"}
        });
        let raw = serde_json::to_vec(&value).unwrap();
        let manifest = Manifest::parse(raw.clone().into(), None, None).unwrap();
        manifest.check_transfer_supported().unwrap();
        let descriptor = manifest.referrer_descriptor().unwrap();
        assert_eq!(descriptor.extra["artifactType"], "application/example");
        assert_eq!(descriptor.annotations["example.title"], "proof");
        assert_eq!(manifest.raw, raw);
        for (field, invalid) in [
            ("subject", serde_json::json!({"digest": subject.digest})),
            ("subject", serde_json::json!("not a descriptor")),
            (
                "subject",
                serde_json::json!({"mediaType": OCI_MANIFEST, "size": 7, "digest": "sha256:invalid"}),
            ),
            ("annotations", serde_json::json!({"example.title": 1})),
        ] {
            let mut invalid_value = value.clone();
            invalid_value[field] = invalid;
            let manifest = Manifest::parse(
                serde_json::to_vec(&invalid_value).unwrap().into(),
                None,
                None,
            )
            .unwrap();
            assert!(manifest.check_transfer_supported().is_err(), "{field}");
        }
    }
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
    fn malformed_media_types_cannot_fall_back_or_bypass_image_selection() {
        let valid = serde_json::json!({
            "schemaVersion": 2, "mediaType": OCI_MANIFEST,
            "config": Descriptor::new("application/vnd.oci.image.config.v1+json", Digest::sha256(b"{}"), 2),
            "layers": []
        });
        for (field, invalid) in [
            ("mediaType", serde_json::json!(false)),
            ("mediaType", Value::Null),
            ("artifactType", serde_json::json!(true)),
            ("artifactType", serde_json::json!("")),
            ("artifactType", serde_json::json!({"type": "proof"})),
        ] {
            let mut value = valid.clone();
            value[field] = invalid;
            assert!(
                Manifest::parse(
                    serde_json::to_vec(&value).unwrap().into(),
                    Some(OCI_MANIFEST),
                    None
                )
                .is_err(),
                "{field}"
            );
        }
    }

    #[test]
    fn artifact_type_validation_does_not_depend_on_subject_registration() {
        let subject = Descriptor::new(OCI_MANIFEST, Digest::sha256(b"subject"), 7);
        for media_type in [OCI_MANIFEST, OCI_INDEX] {
            for with_subject in [false, true] {
                let mut value = serde_json::json!({
                    "schemaVersion": 2, "mediaType": media_type
                });
                if media_type == OCI_MANIFEST {
                    value["config"] = serde_json::json!(Descriptor::new(
                        "application/vnd.oci.image.config.v1+json",
                        Digest::sha256(b"{}"),
                        2,
                    ));
                    value["layers"] = serde_json::json!([]);
                } else {
                    value["manifests"] = serde_json::json!([]);
                }
                if with_subject {
                    value["subject"] = serde_json::json!(subject);
                }
                for artifact_type in [None, Some(serde_json::json!("application/example"))] {
                    if let Some(artifact_type) = artifact_type {
                        value["artifactType"] = artifact_type;
                    }
                    let manifest =
                        Manifest::parse(serde_json::to_vec(&value).unwrap().into(), None, None)
                            .unwrap();
                    manifest.check_transfer_supported().unwrap();
                }
                value["artifactType"] = Value::Null;
                let error = Manifest::parse(serde_json::to_vec(&value).unwrap().into(), None, None)
                    .unwrap_err();
                assert_eq!(error.code, crate::error::Code::InvalidInput);
                assert_eq!(
                    error.message,
                    "manifest artifactType must be a nonempty string"
                );
            }
        }
    }

    #[test]
    fn native_platform_maps_supported_container_hosts() {
        assert_eq!(native_platform("linux", "x86_64").unwrap(), "linux/amd64");
        assert_eq!(native_platform("linux", "aarch64").unwrap(), "linux/arm64");
        assert_eq!(native_platform("macos", "aarch64").unwrap(), "linux/arm64");
        assert!(native_platform("unknown", "unknown").is_err());
        assert!(native_platform("linux", "arm").is_err());
    }
    #[test]
    fn platform_matching() {
        let full: Platform = "linux/arm64/v8".parse().unwrap();
        let p: Platform = "linux/arm64".parse().unwrap();
        assert!(full.matches(&p));
        assert!(!full.matches(&"linux/arm64/v9".parse().unwrap()));
    }
    #[test]
    fn platform_metadata_rejects_malformed_components_and_types() {
        for (field, invalid) in [
            ("os", serde_json::json!("linux/amd64")),
            ("architecture", serde_json::json!("amd64/v2")),
            ("architecture", serde_json::json!("")),
            ("variant", serde_json::json!("v8\nforged output")),
            ("variant", serde_json::json!(true)),
            ("os.version", serde_json::json!(42)),
            ("os.features", serde_json::json!(["valid", false])),
        ] {
            let mut metadata = serde_json::json!({"os": "linux", "architecture": "amd64"});
            metadata[field] = invalid;
            assert!(Platform::from_config(&metadata).is_err(), "{field}");
            assert!(
                serde_json::from_value::<Platform>(metadata).is_err(),
                "{field}"
            );
        }
    }
    #[test]
    fn config_platform_ignores_unrelated_fields_and_accepts_null_options() {
        let config = serde_json::json!({
            "os": "linux", "architecture": "arm64", "variant": "v8",
            "os.version": null, "os.features": null,
            "rootfs": {"diff_ids": ["unrelated"]},
            "config": {"Env": ["SECRET=value"]}
        });
        let platform = Platform::from_config(&config).unwrap();
        assert_eq!(platform, "linux/arm64/v8".parse().unwrap());
        let mut missing_os = config.clone();
        missing_os["os"] = Value::Null;
        assert!(Platform::from_config(&missing_os).is_err());
    }
    #[test]
    fn embedded_data_checks_digest() {
        let mut d = Descriptor::new("application/octet-stream", Digest::sha256(b"abc"), 3);
        d.data = Some(STANDARD.encode(b"abd"));
        assert!(d.embedded().is_err());
    }
}
