//! Optional Docker content cache. Remote descriptors remain the source of truth.
use super::{blocking, docker, safe_archive_path, validate_archive_headers};
use crate::{
    Error, Result,
    config::{TransferConfig, duration, parse_size},
    diagnostics::{Level, log},
    digest::Digest,
    graph::Graph,
    model::Descriptor,
    observer::{BlobPhase, BlobProgress},
    reference::Reference,
    temporary::{Budget, Reservation},
};
use std::{collections::BTreeMap, path::Path, process::Stdio, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt},
    sync::OnceCell,
};

pub(crate) struct DockerCache<'a> {
    reference: &'a Reference,
    limits: &'a TransferConfig,
    graph: &'a Graph,
    archive: OnceCell<Option<Archive>>,
}

struct Archive {
    // Remove exported bytes before releasing their reservation, including on cancellation.
    file: tempfile::NamedTempFile,
    _reservation: Reservation,
    blobs: BTreeMap<Digest, (u64, u64)>,
}

impl<'a> DockerCache<'a> {
    pub(crate) fn new(
        reference: &'a Reference,
        limits: &'a TransferConfig,
        graph: &'a Graph,
    ) -> Self {
        Self {
            reference,
            limits,
            graph,
            archive: OnceCell::new(),
        }
    }

    pub(crate) async fn prepare(&self, budget: &Arc<Budget>) {
        self.archive
            .get_or_init(|| async {
                match self.load(budget).await {
                    Ok(archive) => archive,
                    Err(_) => {
                        log(
                            Level::Debug,
                            format_args!("Docker cache unavailable; using registry downloads"),
                        );
                        None
                    }
                }
            })
            .await;
    }

    pub(crate) async fn stage(
        &self,
        descriptor: &Descriptor,
        output: &Path,
        progress: &dyn BlobProgress,
    ) -> bool {
        let Some(archive) = self.archive.get().and_then(Option::as_ref) else {
            return false;
        };
        let Some(&(offset, size)) = archive.blobs.get(&descriptor.digest) else {
            return false;
        };
        if size != descriptor.size {
            return false;
        }
        progress.phase(BlobPhase::Verifying);
        let result = async {
            let mut input = tokio::fs::File::open(archive.file.path()).await?;
            input.seek(std::io::SeekFrom::Start(offset)).await?;
            let mut output = tokio::fs::File::create(output).await?;
            let mut remaining = size;
            let mut buffer = vec![0u8; 64 * 1024];
            let mut hasher = descriptor.digest.hasher();
            while remaining > 0 {
                let length = remaining.min(buffer.len() as u64) as usize;
                input.read_exact(&mut buffer[..length]).await?;
                hasher.update(&buffer[..length]);
                output.write_all(&buffer[..length]).await?;
                remaining -= length as u64;
                progress.position(size - remaining);
            }
            hasher.verify(&descriptor.digest)?;
            output.flush().await?;
            Ok::<_, Error>(())
        }
        .await;
        if result.is_err() {
            log(
                Level::Debug,
                format_args!("Docker cache blob failed verification; using registry download"),
            );
            return false;
        }
        log(
            Level::Debug,
            format_args!("Reusing Docker blob {}", descriptor.digest),
        );
        true
    }

    async fn load(&self, budget: &Arc<Budget>) -> Result<Option<Archive>> {
        // Keep room for the largest worker file so retaining the archive cannot deadlock downloads.
        let largest = self.graph.blobs.values().map(|d| d.size).max().unwrap_or(0);
        let allowance = budget
            .limit()
            .saturating_sub(largest)
            .min(parse_size(&self.limits.max_archive_size)?);
        if allowance < 1024 {
            return Ok(None);
        }
        let Some(image) = inspect(self.reference, self.limits).await? else {
            return Ok(None);
        };
        let mut reservation = budget.reserve(allowance).await?;
        let mut limits = self.limits.clone();
        limits.max_temp_size = allowance.to_string();
        let file = docker::export(Path::new(image.as_str()), &limits).await?;
        reservation.shrink_to(file.as_file().metadata()?.len());
        let path = file.path().to_owned();
        let wanted: BTreeMap<_, _> = self
            .graph
            .blobs
            .iter()
            .map(|(digest, descriptor)| (digest.clone(), descriptor.size))
            .collect();
        let blobs = blocking(move |flag| {
            validate_archive_headers(&path, &limits, flag.clone())?;
            let reader = super::Cancellable {
                reader: std::io::BufReader::new(std::fs::File::open(&path)?),
                cancelled: flag,
            };
            let mut tar = tar::Archive::new(reader);
            let mut blobs = BTreeMap::new();
            for entry in tar.entries_with_seek()? {
                let entry = entry?;
                let path = safe_archive_path(&entry.path()?)?;
                if !entry.header().entry_type().is_file() {
                    continue;
                }
                let Some(digest) = path_digest(&path) else {
                    continue;
                };
                if wanted
                    .get(&digest)
                    .is_some_and(|size| *size == entry.size())
                    && blobs
                        .insert(digest, (entry.raw_file_position(), entry.size()))
                        .is_some()
                {
                    return Err(Error::input("duplicate Docker cache blob"));
                }
            }
            Ok(blobs)
        })
        .await?;
        if blobs.is_empty() {
            return Ok(None);
        }
        Ok(Some(Archive {
            file,
            _reservation: reservation,
            blobs,
        }))
    }
}

fn path_digest(path: &Path) -> Option<Digest> {
    let path = path.to_str()?;
    if let Some(blob) = path.strip_prefix("blobs/") {
        let (algorithm, encoded) = blob.split_once('/')?;
        format!("{algorithm}:{encoded}").parse().ok()
    } else if !path.contains('/') {
        // Classic Docker saves name image configs by digest. Uncompressed legacy layers
        // cannot stand in for a registry's compressed blobs and are deliberately not converted.
        format!("sha256:{}", path.strip_suffix(".json")?)
            .parse()
            .ok()
    } else {
        None
    }
}

async fn inspect(reference: &Reference, limits: &TransferConfig) -> Result<Option<Digest>> {
    let mut child = match tokio::process::Command::new("docker")
        // The classic store exports reconstructed, uncompressed layers. Avoid a full export
        // when Docker cannot expose an OCI content descriptor for the locally stored image.
        .args([
            "image",
            "inspect",
            "--format",
            "{{if .Descriptor}}{{.Descriptor.Digest}}{{end}}",
            "--",
        ])
        .arg(reference.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
    {
        Ok(child) => child,
        Err(_) => return Ok(None),
    };
    let Some(stdout) = child.stdout.take() else {
        return Ok(None);
    };
    let result = tokio::time::timeout(
        duration(&limits.connect_timeout)?.min(Duration::from_secs(2)),
        async {
            let mut raw = Vec::new();
            stdout.take(257).read_to_end(&mut raw).await?;
            if raw.len() > 256 {
                return Ok(None);
            }
            if !child.wait().await?.success() {
                return Ok(None);
            }
            Ok::<_, Error>(
                std::str::from_utf8(&raw)
                    .ok()
                    .and_then(|value| value.trim().parse().ok()),
            )
        },
    )
    .await;
    // A missing/unresponsive daemon is a cache miss, never a requirement for remote copy.
    result.unwrap_or(Ok(None))
}
