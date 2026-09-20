use crate::{
    Error, Result,
    auth::{AuthFile, Credential},
    cli::*,
    config::{self, Config, parse_size},
    error::Code,
    layout,
    model::{Manifest, ManifestKind, OCI_INDEX},
    reference::{Reference, registry_name, validate_repository},
    registry::Registry,
    transfer::{self, TransferStats},
};
use bytes::Bytes;
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::{IsTerminal, Read, Write},
    path::PathBuf,
    sync::{Arc, Mutex, atomic::AtomicBool},
};

/// Configure diagnostic verbosity and coordinate log output with terminal progress.
pub fn init_diagnostics(level: crate::diagnostics::Level, quiet: bool) {
    crate::diagnostics::init(level, quiet);
    crate::diagnostics::set_writer(|level, message| {
        crate::progress::suspend(|| {
            let _ = writeln!(std::io::stderr().lock(), "{level:?}: {message}");
        });
    });
}

/// Loaded configuration and credentials shared by one command invocation.
pub struct Context {
    /// Validated transfer limits and per-registry connection policies.
    pub config: Arc<Config>,
    /// Path used when persisting registry configuration changes.
    pub config_path: PathBuf,
    /// Path to the encrypted credential store.
    pub auth_path: PathBuf,
    /// Path to the separate credential-encryption master key.
    pub key_path: PathBuf,
    /// Tracks whether remote writes may have occurred, including uncertain responses.
    pub changed: Arc<AtomicBool>,
    auth: AuthFile,
    warnings: Mutex<BTreeSet<String>>,
    /// Whether this invocation may display interactive terminal progress.
    pub progress: bool,
}
impl Context {
    /// Load command configuration and credentials and determine terminal capabilities.
    pub fn new(cli: &Cli) -> Result<Self> {
        let config_path = match &cli.config {
            Some(p) => p.clone(),
            None => config::default_dir()?.join("config.toml"),
        };
        let (auth_path, key_path) =
            crate::auth::paths(cli.authfile.as_deref(), cli.keyfile.as_deref())?;
        let config = Arc::new(Config::load(&config_path)?);
        let auth = AuthFile::load(&auth_path, &key_path)?;
        Ok(Self {
            config,
            config_path,
            auth_path,
            key_path,
            auth,
            changed: Arc::new(AtomicBool::new(false)),
            warnings: Mutex::new(BTreeSet::new()),
            progress: !cli.json
                && !cli.quiet
                && !cli.no_progress
                && std::io::stderr().is_terminal(),
        })
    }
    /// Record a deduplicated warning for the command result.
    pub fn warn(&self, warning: impl Into<String>) {
        if let Ok(mut warnings) = self.warnings.lock() {
            warnings.insert(warning.into());
        }
    }
    /// Return accumulated warnings in deterministic order.
    pub fn warnings(&self) -> Vec<String> {
        self.warnings
            .lock()
            .map(|w| w.iter().cloned().collect())
            .unwrap_or_default()
    }
    fn connection_warnings(&self, name: &str) {
        let p = self.config.for_registry(name);
        if p.plain_http {
            self.warn(format!(
                "{name}: plain HTTP enabled; credentials and image data are unencrypted in transit"
            ));
        }
    }
    /// Construct a registry client using this command's policy and credentials.
    pub fn registry(&self, name: &str) -> Result<Registry> {
        self.connection_warnings(name);
        Registry::new(
            name,
            self.config.clone(),
            self.auth.registries.get(name).cloned(),
            self.changed.clone(),
        )
    }
}

/// Presentation payload consumed by the CLI's final output writer.
pub struct Output {
    /// Structured command data used in the JSON result envelope.
    pub data: Value,
    /// Human-readable result text for non-JSON output.
    pub text: String,
    /// Optional byte-exact output that takes precedence over human-readable text.
    pub raw: Option<Vec<u8>>,
}
impl Output {
    /// Construct a presentation payload with explicit structured data and human-readable text.
    pub fn new(data: Value, text: impl Into<String>) -> Self {
        Self {
            data,
            text: text.into(),
            raw: None,
        }
    }
    /// Create output whose text form is a pretty-printed version of its JSON data.
    pub fn structured(data: Value) -> Result<Self> {
        let text = serde_json::to_string_pretty(&data)?;
        Ok(Self::new(data, text))
    }
}
/// Handle commands that do not require a loaded registry context.
pub fn local_command(cli: &Cli) -> Result<Option<Output>> {
    match &cli.command {
        Command::Auth {
            command: AuthCommand::Migrate,
        } => {
            let (auth, key) = crate::auth::paths(cli.authfile.as_deref(), cli.keyfile.as_deref())?;
            let migrated = crate::vault::migrate(&auth, &key)?;
            Ok(Some(Output::new(
                json!({"authfile":auth,"keyfile":key,"migrated":migrated}),
                if migrated {
                    "Credentials encrypted; no plaintext backup created."
                } else {
                    "Credentials are already encrypted."
                },
            )))
        }
        Command::Version => Ok(Some(Output::new(
            json!({"version":env!("CARGO_PKG_VERSION"),"toolchain":"1.98.1"}),
            format!(
                "quayside {} (toolchain target: Rust 1.98.1)",
                env!("CARGO_PKG_VERSION")
            ),
        ))),
        Command::Completion(options) => crate::completion::run(options).map(Some),
        _ => Ok(None),
    }
}
fn parse_destination(s: &str) -> Result<Reference> {
    let r: Reference = s.parse()?;
    r.require_destination()?;
    Ok(r)
}
fn transfer_summary(
    digest: Option<&crate::digest::Digest>,
    stats: Option<&TransferStats>,
    dry_run: bool,
) -> String {
    let result = if dry_run {
        "Dry run complete; no remote content was changed.".into()
    } else if let Some(d) = digest {
        format!("Completed: {d}")
    } else {
        "Completed.".into()
    };
    let Some(stats) = stats else {
        return result;
    };
    let summary = if dry_run {
        format!(
            "Planned: {} blobs, skipped: {}",
            stats.planned_blobs, stats.skipped_blobs
        )
    } else {
        let mut summary = format!(
            "Copied: {} blobs, skipped: {}",
            stats.copied_blobs, stats.skipped_blobs
        );
        if stats.mounted_blobs > 0 {
            summary.push_str(&format!(", mounted: {}", stats.mounted_blobs));
        }
        summary
    };
    format!("{summary}\n{result}")
}

/// Execute a parsed command using the invocation context and return its presentation payload.
pub async fn run(ctx: &Context, command: &Command) -> Result<Output> {
    match command {
        Command::Login(options) => login(ctx, options).await,
        Command::Logout { registry } => {
            let registry = registry_name(registry)?;
            let removed = AuthFile::remove(&ctx.auth_path, &ctx.key_path, &registry)?;
            Ok(Output::new(
                json!({"registry":registry,"removed":removed,"server_token_revoked":false}),
                "Local credentials removed; server-issued tokens are not revoked.",
            ))
        }
        Command::Registry {
            command: RegistryCommand::Ping { registry },
        } => {
            let name = registry_name(registry)?;
            let reg = ctx.registry(&name)?;
            let authenticated = reg.ping().await?;
            Ok(Output::new(
                json!({"registry":name,"reachable":true,"authenticated_request":authenticated}),
                format!("{name}: reachable"),
            ))
        }
        Command::Registry {
            command: RegistryCommand::Set(options),
        } => {
            let name = registry_name(&options.registry)?;
            if options.insecure_skip_tls_verify == Some(true) {
                return Err(Error::unsupported(
                    "reqx does not support insecure_skip_tls_verify; configure --ca-file instead",
                ));
            }
            let ca = options
                .ca_file
                .as_ref()
                .map(std::fs::canonicalize)
                .transpose()?;
            if ca.as_ref().is_some_and(|p| !p.is_file()) {
                return Err(Error::input("CA path is not a file"));
            }
            let hosts = options
                .auth_hosts
                .iter()
                .map(|h| registry_name(h))
                .collect::<Result<Vec<_>>>()?;
            Config::save_registry(&ctx.config_path, &name, |entry| {
                if options.clear_ca {
                    entry.ca_file = None;
                } else if let Some(ca) = ca {
                    entry.ca_file = Some(ca);
                }
                if let Some(v) = options.plain_http {
                    entry.plain_http = v;
                }
                if let Some(v) = options.insecure_skip_tls_verify {
                    entry.insecure_skip_tls_verify = v;
                }
                if options.clear_auth_hosts {
                    entry.auth_hosts.clear();
                } else {
                    entry.auth_hosts.extend(hosts);
                    entry.auth_hosts.sort();
                    entry.auth_hosts.dedup();
                }
            })?;
            let configured = Config::load(&ctx.config_path)?.for_registry(&name);
            if configured.plain_http {
                ctx.warn(format!("{name}: plain HTTP configured"));
            }
            Ok(Output::new(
                json!({"registry":name,"config":configured}),
                "Registry configuration saved.",
            ))
        }
        Command::Repo {
            command: RepoCommand::Ls { registry },
        } => {
            let name = registry_name(registry)?;
            let reg = ctx.registry(&name)?;
            let repositories = reg.list_repositories().await.map_err(|e| {
                if matches!(e.code, Code::NotFound | Code::Unsupported) { Error::unsupported("registry catalog enumeration is not available; known repositories can still be used") } else { e }
            })?;
            let text = repositories.join("\n");
            Ok(Output::new(
                json!({"registry":name,"repositories":repositories}),
                text,
            ))
        }
        Command::Tag {
            command: TagCommand::Ls { repository },
        } => {
            let r: Reference = repository.parse()?;
            r.require_repository()?;
            let tags = ctx.registry(&r.registry)?.list_tags(&r.repository).await?;
            let text = tags.join("\n");
            Ok(Output::new(
                json!({"repository":r.repository_ref(),"tags":tags}),
                text,
            ))
        }
        Command::Manifest {
            command: ManifestCommand::Get { reference, raw },
        } => {
            let r: Reference = reference.parse()?;
            let m = ctx.registry(&r.registry)?.get_manifest(&r).await?;
            if *raw {
                Ok(Output {
                    data: Value::Null,
                    text: String::new(),
                    raw: Some(m.raw.to_vec()),
                })
            } else {
                Output::structured(m.value)
            }
        }
        Command::Image { command } => image(ctx, command).await,
        Command::Index {
            command:
                IndexCommand::Create {
                    destination,
                    sources,
                    write,
                },
        } => index_create(ctx, destination, sources, write).await,
        Command::Version | Command::Completion(_) | Command::Auth { .. } => {
            Err(Error::input("invalid command dispatch"))
        }
    }
}

async fn login(ctx: &Context, options: &Login) -> Result<Output> {
    let name = registry_name(&options.registry)?;
    if options.username.is_empty() || options.username.contains([':', '\r', '\n']) {
        return Err(Error::input("invalid login username"));
    }
    let mut secret = if options.password_stdin {
        let mut secret = String::new();
        std::io::stdin().take(65_537).read_to_string(&mut secret)?;
        if secret.len() > 65_536 {
            return Err(Error::input("password input exceeds 64KiB"));
        }
        if secret.ends_with('\n') {
            secret.pop();
            if secret.ends_with('\r') {
                secret.pop();
            }
        }
        secret
    } else {
        if !std::io::stdin().is_terminal() {
            return Err(Error::input(
                "non-interactive login requires --password-stdin",
            ));
        }
        rpassword::prompt_password("Password / token: ")?
    };
    if secret.is_empty() {
        return Err(Error::input("empty password/token"));
    }
    let credential = Credential {
        username: options.username.clone(),
        secret: std::mem::take(&mut secret),
    };
    ctx.connection_warnings(&name);
    let verified = if options.save_unverified {
        false
    } else {
        let registry = Registry::new(
            &name,
            ctx.config.clone(),
            Some(credential.clone()),
            ctx.changed.clone(),
        )?;
        let authenticated = if let Some(repo) = &options.repository {
            validate_repository(repo)?;
            registry.verify_repository(repo).await?
        } else {
            registry.ping().await?
        };
        if !authenticated {
            return Err(Error::new(
                Code::UnverifiedCredentials,
                "endpoint allowed anonymous access, so credentials were not verified; use --repository with a private repository, or explicitly use --save-unverified",
            ));
        }
        true
    };
    AuthFile::put(&ctx.auth_path, &ctx.key_path, &name, credential)?;
    if !verified {
        ctx.warn("Credentials were stored without remote verification.");
    }
    Ok(Output::new(
        json!({"registry":name,"verified":verified,"authfile":ctx.auth_path,"keyfile":ctx.key_path,"encrypted":true}),
        if verified {
            "Login verified; credentials saved."
        } else {
            "Credentials saved (not verified)."
        },
    ))
}

async fn image(ctx: &Context, command: &ImageCommand) -> Result<Output> {
    match command {
        ImageCommand::Digest {
            reference,
            platform,
        } => {
            let r: Reference = reference.parse()?;
            let resolved =
                transfer::resolve(&ctx.registry(&r.registry)?, &r, platform.as_deref()).await?;
            let digest = resolved.manifest.digest().to_string();
            Ok(Output::new(
                json!({"reference":r.to_string(),"source_digest":resolved.source_digest,"digest":digest}),
                digest,
            ))
        }
        ImageCommand::Inspect {
            reference,
            platform,
        } => {
            let r: Reference = reference.parse()?;
            let reg = ctx.registry(&r.registry)?;
            let resolved = transfer::resolve(&reg, &r, platform.as_deref()).await?;
            let m = &resolved.manifest;
            let config = if m.kind == ManifestKind::Image && !m.is_artifact()? {
                let bytes = reg
                    .get_blob_bytes(
                        &r.repository,
                        &m.config()?,
                        parse_size(&ctx.config.transfer.max_manifest_size)?,
                    )
                    .await?;
                serde_json::from_slice::<Value>(&bytes)?
            } else {
                Value::Null
            };
            Output::structured(
                json!({"reference":r.to_string(),"source_digest":resolved.source_digest,
                "digest":m.digest(),"media_type":m.descriptor.media_type,"size":m.raw.len(),"platforms":resolved.platforms,
                "manifest":m.value,"config":config}),
            )
        }
        ImageCommand::Copy {
            source,
            destination,
            selection,
            write,
        } => {
            let src: Reference = source.parse()?;
            let dst = parse_destination(destination)?;
            let data = transfer::copy(
                &ctx.registry(&src.registry)?,
                &src,
                &ctx.registry(&dst.registry)?,
                &dst,
                selection.platform.as_deref(),
                &write.into(),
                &crate::progress::TerminalObserver(ctx.progress),
            )
            .await?;
            ctx.warn("Independent referrers (signatures/SBOMs) were not copied.");
            let text = transfer_summary(Some(&data.target_digest), Some(&data.stats), data.dry_run);
            Ok(Output::new(serde_json::to_value(data)?, text))
        }
        ImageCommand::Pull {
            reference,
            output,
            format,
            selection,
            write,
        } => {
            let r: Reference = reference.parse()?;
            let data = layout::pull(
                &ctx.registry(&r.registry)?,
                &r,
                output,
                (*format).into(),
                selection.platform.as_deref(),
                &write.into(),
            )
            .await?;
            ctx.warn("Independent referrers were not exported.");
            let text = transfer_summary(Some(&data.target_digest), None, data.dry_run);
            Ok(Output::new(serde_json::to_value(data)?, text))
        }
        ImageCommand::Push {
            path,
            destination,
            reference,
            write,
        } => {
            let dst = parse_destination(destination)?;
            let data = layout::push(
                path,
                reference.as_deref(),
                &ctx.registry(&dst.registry)?,
                &dst,
                &write.into(),
            )
            .await?;
            ctx.warn("Only the selected OCI layout dependency graph was pushed; no signature trust verification was performed.");
            let text = transfer_summary(Some(&data.target_digest), Some(&data.stats), data.dry_run);
            Ok(Output::new(serde_json::to_value(data)?, text))
        }
        ImageCommand::Tag {
            source,
            destination,
            write,
        } => {
            let src: Reference = source.parse()?;
            let dst = parse_destination(destination)?;
            if src.registry != dst.registry || src.repository != dst.repository {
                return Err(Error::input(
                    "image tag requires the same registry and repository; use image copy across repositories",
                ));
            }
            if dst.digest().is_some() {
                return Err(Error::input("image tag destination must be a tag"));
            }
            let reg = ctx.registry(&src.registry)?;
            let manifest = reg.get_manifest(&src).await?;
            manifest.check_transfer_supported()?;
            transfer::check_destination(&reg, &dst, &manifest, write.overwrite).await?;
            if !write.dry_run {
                transfer::publish_root(&reg, &dst, &manifest, write.overwrite).await?;
            }
            let data = json!({"source":src.to_string(),"destination":dst.to_string(),"target_digest":manifest.digest(),"dry_run":write.dry_run});
            let text = transfer_summary(Some(manifest.digest()), None, write.dry_run);
            Ok(Output::new(data, text))
        }
    }
}

async fn index_create(
    ctx: &Context,
    destination: &str,
    sources: &[String],
    write: &WriteOptions,
) -> Result<Output> {
    let dst = parse_destination(destination)?;
    let target = ctx.registry(&dst.registry)?;
    let mut inputs = BTreeMap::new();
    let mut seen_digests = BTreeSet::new();
    let mut metadata_bytes = 0u64;
    let mut object_count = 0usize;
    for source in sources {
        let r: Reference = source.parse()?;
        let reg = ctx.registry(&r.registry)?;
        let mut manifest = reg.get_manifest(&r).await?;
        if manifest.kind != ManifestKind::Image {
            return Err(Error::input(
                "index create --from accepts single-platform images only",
            ));
        }
        let platform = transfer::image_platform(&reg, &r.repository, &manifest).await?;
        if !seen_digests.insert(manifest.digest().clone()) {
            continue;
        }
        if inputs.contains_key(&platform.to_string()) {
            return Err(Error::conflict(format!(
                "multiple different images for platform {platform}"
            )));
        }
        manifest.descriptor.platform = Some(platform.clone());
        let graph = transfer::remote_graph(&reg, &r, manifest).await?;
        metadata_bytes += graph
            .manifests
            .values()
            .map(|m| m.raw.len() as u64)
            .sum::<u64>();
        object_count += graph.manifests.len() + graph.blobs.len();
        if metadata_bytes > parse_size(&ctx.config.transfer.max_metadata_size)?
            || object_count > ctx.config.transfer.max_objects
        {
            return Err(Error::input(
                "combined index input graph exceeds configured resource limits",
            ));
        }
        inputs.insert(platform.to_string(), (reg, r, graph));
    }
    let descriptors: Vec<_> = inputs
        .values()
        .map(|(_, _, graph)| graph.root.descriptor.clone())
        .collect();
    let body = Bytes::from(serde_json::to_vec(
        &json!({"schemaVersion":2,"mediaType":OCI_INDEX,"manifests":descriptors}),
    )?);
    let index = Manifest::parse(body, Some(OCI_INDEX), None)?;
    transfer::check_destination(&target, &dst, &index, write.overwrite).await?;
    let mut stats = TransferStats::default();
    let mut planned = BTreeSet::new();
    for (source, source_ref, graph) in inputs.values() {
        let mut unique = graph.clone();
        if write.dry_run {
            unique
                .blobs
                .retain(|digest, _| planned.insert(digest.clone()));
        }
        stats.merge(
            &transfer::transfer_remote_blobs(
                source,
                source_ref,
                &target,
                &dst,
                &unique,
                write.dry_run,
                &crate::progress::TerminalObserver(ctx.progress),
            )
            .await?,
        );
        if !write.dry_run {
            transfer::publish_dependencies(&target, &dst, graph).await?;
        }
    }
    if !write.dry_run {
        transfer::publish_root(&target, &dst, &index, write.overwrite).await?;
    }
    ctx.warn("Independent referrers were not copied. Input images were not deleted.");
    let data = json!({"destination":dst.to_string(),"target_digest":index.digest(),"platforms":inputs.keys().collect::<Vec<_>>(),
        "stats":stats,"dry_run":write.dry_run,"referrers":"not-copied"});
    let text = transfer_summary(Some(index.digest()), Some(&stats), write.dry_run);
    Ok(Output::new(data, text))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn transfer_summary_uses_actual_counts_and_distinguishes_dry_runs() {
        let digest = crate::digest::Digest::sha256(b"example");
        let mut stats = TransferStats {
            copied_blobs: 69,
            skipped_blobs: 19,
            ..Default::default()
        };
        assert_eq!(
            transfer_summary(Some(&digest), Some(&stats), false),
            format!("Copied: 69 blobs, skipped: 19\nCompleted: {digest}")
        );
        stats.mounted_blobs = 2;
        assert!(transfer_summary(Some(&digest), Some(&stats), false).contains("mounted: 2"));
        stats.planned_blobs = 69;
        assert_eq!(
            transfer_summary(Some(&digest), Some(&stats), true),
            "Planned: 69 blobs, skipped: 19\nDry run complete; no remote content was changed."
        );
        assert_eq!(transfer_summary(None, None, false), "Completed.");
    }
}
