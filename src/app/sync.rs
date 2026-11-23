use super::{Context, MirrorPolicy, Outcome, Output};
use crate::{
    Error, Result,
    observer::{Observer, Phase},
    options::{PlatformSelection, TransferOptions, WriteOptions},
    progress::{Status, TerminalObserver},
    reference::Reference,
    registry::TagPattern,
    transfer::{self, CopyResult, Resolved},
};
use serde::Deserialize;
use serde_json::json;
use std::{
    collections::{BTreeMap, btree_map::Entry},
    io::Write,
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SyncFile {
    platform: Option<String>,
    sync: Vec<JobConfig>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct JobConfig {
    from: String,
    to: String,
    #[serde(default)]
    overwrite: bool,
}

struct Job {
    from: Reference,
    to: Reference,
    pattern: Option<TagPattern>,
    overwrite: bool,
}

impl JobConfig {
    fn parse(self) -> Result<Job> {
        let (from, pattern) = if self.from.contains('*') {
            let (repository, pattern) = self.from.rsplit_once(':').ok_or_else(|| {
                Error::input("a numeric tag pattern must follow the repository and a colon")
            })?;
            let from = Reference::parse_source(repository)?;
            from.require_repository()?;
            (from, Some(TagPattern::new(pattern)?))
        } else {
            (Reference::parse_source(&self.from)?, None)
        };
        let to: Reference = self.to.parse()?;
        if from.digest().is_some() && !to.explicit {
            return Err(Error::input(
                "a digest source requires an explicit destination tag or digest",
            ));
        }
        Ok(Job {
            from,
            to,
            pattern,
            overwrite: self.overwrite,
        })
    }
}

#[derive(Default)]
struct RepositorySnapshot {
    tags: Option<Result<Vec<String>>>,
    manifests: BTreeMap<(String, bool), Result<Resolved>>,
}

impl Job {
    fn source(&self) -> String {
        match &self.pattern {
            Some(pattern) => format!("{}:{pattern}", self.from.repository_ref()),
            None => self.from.to_string(),
        }
    }

    fn destination(&self) -> String {
        if self.to.explicit {
            self.to.to_string()
        } else {
            self.to.repository_ref()
        }
    }

    async fn copy(
        &mut self,
        ctx: &Context,
        selection: &PlatformSelection,
        snapshot: &mut RepositorySnapshot,
        changed: Arc<AtomicBool>,
        observer: &TerminalObserver,
    ) -> Result<CopyResult> {
        let policy = if self.pattern.is_some() {
            MirrorPolicy::ContentOnly
        } else {
            MirrorPolicy::TagsAndContent
        };
        let source = ctx.source_registry(&self.from.registry, policy)?;
        let resolving = observer.begin(Phase::Resolving, 0);
        if let Some(pattern) = &self.pattern {
            let tags = match &mut snapshot.tags {
                Some(tags) => tags,
                None => snapshot
                    .tags
                    .insert(source.list_tags(&self.from.repository).await),
            };
            self.from.selector = pattern.latest(
                tags.as_ref().map_err(Clone::clone)?,
                &self.from.repository_ref(),
            )?;
            self.from.explicit = true;
            self.pattern = None;
            observer.set_image(self.from.to_string());
        }
        if !self.to.explicit {
            self.to.selector.clone_from(&self.from.selector);
            self.to.explicit = true;
        }
        let options = TransferOptions::default();
        let key = (
            self.from.selector.clone(),
            source.resolves_tags_at_mirrors() && self.from.digest().is_none(),
        );
        let resolved = match snapshot.manifests.entry(key) {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) => entry.insert(
                transfer::associated::selected(&source, &self.from, selection, &options).await,
            ),
        };
        let resolved = resolved.clone()?;
        drop(resolving);
        let target = ctx.registry(&self.to.registry)?.track_job_writes(changed);
        transfer::copy_resolved(
            &source,
            &self.from,
            &target,
            &self.to,
            resolved,
            &WriteOptions {
                overwrite: self.overwrite,
                dry_run: false,
            },
            &options,
            observer,
        )
        .await
    }
}

pub(super) async fn run(ctx: &Context, path: &Path, platform: Option<&str>) -> Result<Output> {
    let text = tokio::fs::read_to_string(path).await.map_err(|e| {
        Error::new(
            crate::error::Code::Execution,
            format!("cannot read sync file {}: {e}", path.display()),
        )
    })?;
    let file: SyncFile = toml::from_str(&text).map_err(|e| {
        let line = e.span().map(|span| {
            1 + text.as_bytes()[..span.start]
                .iter()
                .filter(|b| **b == b'\n')
                .count()
        });
        let location = line.map_or_else(String::new, |line| format!(" at line {line}"));
        Error::input(format!(
            "invalid sync file {}{location}: {}",
            path.display(),
            e.message()
        ))
    })?;
    if file.sync.is_empty() {
        return Err(Error::input(
            "sync file must contain at least one [[sync]] table",
        ));
    }
    let selection = match platform.or(file.platform.as_deref()) {
        Some(value) => PlatformSelection::Platform(value.parse()?),
        None => PlatformSelection::Native,
    };
    let jobs = file
        .sync
        .into_iter()
        .enumerate()
        .map(|(index, job)| {
            job.parse()
                .map_err(|e| Error::input(format!("invalid sync entry {}: {e}", index + 1)))
        })
        .collect::<Result<Vec<_>>>()?;
    // Release tag pages and manifests as soon as the last job for a repository finishes.
    let last_job: BTreeMap<_, _> = jobs
        .iter()
        .enumerate()
        .map(|(i, job)| (job.from.repository_ref(), i))
        .collect();
    let mut snapshots = BTreeMap::new();
    let mut results = Vec::with_capacity(jobs.len());
    let (mut copied, mut up_to_date, mut failed) = (0, 0, 0);
    let mut first_error = None;
    for (i, mut job) in jobs.into_iter().enumerate() {
        let repo = job.from.repository_ref();
        let snapshot = snapshots.entry(repo.clone()).or_default();
        let changed = Arc::new(AtomicBool::new(false));
        let observer = TerminalObserver::new(ctx.progress, job.source(), Phase::Copying);
        let result = job
            .copy(ctx, &selection, snapshot, changed.clone(), &observer)
            .await;
        if last_job[&repo] == i {
            snapshots.remove(&repo);
        }
        let wrote = changed.load(Ordering::SeqCst);
        let (item, line) = match result {
            Ok(copy) => {
                let unchanged = copy.already_present && !wrote;
                let (status, label) = if unchanged {
                    up_to_date += 1;
                    observer.finish(Status::UpToDate);
                    ("up_to_date", "Up to date")
                } else {
                    copied += 1;
                    observer.finish(Status::Complete);
                    ("copied", "Copied")
                };
                let platforms = if copy.platforms.is_empty() {
                    String::new()
                } else {
                    format!(" [{}]", copy.platforms.join(", "))
                };
                let line = format!(
                    "{label}  {} -> {}{platforms}  {}",
                    copy.source, copy.destination, copy.target_digest
                );
                (
                    json!({"from":copy.source, "to":copy.destination, "status":status, "digest":copy.target_digest, "platforms":copy.platforms}),
                    line,
                )
            }
            Err(error) => {
                observer.finish(Status::Failed);
                failed += 1;
                let from = job.source();
                let to = job.destination();
                let reason = error
                    .to_string()
                    .split_whitespace()
                    .collect::<Vec<_>>()
                    .join(" ");
                let partial = if wrote {
                    " (remote writes may have occurred)"
                } else {
                    ""
                };
                let line = format!(
                    "Failed  {from} -> {to}  [{:?}] {reason}{partial}",
                    error.code
                );
                let item = json!({"from":from, "to":to, "status":"failed", "error":error, "remote_writes_may_have_occurred":wrote});
                first_error.get_or_insert(error);
                (item, line)
            }
        };
        if !ctx.json {
            writeln!(
                std::io::stdout().lock(),
                "{}",
                line.replace(char::is_control, " ")
            )?;
        }
        results.push(item);
    }
    let mut output = Output::new(
        json!({"results": results, "copied": copied, "up_to_date": up_to_date, "failed": failed}),
        format!("Sync complete: {copied} copied, {up_to_date} up to date, {failed} failed"),
    );
    if let Some(error) = first_error {
        output.outcome = if copied + up_to_date > 0 || ctx.changed.load(Ordering::SeqCst) {
            Outcome::Partial(error)
        } else {
            Outcome::Failed(error)
        };
    }
    Ok(output)
}
