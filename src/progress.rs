//! Terminal-only progress; upload positions are registry-acknowledged offsets.
use indicatif::{MultiProgress, ProgressBar, ProgressDrawTarget, ProgressStyle};
use std::{
    collections::BTreeMap,
    io::IsTerminal,
    sync::{Arc, Mutex, Weak},
    time::Duration,
};

static ACTIVE: Mutex<Weak<Display>> = Mutex::new(Weak::new());

pub(crate) fn suspend(write: impl FnOnce()) {
    let display = ACTIVE.lock().ok().and_then(|active| active.upgrade());
    if let Some(display) = display {
        display.multi.suspend(write);
    } else {
        write();
    }
}

fn style(template: &str) -> ProgressStyle {
    ProgressStyle::with_template(template)
        .expect("valid static progress template")
        .progress_chars("=> ")
        .tick_strings(&["|", "/", "-", "\\", " "])
}
fn activity_style() -> ProgressStyle {
    style("{prefix} {wide_msg}")
}
fn transfer_style() -> ProgressStyle {
    style("{prefix} {msg:11} [{wide_bar}] {bytes}/{total_bytes}")
}

#[derive(Default)]
struct Counts {
    active: BTreeMap<String, ProgressBar>,
    completed: u64,
    stopped: bool,
}
struct Display {
    multi: MultiProgress,
    summary: ProgressBar,
    counts: Mutex<Counts>,
}
pub(crate) struct Progress {
    display: Option<Arc<Display>>,
    task: Option<tokio::task::JoinHandle<()>>,
}
#[derive(Clone, Default)]
pub(crate) struct Blob {
    display: Option<Arc<Display>>,
    bar: Option<ProgressBar>,
    key: String,
    size: u64,
}
impl Progress {
    pub(crate) fn new(enabled: bool, phase: &'static str, total: usize) -> Self {
        if !enabled
            || !std::io::stderr().is_terminal()
            || std::env::var("TERM").is_ok_and(|term| term == "dumb")
        {
            return Self {
                display: None,
                task: None,
            };
        }
        let mut progress = Self::with_target(phase, total, ProgressDrawTarget::stderr_with_hz(10));
        let display = progress.display.as_ref().expect("initialized display");
        if let Ok(mut active) = ACTIVE.lock() {
            *active = Arc::downgrade(display);
        }
        let weak = Arc::downgrade(display);
        // One ticker for all workers, rather than one thread for every progress bar.
        progress.task = Some(tokio::spawn(async move {
            let mut timer = tokio::time::interval(Duration::from_millis(100));
            loop {
                timer.tick().await;
                let Some(display) = weak.upgrade() else {
                    break;
                };
                if let Ok(counts) = display.counts.lock() {
                    if counts.stopped {
                        break;
                    }
                    display.summary.tick();
                    for bar in counts.active.values() {
                        bar.tick();
                    }
                }
            }
        }));
        progress
    }
    fn with_target(phase: &'static str, total: usize, target: ProgressDrawTarget) -> Self {
        let multi = MultiProgress::with_draw_target(target);
        let summary = multi.add(ProgressBar::new(total as u64));
        if total == 0 {
            summary.set_style(style("{spinner} {wide_msg}"));
            summary.set_message(phase);
        } else {
            summary.set_style(style("{prefix} {pos}/{len} blobs"));
            summary.set_prefix(phase);
        }
        Self {
            display: Some(Arc::new(Display {
                multi,
                summary,
                counts: Mutex::new(Counts::default()),
            })),
            task: None,
        }
    }
    pub(crate) fn blob(&self, key: String, size: u64) -> Blob {
        let Some(display) = &self.display else {
            return Blob::default();
        };
        let bar = display.multi.add(ProgressBar::new(size));
        bar.set_style(activity_style());
        bar.set_prefix(
            key.split(':')
                .next_back()
                .unwrap_or(&key)
                .chars()
                .take(12)
                .collect::<String>(),
        );
        bar.set_message("Checking");
        if let Ok(mut counts) = display.counts.lock() {
            counts.active.insert(key.clone(), bar.clone());
        }
        Blob {
            display: Some(display.clone()),
            bar: Some(bar),
            key,
            size,
        }
    }
}
impl Drop for Progress {
    fn drop(&mut self) {
        if let Some(task) = &self.task {
            task.abort();
        }
        if let Some(display) = &self.display
            && let Ok(mut counts) = display.counts.lock()
        {
            counts.stopped = true;
            for bar in counts.active.values() {
                bar.finish_and_clear();
            }
            counts.active.clear();
            display.summary.finish_and_clear();
            let _ = display.multi.clear();
        }
    }
}
impl Blob {
    pub(crate) fn phase(&self, phase: &'static str) {
        if let Some(bar) = &self.bar
            && !bar.is_finished()
        {
            if matches!(phase, "Downloading" | "Uploading") {
                // Reset the offset on direction changes and retries.
                bar.reset();
                bar.set_style(transfer_style());
            } else {
                bar.set_style(activity_style());
            }
            bar.set_message(phase);
        }
    }
    pub(crate) fn position(&self, position: u64) {
        if let Some(bar) = &self.bar
            && !bar.is_finished()
        {
            bar.set_position(position.min(self.size));
        }
    }
    pub(crate) fn finish(&self) {
        if let Some(display) = &self.display
            && let Ok(mut counts) = display.counts.lock()
            && let Some(bar) = counts.active.remove(&self.key)
        {
            counts.completed += 1;
            bar.finish_and_clear();
            display.multi.remove(&bar);
            display.summary.set_position(counts.completed);
        }
    }
}

/// CLI adapter; core transfer code only depends on observer traits.
pub(crate) struct TerminalObserver(pub bool);
impl crate::observer::Observer for TerminalObserver {
    fn begin(
        &self,
        phase: crate::observer::Phase,
        total: usize,
    ) -> Box<dyn crate::observer::Operation> {
        use crate::observer::Phase;
        let label = match phase {
            Phase::Resolving => "Resolving manifests",
            Phase::CheckingDestination => "Checking destination",
            Phase::Copying => "Copying",
            Phase::Planning => "Planning",
            Phase::Publishing => "Publishing manifests",
        };
        Box::new(Progress::new(self.0, label, total))
    }
}
impl crate::observer::Operation for Progress {
    fn blob(&self, digest: String, size: u64) -> Box<dyn crate::observer::BlobProgress> {
        Box::new(self.blob(digest, size))
    }
}
impl crate::observer::BlobProgress for Blob {
    fn phase(&self, phase: crate::observer::BlobPhase) {
        use crate::observer::BlobPhase;
        self.phase(match phase {
            BlobPhase::Downloading => "Downloading",
            BlobPhase::Verifying => "Verifying",
            BlobPhase::Uploading => "Uploading",
            BlobPhase::Committing => "Committing",
            BlobPhase::Waiting => "Waiting",
        });
    }
    fn position(&self, position: u64) {
        self.position(position);
    }
    fn finish(&self) {
        self.finish();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn retries_reset_positions_and_completion_is_idempotent() {
        let progress = Progress::with_target("Checking", 2, ProgressDrawTarget::hidden());
        let blob = progress.blob("sha256:0123456789abcdef".into(), 100);
        let bar = blob.bar.as_ref().unwrap();
        blob.phase("Downloading");
        blob.position(70);
        blob.phase("Downloading");
        assert_eq!(bar.position(), 0);
        blob.position(30);
        assert_eq!(bar.position(), 30);
        blob.position(100);
        blob.phase("Uploading");
        assert_eq!(bar.position(), 0);
        blob.position(200);
        assert_eq!(bar.position(), 100);
        blob.phase("Committing");
        assert_eq!(bar.position(), 100);
        blob.finish();
        blob.finish();
        assert!(bar.is_finished());
        let pending = progress.blob("sha256:pending".into(), 100);
        let display = progress.display.as_ref().unwrap().clone();
        assert_eq!(display.counts.lock().unwrap().completed, 1);
        drop(progress);
        assert!(pending.bar.as_ref().unwrap().is_finished());
        assert!(display.counts.lock().unwrap().stopped);
        assert!(display.counts.lock().unwrap().active.is_empty());
    }
    #[derive(Clone, Debug)]
    struct Terminal {
        width: Arc<std::sync::atomic::AtomicU16>,
        writes: Arc<Mutex<String>>,
    }
    impl indicatif::TermLike for Terminal {
        fn width(&self) -> u16 {
            self.width.load(std::sync::atomic::Ordering::Relaxed)
        }
        fn height(&self) -> u16 {
            24
        }
        fn move_cursor_up(&self, _: usize) -> std::io::Result<()> {
            Ok(())
        }
        fn move_cursor_down(&self, _: usize) -> std::io::Result<()> {
            Ok(())
        }
        fn move_cursor_right(&self, _: usize) -> std::io::Result<()> {
            Ok(())
        }
        fn move_cursor_left(&self, _: usize) -> std::io::Result<()> {
            Ok(())
        }
        fn write_line(&self, text: &str) -> std::io::Result<()> {
            self.write_str(&format!("{text}\n"))
        }
        fn write_str(&self, text: &str) -> std::io::Result<()> {
            self.writes.lock().unwrap().push_str(text);
            Ok(())
        }
        fn clear_line(&self) -> std::io::Result<()> {
            Ok(())
        }
        fn flush(&self) -> std::io::Result<()> {
            Ok(())
        }
    }
    #[test]
    fn terminal_resize_and_completed_rows_do_not_accumulate() {
        let terminal = Terminal {
            width: Arc::new(std::sync::atomic::AtomicU16::new(120)),
            writes: Arc::new(Mutex::new(String::new())),
        };
        let progress = Progress::with_target(
            "Checking",
            88,
            ProgressDrawTarget::term_like(Box::new(terminal.clone())),
        );
        let first = progress.blob("sha256:first".into(), 1024);
        first.phase("Downloading");
        first.position(512);
        first.bar.as_ref().unwrap().force_draw();
        terminal
            .width
            .store(40, std::sync::atomic::Ordering::Relaxed);
        first.phase("Uploading");
        first.position(256);
        first.bar.as_ref().unwrap().force_draw();
        terminal
            .width
            .store(100, std::sync::atomic::Ordering::Relaxed);
        let display = progress.display.as_ref().unwrap();
        display.multi.suspend(|| {
            terminal
                .writes
                .lock()
                .unwrap()
                .push_str("Diagnostic preserved\n");
        });
        first.finish();
        for index in 1..88 {
            progress.blob(format!("sha256:{index:012}"), 0).finish();
        }
        assert_eq!(display.summary.position(), 88);
        assert!(display.counts.lock().unwrap().active.is_empty());
        {
            let text = terminal.writes.lock().unwrap();
            for expected in ["Downloading", "Uploading", "Diagnostic preserved"] {
                assert!(text.contains(expected), "missing {expected}: {text}");
            }
            assert!(!text.contains("Already exists"));
            assert!(!text.contains("Copied"));
        }
        terminal.writes.lock().unwrap().clear();
        display.summary.force_draw();
        assert!(!terminal.writes.lock().unwrap().contains("000000000087"));
        drop(progress);
    }
    #[test]
    fn disabled_progress_does_not_require_an_async_runtime() {
        let progress = Progress::new(false, "Resolving", 1);
        let blob = progress.blob("sha256:abc".into(), 0);
        blob.phase("Uploading");
        blob.position(1);
        blob.finish();
        assert!(progress.display.is_none());
    }
}
