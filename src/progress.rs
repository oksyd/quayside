//! One terminal display spans resolution, payload transfer and final publication.
use crate::{
    Result,
    error::Code,
    observer::{BlobOutcome, BlobPhase, Observer, Operation, Phase},
};
use indicatif::{MultiProgress, ProgressBar, ProgressDrawTarget, ProgressStyle};
use std::{
    collections::BTreeMap,
    fmt,
    io::{IsTerminal, Write},
    sync::{Arc, Mutex, Weak},
    time::{Duration, Instant},
};

mod render;
#[cfg(test)]
mod tests;

static ACTIVE: Mutex<Weak<Display>> = Mutex::new(Weak::new());

pub(crate) fn println(message: fmt::Arguments<'_>) {
    let display = ACTIVE.lock().ok().and_then(|active| active.upgrade());
    if let Some(display) = display {
        let state = display.state.lock().expect("progress state lock");
        if state.status == Status::Running && !display.region.is_hidden() {
            let _ = display.region.println(message.to_string());
            return;
        }
    }
    let _ = writeln!(std::io::stderr().lock(), "{message}");
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Status {
    Running,
    Complete,
    UpToDate,
    Failed,
    Interrupted,
}

struct Row {
    digest: String,
    size: u64,
    started: Option<Instant>,
    stopped: Option<Instant>,
    phase: Option<BlobPhase>,
    position: u64,
    downloaded: u64,
    uploaded: u64,
    outcome: Option<BlobOutcome>,
    failed: bool,
}
impl Row {
    fn settled(&self) -> bool {
        self.outcome.is_some() || self.failed
    }
    fn progress(&self, action: Phase) -> (u128, u128) {
        let total = u128::from(self.size.max(1)) * if action == Phase::Copying { 2 } else { 1 };
        let current = if self.outcome.is_some() {
            total
        } else {
            match action {
                Phase::Copying => u128::from(self.downloaded) + u128::from(self.uploaded),
                Phase::Pushing => u128::from(self.uploaded),
                _ => u128::from(self.downloaded),
            }
        };
        (current.min(total), total)
    }
}

struct State {
    image: String,
    platforms: Option<String>,
    action: Phase,
    phase: Phase,
    total: Option<usize>,
    rows: Vec<Row>,
    indices: BTreeMap<String, usize>,
    started: Instant,
    stopped: Option<Instant>,
    status: Status,
    planning: bool,
    terminal_size: Option<(u16, u16)>,
}
impl State {
    fn new(image: String, action: Phase) -> Self {
        Self {
            image: image
                .chars()
                .map(|c| if c.is_control() { '?' } else { c })
                .collect(),
            platforms: None,
            action,
            phase: Phase::Resolving,
            total: None,
            rows: vec![],
            indices: BTreeMap::new(),
            started: Instant::now(),
            stopped: None,
            status: Status::Running,
            planning: false,
            terminal_size: None,
        }
    }
    fn register(&mut self, digest: String, size: u64) -> usize {
        if let Some(index) = self.indices.get(&digest) {
            return *index;
        }
        let index = self.rows.len();
        self.indices.insert(digest.clone(), index);
        self.rows.push(Row {
            digest,
            size,
            started: None,
            stopped: None,
            phase: None,
            position: 0,
            downloaded: 0,
            uploaded: 0,
            outcome: None,
            failed: false,
        });
        index
    }
}

struct Display {
    region: MultiProgress,
    bar: ProgressBar,
    state: Mutex<State>,
    dimensions: Box<dyn Fn() -> (u16, u16) + Send + Sync>,
    color: bool,
}
impl Display {
    fn frame(&self, state: &mut State) -> String {
        let size @ (height, width) = (self.dimensions)();
        // Rows only grow during a transfer, but resizing can shrink the displayed frame.
        if state
            .terminal_size
            .replace(size)
            .is_some_and(|old| old != size)
        {
            let _ = self.region.clear();
        }
        render::frame(
            state,
            width.into(),
            height.into(),
            Instant::now(),
            self.color,
        )
    }
    fn draw(&self) {
        let mut state = self.state.lock().expect("progress state lock");
        if state.status == Status::Running {
            self.bar.set_message(self.frame(&mut state));
        }
    }
    fn finish(&self, status: Status) {
        let mut state = self.state.lock().expect("progress state lock");
        if state.status != Status::Running {
            return;
        }
        state.status = status;
        state.stopped = Some(Instant::now());
        // Finish once with the final frame; stage guards never clear the screen.
        self.bar.finish_with_message(self.frame(&mut state));
    }
}

/// CLI adapter retaining one image and its blob rows for the entire command.
pub(crate) struct TerminalObserver {
    display: Option<Arc<Display>>,
    task: Option<tokio::task::JoinHandle<()>>,
    platform_notice: bool,
}
impl TerminalObserver {
    pub(crate) fn set_image(&self, image: String) {
        if let Some(display) = &self.display {
            display.state.lock().expect("progress state lock").image = image
                .chars()
                .map(|c| if c.is_control() { '?' } else { c })
                .collect();
            display.draw();
        }
    }

    pub(crate) fn new(enabled: bool, image: String, action: Phase) -> Self {
        if !enabled
            || !std::io::stderr().is_terminal()
            || std::env::var("TERM").is_ok_and(|term| term == "dumb")
        {
            return Self {
                display: None,
                task: None,
                platform_notice: false,
            };
        }
        let terminal = console::Term::stderr();
        let mut observer = Self::with_target(
            image,
            action,
            ProgressDrawTarget::stderr_with_hz(10),
            Box::new(move || terminal.size()),
            console::colors_enabled_stderr(),
        );
        let display = observer.display.as_ref().expect("initialized display");
        display.draw();
        *ACTIVE.lock().expect("active progress lock") = Arc::downgrade(display);
        let weak = Arc::downgrade(display);
        observer.task = Some(tokio::spawn(async move {
            let period = Duration::from_millis(100);
            let mut timer = tokio::time::interval_at(tokio::time::Instant::now() + period, period);
            timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                timer.tick().await;
                let Some(display) = weak.upgrade() else {
                    break;
                };
                display.draw();
            }
        }));
        observer
    }
    fn with_target(
        image: String,
        action: Phase,
        target: ProgressDrawTarget,
        dimensions: Box<dyn Fn() -> (u16, u16) + Send + Sync>,
        color: bool,
    ) -> Self {
        let region = MultiProgress::with_draw_target(target);
        region.set_move_cursor(true);
        let bar = region.add(ProgressBar::hidden());
        bar.set_style(
            ProgressStyle::with_template("{msg}").expect("valid static progress template"),
        );
        Self {
            display: Some(Arc::new(Display {
                region,
                bar,
                state: Mutex::new(State::new(image, action)),
                dimensions,
                color,
            })),
            task: None,
            platform_notice: false,
        }
    }
    pub(crate) fn with_platform_notice(mut self, enabled: bool) -> Self {
        self.platform_notice = enabled;
        self
    }
    pub(crate) fn complete<T>(&self, result: &Result<T>) {
        self.finish(match result {
            Ok(_) => Status::Complete,
            Err(error) if error.code == Code::Interrupted => Status::Interrupted,
            Err(_) => Status::Failed,
        });
    }
    pub(crate) fn finish(&self, status: Status) {
        if let Some(display) = &self.display {
            display.finish(status);
            self.detach();
        }
    }
    fn detach(&self) {
        if let Ok(mut active) = ACTIVE.lock()
            && let (Some(display), Some(current)) = (&self.display, active.upgrade())
            && Arc::ptr_eq(display, &current)
        {
            *active = Weak::new();
        }
    }
}
impl Drop for TerminalObserver {
    fn drop(&mut self) {
        if let Some(task) = &self.task {
            task.abort();
        }
        // Dropping the command future (Ctrl-C) must preserve an interrupted, never successful, result.
        if let Some(display) = &self.display {
            display.finish(Status::Interrupted);
        }
        self.detach();
    }
}
impl Observer for TerminalObserver {
    fn selected_platforms(&self, platforms: &[String]) {
        if platforms.is_empty() {
            return;
        }
        let label = if platforms.len() == 1 {
            "Platform"
        } else {
            "Platforms"
        };
        let text: String = format!("{label}: {}", platforms.join(", "))
            .chars()
            .map(|c| if c.is_control() { '?' } else { c })
            .collect();
        if let Some(display) = &self.display {
            display.state.lock().expect("progress state lock").platforms = Some(text);
        } else if self.platform_notice {
            println(format_args!("{text}"));
        }
    }
    fn begin(&self, phase: Phase, total: usize) -> Box<dyn Operation> {
        if let Some(display) = &self.display {
            let mut state = display.state.lock().expect("progress state lock");
            if state.status == Status::Running {
                state.phase = phase;
                if matches!(
                    phase,
                    Phase::Copying | Phase::Pulling | Phase::Pushing | Phase::Planning
                ) {
                    state.total = Some(total);
                    state.planning = phase == Phase::Planning;
                }
            }
        }
        Box::new(Stage(self.display.clone()))
    }
}
struct Stage(Option<Arc<Display>>);
impl Operation for Stage {
    fn register_blob(&self, digest: String, size: u64) {
        if let Some(display) = &self.0 {
            display
                .state
                .lock()
                .expect("progress state lock")
                .register(digest, size);
        }
    }
    fn blob(&self, digest: String, size: u64) -> Box<dyn crate::observer::BlobProgress> {
        let index = self.0.as_ref().map(|display| {
            let mut state = display.state.lock().expect("progress state lock");
            let index = state.register(digest, size);
            state.rows[index].started.get_or_insert_with(Instant::now);
            index
        });
        Box::new(Blob {
            display: self.0.clone(),
            index,
        })
    }
}
struct Blob {
    display: Option<Arc<Display>>,
    index: Option<usize>,
}
impl Blob {
    fn update(&self, change: impl FnOnce(&mut Row)) {
        if let (Some(display), Some(index)) = (&self.display, self.index) {
            let mut state = display.state.lock().expect("progress state lock");
            if state.status == Status::Running && !state.rows[index].settled() {
                change(&mut state.rows[index]);
            }
        }
    }
}
impl crate::observer::BlobProgress for Blob {
    fn phase(&self, phase: BlobPhase) {
        self.update(|row| {
            if matches!(phase, BlobPhase::Downloading | BlobPhase::Uploading) {
                row.position = 0;
            }
            if phase == BlobPhase::Uploading {
                row.downloaded = row.size;
            }
            row.phase = Some(phase);
        });
    }
    fn position(&self, position: u64) {
        self.update(|row| {
            row.position = position.min(row.size);
            // High-water marks keep aggregate work progress continuous across stage changes and retries.
            match row.phase {
                Some(BlobPhase::Downloading) => row.downloaded = row.downloaded.max(row.position),
                Some(BlobPhase::Uploading) => row.uploaded = row.uploaded.max(row.position),
                _ => {}
            }
        });
    }
    fn finish(&self) {
        self.finish_with(BlobOutcome::Copied);
    }
    fn finish_with(&self, outcome: BlobOutcome) {
        self.update(|row| {
            row.outcome = Some(outcome);
            row.stopped = Some(Instant::now());
        });
    }
    fn fail(&self) {
        self.update(|row| {
            row.failed = true;
            row.stopped = Some(Instant::now());
        });
    }
}
