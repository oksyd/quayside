//! One terminal display spans resolution, payload transfer and final publication.
use crate::{
    Result,
    error::Code,
    observer::{BlobOutcome, BlobPhase, Observer, Operation, Phase},
};
use indicatif::{ProgressBar, ProgressDrawTarget, ProgressStyle};
use std::{
    collections::BTreeMap,
    io::IsTerminal,
    sync::{Arc, Mutex, Weak},
    time::{Duration, Instant},
};

mod render;
#[cfg(test)]
mod tests;

static ACTIVE: Mutex<Weak<Display>> = Mutex::new(Weak::new());

pub(crate) fn suspend(write: impl FnOnce()) {
    let display = ACTIVE.lock().ok().and_then(|active| active.upgrade());
    if let Some(display) = display {
        display.bar.suspend(write);
    } else {
        write();
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Status {
    Running,
    Complete,
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
    action: Phase,
    phase: Phase,
    total: Option<usize>,
    rows: Vec<Row>,
    indices: BTreeMap<String, usize>,
    started: Instant,
    stopped: Option<Instant>,
    status: Status,
    planning: bool,
}
impl State {
    fn new(image: String, action: Phase) -> Self {
        Self {
            image: image
                .chars()
                .map(|c| if c.is_control() { '?' } else { c })
                .collect(),
            action,
            phase: Phase::Resolving,
            total: None,
            rows: vec![],
            indices: BTreeMap::new(),
            started: Instant::now(),
            stopped: None,
            status: Status::Running,
            planning: false,
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
    bar: ProgressBar,
    state: Mutex<State>,
    dimensions: Box<dyn Fn() -> (u16, u16) + Send + Sync>,
}
impl Display {
    fn draw(&self) {
        let state = self.state.lock().expect("progress state lock");
        if state.status != Status::Running {
            return;
        }
        let (height, width) = (self.dimensions)();
        self.bar.set_message(render::frame(
            &state,
            width as usize,
            height as usize,
            Instant::now(),
        ));
    }
    fn finish(&self, status: Status) {
        let mut state = self.state.lock().expect("progress state lock");
        if state.status != Status::Running {
            return;
        }
        state.status = status;
        state.stopped = Some(Instant::now());
        let (height, width) = (self.dimensions)();
        let frame = render::frame(&state, width as usize, height as usize, Instant::now());
        // Finish once with the final frame; stage guards never clear the screen.
        self.bar.finish_with_message(frame);
    }
}

/// CLI adapter retaining one image and its blob rows for the entire command.
pub(crate) struct TerminalObserver {
    display: Option<Arc<Display>>,
    task: Option<tokio::task::JoinHandle<()>>,
}
impl TerminalObserver {
    pub(crate) fn new(enabled: bool, image: String, action: Phase) -> Self {
        if !enabled
            || !std::io::stderr().is_terminal()
            || std::env::var("TERM").is_ok_and(|term| term == "dumb")
        {
            return Self {
                display: None,
                task: None,
            };
        }
        let terminal = console::Term::stderr();
        let mut observer = Self::with_target(
            image,
            action,
            ProgressDrawTarget::stderr_with_hz(10),
            Box::new(move || terminal.size()),
        );
        let display = observer.display.as_ref().expect("initialized display");
        *ACTIVE.lock().expect("active progress lock") = Arc::downgrade(display);
        let weak = Arc::downgrade(display);
        observer.task = Some(tokio::spawn(async move {
            let mut timer = tokio::time::interval(Duration::from_millis(100));
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
    ) -> Self {
        let bar = ProgressBar::with_draw_target(None, target);
        bar.set_style(
            ProgressStyle::with_template("{msg}").expect("valid static progress template"),
        );
        Self {
            display: Some(Arc::new(Display {
                bar,
                state: Mutex::new(State::new(image, action)),
                dimensions,
            })),
            task: None,
        }
    }
    pub(crate) fn complete<T>(&self, result: &Result<T>) {
        if let Some(display) = &self.display {
            display.finish(match result {
                Ok(_) => Status::Complete,
                Err(error) if error.code == Code::Interrupted => Status::Interrupted,
                Err(_) => Status::Failed,
            });
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
