use super::*;
use indicatif::TermLike;
use std::sync::atomic::{AtomicU16, Ordering};

fn display(total: usize) -> (TerminalObserver, Box<dyn Operation>) {
    let observer = TerminalObserver::with_target(
        "docker.io/library/nginx:latest".into(),
        Phase::Copying,
        ProgressDrawTarget::hidden(),
        Box::new(|| (24, 100)),
    );
    let stage = observer.begin(Phase::Copying, total);
    (observer, stage)
}
fn snapshot(observer: &TerminalObserver, width: usize, height: usize) -> String {
    let state = observer.display.as_ref().unwrap().state.lock().unwrap();
    render::frame(
        &state,
        width,
        height,
        state.started + Duration::from_secs(3),
    )
}

#[test]
fn rows_keep_their_order_and_final_results_across_command_stages() {
    let (observer, stage) = display(3);
    for id in ["aaaaaaaaaaaa", "bbbbbbbbbbbb", "cccccccccccc"] {
        stage.register_blob(format!("sha256:{id}"), 1024);
    }
    let second = stage.blob("sha256:bbbbbbbbbbbb".into(), 1024);
    second.finish_with(BlobOutcome::AlreadyExists);
    let first = stage.blob("sha256:aaaaaaaaaaaa".into(), 1024);
    first.phase(BlobPhase::Downloading);
    first.position(512);
    let screen = snapshot(&observer, 100, 24);
    assert!(screen.contains("[+] Copying 1/3 blobs"));
    assert!(screen.contains("nginx:latest"));
    assert!(screen.contains("512 B/1.00 KiB"));
    let rows: Vec<_> = screen.lines().skip(2).collect();
    assert!(rows[0].contains("aaaaaaaaaaaa Downloading"));
    assert!(rows[1].contains("bbbbbbbbbbbb Already exists"));
    assert!(rows[2].contains("cccccccccccc Waiting"));
    first.finish_with(BlobOutcome::Copied);
    first.finish_with(BlobOutcome::Mounted); // An outcome is final and counted once.
    stage
        .blob("sha256:cccccccccccc".into(), 1024)
        .finish_with(BlobOutcome::Reused);
    drop(stage);
    let _publishing = observer.begin(Phase::Publishing, 0);
    let screen = snapshot(&observer, 100, 24);
    assert!(screen.contains("3/3 blobs"));
    assert!(screen.contains("Publishing manifests"));
    assert!(screen.contains("aaaaaaaaaaaa Copied"));
    observer.complete(&Ok(()));
    let final_screen = observer.display.as_ref().unwrap().bar.message();
    assert!(final_screen.lines().nth(1).unwrap().contains("✔"));
    assert!(final_screen.contains("bbbbbbbbbbbb Already exists"));
    assert!(final_screen.contains("cccccccccccc Copied (local)"));
    // Dropping the observer does not erase a finished frame.
    let bar = observer.display.as_ref().unwrap().bar.clone();
    drop(observer);
    assert_eq!(bar.message(), final_screen);
}

#[test]
fn aggregate_progress_is_weighted_and_continuous_through_upload_and_retry() {
    let (observer, stage) = display(2);
    stage.register_blob("sha256:large".into(), 300);
    stage.register_blob("sha256:small".into(), 100);
    let blob = stage.blob("sha256:large".into(), 300);
    blob.phase(BlobPhase::Downloading);
    blob.position(200);
    assert!(snapshot(&observer, 100, 24).contains("25%"));
    blob.position(300);
    assert!(snapshot(&observer, 100, 24).contains("37%"));
    blob.phase(BlobPhase::Uploading);
    assert!(snapshot(&observer, 100, 24).contains("37%"));
    blob.position(100);
    assert!(snapshot(&observer, 100, 24).contains("50%"));
    blob.phase(BlobPhase::Uploading);
    blob.position(20);
    assert!(snapshot(&observer, 100, 24).contains("50%"));
    assert!(snapshot(&observer, 100, 24).contains("20 B/300 B"));
    stage
        .blob("sha256:small".into(), 100)
        .finish_with(BlobOutcome::AlreadyExists);
    assert!(snapshot(&observer, 100, 24).contains("75%"));
    // Completing payload bytes does not falsely report that manifest publication has succeeded.
    blob.phase(BlobPhase::Committing);
    blob.finish_with(BlobOutcome::Copied);
    let _publishing = observer.begin(Phase::Publishing, 0);
    observer.complete::<()>(&Err(crate::Error::network("publication failed")));
    let screen = observer.display.as_ref().unwrap().bar.message();
    assert!(screen.lines().nth(1).unwrap().contains("Failed"));
    assert!(screen.contains("large Copied"));
}

#[test]
fn failure_identifies_the_blob_and_cancellation_never_marks_success() {
    let (observer, stage) = display(3);
    let good = stage.blob("sha256:good".into(), 100);
    good.finish_with(BlobOutcome::Mounted);
    let failed = stage.blob("sha256:failed".into(), 100);
    failed.phase(BlobPhase::Uploading);
    failed.fail();
    failed.finish();
    let _other = stage.blob("sha256:other".into(), 100);
    observer.complete::<()>(&Err(crate::Error::network("upload failed")));
    let screen = observer.display.as_ref().unwrap().bar.message();
    assert!(screen.contains("1/3 blobs"));
    assert!(screen.contains("good Mounted"));
    assert!(screen.contains("✘ failed Failed"));
    assert!(screen.contains("other Cancelled"));
    let (observer, stage) = display(1);
    let _blob = stage.blob("sha256:pending".into(), 100);
    let bar = observer.display.as_ref().unwrap().bar.clone();
    drop(observer);
    assert!(bar.message().contains("Interrupted"));
    assert!(!bar.message().contains("Copied"));
}

#[test]
fn folding_preserves_active_and_failed_rows_and_respects_terminal_dimensions() {
    let (observer, stage) = display(88);
    for index in 0..88 {
        stage.register_blob(format!("sha256:{index:012}"), 1024);
    }
    for index in 0..80 {
        stage
            .blob(format!("sha256:{index:012}"), 1024)
            .finish_with(BlobOutcome::AlreadyExists);
    }
    let active = stage.blob("sha256:000000000080".into(), 1024);
    active.phase(BlobPhase::Uploading);
    let failed = stage.blob("sha256:000000000081".into(), 1024);
    failed.fail();
    let frame = snapshot(&observer, 100, 10);
    assert!(frame.contains("000000000080 Uploading"));
    assert!(frame.contains("000000000081 Failed"));
    assert!(frame.contains("hidden (80 complete, 6 waiting in total)"));
    for height in [1, 3, 8, 24, 100] {
        for width in [1, 12, 25, 40, 80, 160] {
            let frame = snapshot(&observer, width, height);
            assert!(frame.lines().count() <= height.saturating_sub(2).max(1));
            assert!(
                frame
                    .lines()
                    .all(|line| console::measure_text_width(line) <= width),
                "{frame}"
            );
        }
    }
    let wide = snapshot(&observer, 100, 100);
    assert!(!wide.contains("hidden"));
    assert!(wide.contains("000000000000 Already exists"));
    assert!(wide.contains("000000000087 Waiting"));
}

#[test]
fn image_names_cannot_inject_terminal_controls_and_unicode_is_bounded() {
    let mut state = State::new("image\n\x1b[31m\r\t🦀界".into(), Phase::Copying);
    state.status = Status::Failed;
    for columns in [1, 20, 40, 60] {
        let screen = render::frame(&state, columns, 24, Instant::now());
        assert!(
            screen
                .lines()
                .all(|line| console::measure_text_width(line) <= columns)
        );
        assert!(!screen.contains(['\x1b', '\r', '\t']));
        assert_eq!(screen.lines().count(), 2);
    }
}

#[derive(Clone, Debug)]
struct Terminal {
    width: Arc<AtomicU16>,
    writes: Arc<Mutex<String>>,
}
impl indicatif::TermLike for Terminal {
    fn width(&self) -> u16 {
        self.width.load(Ordering::Relaxed)
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
fn terminal_diagnostics_resize_and_final_frame_survive_rendering() {
    let terminal = Terminal {
        width: Arc::new(AtomicU16::new(100)),
        writes: Arc::new(Mutex::new(String::new())),
    };
    let dimensions = terminal.width.clone();
    let observer = TerminalObserver::with_target(
        "docker.io/library/nginx:latest".into(),
        Phase::Copying,
        ProgressDrawTarget::term_like(Box::new(terminal.clone())),
        Box::new(move || (24, dimensions.load(Ordering::Relaxed))),
    );
    let stage = observer.begin(Phase::Copying, 1);
    let blob = stage.blob("sha256:123456789abc".into(), 1024);
    blob.phase(BlobPhase::Downloading);
    blob.position(512);
    let display = observer.display.as_ref().unwrap();
    display.draw();
    display.bar.force_draw();
    display
        .bar
        .suspend(|| terminal.write_str("Diagnostic preserved\n").unwrap());
    terminal.width.store(40, Ordering::Relaxed);
    display.draw();
    display.bar.force_draw();
    blob.finish_with(BlobOutcome::Copied);
    observer.complete(&Ok(()));
    let output = terminal.writes.lock().unwrap().clone();
    for expected in [
        "[+] Copying",
        "nginx:latest",
        "Downloading",
        "Diagnostic preserved",
        "Copied",
    ] {
        assert!(output.contains(expected), "missing {expected}: {output}");
    }
    assert!(output.trim_end().ends_with('s'));
}
