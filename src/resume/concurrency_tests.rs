use super::*;
use std::{sync::mpsc, thread, time::Duration};

#[tokio::test(flavor = "current_thread")]
async fn checkpoint_io_does_not_block_sibling_work_or_state_reads() {
    let directory = tempfile::tempdir().unwrap();
    let config = TransferConfig {
        resume_dir: Some(directory.path().to_owned()),
        ..Default::default()
    };
    let store = Store::open("checkpoint-concurrency", &config)
        .await
        .unwrap();
    let descriptor = Descriptor::new("application/octet-stream", Digest::sha256(b"abcdefgh"), 8);
    let blob = store.blob(&descriptor).await.unwrap();
    blob.ranges(std::slice::from_ref(&(0..8))).await.unwrap();
    fs::write(&blob.path, b"abcd").unwrap();

    let (entered, waiting) = tokio::sync::oneshot::channel();
    let (release, blocked) = mpsc::channel();
    let held = blob.clone();
    let writer = thread::spawn(move || {
        let _guard = held.io_lock.lock().unwrap();
        entered.send(()).unwrap();
        // This is only a deadlock watchdog. Progress is coordinated by channels, not elapsed time.
        blocked.recv_timeout(Duration::from_secs(30))
    });
    waiting.await.unwrap();

    // join! polls the checkpoint first on this one runtime thread. Its blocking I/O job must
    // yield so a sibling can read state and release the writer, just as other transfers must run.
    let (checkpoint, released) = tokio::join! {
        biased;
        blob.checkpoint(0, 4),
        async {
            let offset = blob.offset(0);
            let released = release.send(());
            (offset, released)
        },
    };
    assert!(
        writer.join().unwrap().is_ok(),
        "checkpoint I/O blocked the runtime before sibling work could release it"
    );
    released.1.unwrap();
    assert_eq!(released.0, 0);
    checkpoint.unwrap();
    assert_eq!(blob.offset(0), 4);
    let saved: State = serde_json::from_slice(&fs::read(&blob.state_path).unwrap()).unwrap();
    assert_eq!(saved.parts[0].offset, 4);
}

#[tokio::test]
async fn concurrent_range_checkpoints_preserve_every_acknowledged_offset() {
    let directory = tempfile::tempdir().unwrap();
    let config = TransferConfig {
        resume_dir: Some(directory.path().to_owned()),
        ..Default::default()
    };
    let store = Store::open("parallel-checkpoints", &config).await.unwrap();
    let descriptor = Descriptor::new("application/octet-stream", Digest::sha256(b"abcdefgh"), 8);
    let blob = store.blob(&descriptor).await.unwrap();
    blob.ranges(&[0..4, 4..8]).await.unwrap();
    fs::write(&blob.path, b"abcdefgh").unwrap();

    for (first, second) in [(2, 6), (4, 8)] {
        let (left, right) = tokio::join!(blob.checkpoint(0, first), blob.checkpoint(4, second));
        left.unwrap();
        right.unwrap();
        let saved: State = serde_json::from_slice(&fs::read(&blob.state_path).unwrap()).unwrap();
        assert_eq!(saved.parts[0].offset, first);
        assert_eq!(saved.parts[1].offset, second);
    }
}

#[tokio::test]
async fn cancelled_checkpoint_keeps_the_transfer_lock_until_disk_work_finishes() {
    let directory = tempfile::tempdir().unwrap();
    let config = TransferConfig {
        resume_dir: Some(directory.path().to_owned()),
        ..Default::default()
    };
    let store = Store::open("cancelled-checkpoint", &config).await.unwrap();
    let lock_path = store.root.join("lock");
    let descriptor = Descriptor::new("application/octet-stream", Digest::sha256(b"blob"), 4);
    let blob = store.blob(&descriptor).await.unwrap();
    let (entered, waiting) = tokio::sync::oneshot::channel();
    let (release, blocked) = mpsc::channel();
    let task = tokio::spawn(async move {
        blob.write(move |_| {
            entered.send(()).unwrap();
            blocked
                .recv_timeout(Duration::from_secs(30))
                .map_err(|_| Error::input("checkpoint test gate was not released"))?;
            Ok(())
        })
        .await
    });
    waiting.await.unwrap();
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    drop(store);
    assert!(
        Store::open("cancelled-checkpoint", &config)
            .await
            .is_err_and(|error| error.code == crate::error::Code::Conflict),
        "cancelling the caller must not unlock an unfinished checkpoint"
    );

    release.send(()).unwrap();
    // Wait on the actual OS lock, without guessing when the detached disk job has returned.
    let released_lock = tokio::task::spawn_blocking(move || {
        let file = File::open(lock_path).unwrap();
        FileExt::lock_exclusive(&file).unwrap();
        file
    })
    .await
    .unwrap();
    drop(released_lock);
    Store::open("cancelled-checkpoint", &config).await.unwrap();
}
