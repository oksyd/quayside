//! Optional operation observation. Implementations own presentation and cleanup.
//! Operation guards delimit stages; observers may retain rows until the command ends.
/// Operation-level stages reported independently of terminal presentation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    /// Resolving the source manifest and dependency graph.
    Resolving,
    /// Checking destination content and overwrite policy.
    CheckingDestination,
    /// Processing the remote blob dependency set.
    Copying,
    /// Downloading payloads to a local layout or archive.
    Pulling,
    /// Uploading payloads from a local layout or archive.
    Pushing,
    /// Opening and selecting a local image layout or archive.
    ReadingLocal,
    /// Verifying the selected local dependency graph before remote writes.
    VerifyingLocal,
    /// Exporting an explicitly requested image from the Docker daemon.
    ExportingDocker,
    /// Writing the final local layout or archive.
    Saving,
    /// Inspecting the blob dependency set without performing writes.
    Planning,
    /// Publishing and verifying dependency and root manifests.
    Publishing,
}
/// Stages within one blob transfer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlobPhase {
    /// Receiving payload bytes from the source registry.
    Downloading,
    /// Verifying the complete digest after a parallel download.
    Verifying,
    /// Sending payload chunks and tracking registry-acknowledged offsets.
    Uploading,
    /// Committing an upload session to its final content digest.
    Committing,
    /// Waiting for a reservation in the shared temporary-storage budget.
    Waiting,
}

/// Successful outcome of processing a blob, independent of terminal presentation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlobOutcome {
    /// Uploaded and verified at the destination.
    Copied,
    /// Downloaded and verified in local staging storage.
    Downloaded,
    /// Uploaded from local storage and verified at the destination.
    Uploaded,
    /// Uploaded using verified payload bytes from the local Docker cache.
    Reused,
    /// Verified as already present at the destination.
    AlreadyExists,
    /// Mounted from another repository and verified at the destination.
    Mounted,
    /// Would be transferred during a real run; no content was written.
    Planned,
}

/// Receives operation stages without imposing a terminal or logging backend.
pub trait Observer: Send + Sync {
    /// Begin observing an operation stage; total is the known blob count, or zero for metadata work.
    fn begin(&self, phase: Phase, total: usize) -> Box<dyn Operation>;
}
/// Owns one stage. Implementations should release display/resources when dropped.
pub trait Operation: Send + Sync {
    /// Declare queued blobs before starting workers, so totals and display order remain stable.
    fn register_blob(&self, _digest: String, _size: u64) {}
    /// Begin observing a blob identified by its digest and declared payload size.
    fn blob(&self, digest: String, size: u64) -> Box<dyn BlobProgress>;
}
/// Per-blob callbacks may run concurrently for different blobs.
pub trait BlobProgress: Send + Sync {
    /// Mark this blob as failed; cancellation of sibling workers must not imply their failure.
    fn fail(&self) {}
    /// Report a transfer-phase change, including restarts after a retry.
    fn phase(&self, phase: BlobPhase);
    /// Absolute offset in the current phase; may decrease after retry/reconciliation.
    fn position(&self, position: u64);
    /// Marks successful processing, including a verified existing or mounted blob.
    fn finish(&self);
    /// Report a successful outcome. Observers without outcome support still receive `finish`.
    fn finish_with(&self, _outcome: BlobOutcome) {
        self.finish();
    }
}
/// No-op observer for callers that do not need progress reporting.
#[derive(Default)]
pub struct NoProgress;
impl Observer for NoProgress {
    fn begin(&self, _: Phase, _: usize) -> Box<dyn Operation> {
        Box::new(Self)
    }
}
impl Operation for NoProgress {
    fn blob(&self, _: String, _: u64) -> Box<dyn BlobProgress> {
        Box::new(Self)
    }
}
impl BlobProgress for NoProgress {
    fn phase(&self, _: BlobPhase) {}
    fn position(&self, _: u64) {}
    fn finish(&self) {}
}
