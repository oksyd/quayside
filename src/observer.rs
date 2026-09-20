//! Optional operation observation. Implementations own presentation and cleanup.
//! Dropping an operation ends observation, including on errors and cancellation.
/// Operation-level stages reported independently of terminal presentation.
#[derive(Debug, Clone, Copy)]
pub enum Phase {
    /// Resolving the source manifest and dependency graph.
    Resolving,
    /// Checking destination content and overwrite policy.
    CheckingDestination,
    /// Processing the remote blob dependency set.
    Copying,
    /// Inspecting the blob dependency set without performing writes.
    Planning,
    /// Publishing and verifying dependency and root manifests.
    Publishing,
}
/// Stages within one blob transfer.
#[derive(Debug, Clone, Copy)]
pub enum BlobPhase {
    /// Receiving payload bytes from the source registry.
    Downloading,
    /// Sending payload chunks and tracking registry-acknowledged offsets.
    Uploading,
    /// Committing an upload session to its final content digest.
    Committing,
    /// Waiting for a reservation in the shared temporary-storage budget.
    Waiting,
}

/// Receives operation stages without imposing a terminal or logging backend.
pub trait Observer: Send + Sync {
    /// Begin observing an operation stage; total is the known blob count, or zero for metadata work.
    fn begin(&self, phase: Phase, total: usize) -> Box<dyn Operation>;
}
/// Owns one stage. Implementations should release display/resources when dropped.
pub trait Operation: Send + Sync {
    /// Begin observing a blob identified by its digest and declared payload size.
    fn blob(&self, digest: String, size: u64) -> Box<dyn BlobProgress>;
}
/// Per-blob callbacks may run concurrently for different blobs.
pub trait BlobProgress: Send + Sync {
    /// Report a transfer-phase change, including restarts after a retry.
    fn phase(&self, phase: BlobPhase);
    /// Absolute offset in the current phase; may decrease after retry/reconciliation.
    fn position(&self, position: u64);
    /// Marks successful processing, including a verified existing or mounted blob.
    fn finish(&self);
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
