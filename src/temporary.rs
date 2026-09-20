//! Per-operation temporary file content quota, shared by concurrent workers.
use crate::{Error, Result};
use std::sync::{Arc, Mutex};
use tokio::sync::Notify;

pub(crate) struct Budget {
    limit: u64,
    used: Mutex<u64>,
    released: Notify,
}

pub(crate) struct Reservation {
    budget: Arc<Budget>,
    bytes: u64,
}

impl Budget {
    pub(crate) fn new(limit: u64) -> Arc<Self> {
        Arc::new(Self {
            limit,
            used: Mutex::new(0),
            released: Notify::new(),
        })
    }

    pub(crate) async fn reserve(self: &Arc<Self>, bytes: u64) -> Result<Reservation> {
        if bytes > self.limit {
            return Err(Error::input(
                "blob exceeds available max_temp_size; increase the temporary storage limit",
            ));
        }
        loop {
            let notified = self.released.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            {
                let mut used = self.used.lock().expect("temporary budget lock poisoned");
                if bytes <= self.limit - *used {
                    *used += bytes;
                    return Ok(Reservation {
                        budget: self.clone(),
                        bytes,
                    });
                }
            }
            notified.await;
        }
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        *self
            .budget
            .used
            .lock()
            .expect("temporary budget lock poisoned") -= self.bytes;
        self.budget.released.notify_waiters();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn concurrent_reservations_wait_and_cancellation_releases_quota() {
        let budget = Budget::new(10);
        let first = budget.reserve(7).await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(20), budget.reserve(4))
                .await
                .is_err()
        );
        let other = budget.reserve(3).await.unwrap();
        drop(first);
        let next = tokio::time::timeout(Duration::from_secs(1), budget.reserve(7))
            .await
            .unwrap()
            .unwrap();
        drop((other, next));
        assert!(budget.reserve(10).await.is_ok());
        assert!(budget.reserve(11).await.is_err());
    }

    #[tokio::test]
    async fn aborted_worker_releases_reserved_space() {
        let budget = Budget::new(10);
        let reservation = budget.reserve(10).await.unwrap();
        let worker = tokio::spawn(async move {
            let _reservation = reservation;
            std::future::pending::<()>().await;
        });
        worker.abort();
        let _ = worker.await;
        assert!(
            tokio::time::timeout(Duration::from_secs(1), budget.reserve(10))
                .await
                .unwrap()
                .is_ok()
        );
    }
}
