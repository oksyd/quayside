use super::Registry;
use crate::{Result, error::Code};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

struct Mirror {
    registry: Registry,
    unavailable: AtomicBool,
    announced: AtomicBool,
    fallback_announced: AtomicBool,
}

pub(super) struct Mirrors {
    pub(super) resolve_tags: bool,
    entries: Vec<Mirror>,
    notice: Box<dyn Fn(&str) + Send + Sync>,
    origin_announced: AtomicBool,
}

pub(super) fn can_fallback(code: Code) -> bool {
    matches!(
        code,
        Code::Network | Code::NotFound | Code::Unauthorized | Code::Forbidden
    )
}

impl Registry {
    // Attach mirrors to this source handle only. Cached destination handles keep direct routing.
    pub(crate) fn with_mirrors(
        mut self,
        mirrors: Vec<Registry>,
        resolve_tags: bool,
        notice: impl Fn(&str) + Send + Sync + 'static,
    ) -> Self {
        if !mirrors.is_empty() {
            self.mirrors = Some(Arc::new(Mirrors {
                resolve_tags,
                entries: mirrors
                    .into_iter()
                    .map(|registry| Mirror {
                        registry,
                        unavailable: AtomicBool::new(false),
                        announced: AtomicBool::new(false),
                        fallback_announced: AtomicBool::new(false),
                    })
                    .collect(),
                notice: Box::new(notice),
                origin_announced: AtomicBool::new(false),
            }));
        }
        self
    }

    pub(crate) fn resolves_tags_at_mirrors(&self) -> bool {
        self.mirrors
            .as_ref()
            .is_some_and(|mirrors| mirrors.resolve_tags)
    }

    // Each attempt includes body reading and verification, so interrupted streams can fail over.
    // Operations call direct methods; authentication and redirects stay with their actual origin.
    pub(super) async fn read<'a, T, F>(&'a self, operation: impl Fn(&'a Registry) -> F) -> Result<T>
    where
        F: std::future::Future<Output = Result<T>>,
    {
        if let Some(mirrors) = &self.mirrors {
            for mirror in &mirrors.entries {
                if mirror.unavailable.load(Ordering::Relaxed) {
                    continue;
                }
                let endpoint = mirror.registry.endpoint();
                if !mirror.announced.swap(true, Ordering::Relaxed) {
                    (mirrors.notice)(&format!("Using Docker Hub mirror {endpoint}"));
                }
                match operation(&mirror.registry).await {
                    Ok(value) => return Ok(value),
                    Err(error) if can_fallback(error.code) => {
                        if error.code == Code::Network {
                            mirror.unavailable.store(true, Ordering::Relaxed);
                        }
                        if !mirror.fallback_announced.swap(true, Ordering::Relaxed) {
                            (mirrors.notice)(&format!(
                                "Mirror {endpoint} could not serve content ({:?}); trying the next source",
                                error.code,
                            ));
                        }
                    }
                    Err(error) => return Err(error),
                }
            }
            if !mirrors.origin_announced.swap(true, Ordering::Relaxed) {
                (mirrors.notice)("Using Docker Hub origin for unavailable mirror content");
            }
        }
        operation(self).await
    }
}
