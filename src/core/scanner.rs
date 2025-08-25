use std::sync::Arc;
use tokio::sync::{RwLock, Semaphore};
use tokio::task::JoinSet;
use tracing::{debug, error, info};

use super::result::ScanningResult;
use super::subject::ScanningSubject;
use crate::config::ScannerConfig;
use crate::errors::ScanError;
use crate::feeders::traits::Feeder;
use crate::fetchers::registry::FetcherRegistry;

pub struct Scanner {
    fetcher_registry: Arc<RwLock<FetcherRegistry>>,
    config: Arc<ScannerConfig>,
}

impl Scanner {
    pub fn new(fetcher_registry: Arc<RwLock<FetcherRegistry>>, config: Arc<ScannerConfig>) -> Self {
        Self {
            fetcher_registry,
            config,
        }
    }

    pub async fn scan(
        &self,
        mut feeder: Box<dyn Feeder>,
    ) -> Result<Vec<ScanningResult>, ScanError> {
        info!("Starting scan with {} threads", self.config.max_threads);

        let semaphore = Arc::new(Semaphore::new(self.config.max_threads));
        let mut results = Vec::new();
        let mut tasks = JoinSet::new();

        while let Some(address) = feeder.next_address().await {
            let permit = semaphore.clone().acquire_owned().await.unwrap();
            let fetcher_registry = self.fetcher_registry.clone();
            let config = self.config.clone();

            tasks.spawn(async move {
                let _permit = permit;
                let mut subject = ScanningSubject::new(address, config.clone());
                let mut result = ScanningResult::new(address);

                let registry = fetcher_registry.read().await;
                for fetcher in registry.get_selected_fetchers() {
                    match fetcher.scan(&mut subject).await {
                        Ok(value) => {
                            result.add_value(fetcher.id(), value);
                        }
                        Err(e) => {
                            debug!("Fetcher {} failed for {}: {}", fetcher.id(), address, e);
                        }
                    }

                    if subject.is_aborted() && !config.scan_dead_hosts {
                        break;
                    }
                }

                result.set_type(subject.result_type());
                result
            });
        }

        while let Some(result) = tasks.join_next().await {
            match result {
                Ok(scan_result) => {
                    info!(
                        "Scanned: {} - {:?}",
                        scan_result.address(),
                        scan_result.result_type()
                    );
                    results.push(scan_result);
                }
                Err(e) => {
                    error!("Task failed: {}", e);
                }
            }
        }

        info!("Scan completed. {} hosts scanned", results.len());
        Ok(results)
    }
}
