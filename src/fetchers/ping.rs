use async_trait::async_trait;
use std::sync::Arc;
use std::time::Duration;
use surge_ping::{Client, Config, PingIdentifier, PingSequence};
use tokio::time::timeout;

use super::traits::Fetcher;
use crate::config::ScannerConfig;
use crate::core::result::ResultType;
use crate::core::subject::ScanningSubject;
use crate::errors::ScanError;

pub struct PingFetcher {
    config: Arc<ScannerConfig>,
}

impl PingFetcher {
    pub fn new(config: Arc<ScannerConfig>) -> Self {
        Self { config }
    }
}

#[async_trait]
impl Fetcher for PingFetcher {
    fn id(&self) -> String {
        "ping".to_string()
    }

    fn name(&self) -> String {
        "Ping".to_string()
    }

    async fn scan(&self, subject: &mut ScanningSubject) -> Result<String, ScanError> {
        let client =
            Client::new(&Config::default()).map_err(|e| ScanError::PingFailed(e.to_string()))?;

        let mut total_time = Duration::ZERO;
        let mut successful_pings = 0;

        for seq in 0..self.config.ping_count {
            let mut pinger = client.pinger(subject.address(), PingIdentifier(0)).await;
            pinger.timeout(Duration::from_millis(self.config.ping_timeout_ms));

            if let Ok(Ok((_, duration))) = timeout(
                Duration::from_millis(self.config.ping_timeout_ms),
                pinger.ping(PingSequence(seq as u16), &[]),
            )
            .await
            {
                total_time += duration;
                successful_pings += 1;
            }
        }

        if successful_pings > 0 {
            subject.set_result_type(ResultType::Alive);
            let avg_time = total_time / successful_pings;

            if self.config.adapt_port_timeout {
                let adapted =
                    (avg_time.as_millis() as u64 * 3).max(self.config.min_port_timeout_ms);
                subject.set_adapted_port_timeout(adapted);
            }

            Ok(format!("{} ms", avg_time.as_millis()))
        } else {
            subject.set_result_type(ResultType::Dead);
            if !self.config.scan_dead_hosts {
                subject.abort();
            }
            Ok("[n/a]".to_string())
        }
    }
}
