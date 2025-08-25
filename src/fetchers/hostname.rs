use async_trait::async_trait;
use dns_lookup::lookup_addr;

use super::traits::Fetcher;
use crate::core::subject::ScanningSubject;
use crate::errors::ScanError;

pub struct HostnameFetcher;

impl HostnameFetcher {
    pub fn new() -> Self {
        Self
    }
}

impl Default for HostnameFetcher {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Fetcher for HostnameFetcher {
    fn id(&self) -> String {
        "hostname".to_string()
    }

    fn name(&self) -> String {
        "Hostname".to_string()
    }

    async fn scan(&self, subject: &mut ScanningSubject) -> Result<String, ScanError> {
        tokio::task::spawn_blocking({
            let addr = subject.address();
            move || match lookup_addr(&addr) {
                Ok(hostname) => Ok(hostname),
                Err(_) => Ok("[n/a]".to_string()),
            }
        })
        .await
        .map_err(|e| ScanError::DnsResolutionFailed(e.to_string()))?
    }
}
