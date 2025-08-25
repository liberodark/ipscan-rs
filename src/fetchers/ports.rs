use async_trait::async_trait;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;

use super::traits::Fetcher;
use crate::config::ScannerConfig;
use crate::core::port_iterator::PortIterator;
use crate::core::result::ResultType;
use crate::core::subject::ScanningSubject;
use crate::errors::ScanError;

pub struct PortsFetcher {
    config: Arc<ScannerConfig>,
}

impl PortsFetcher {
    pub fn new(config: Arc<ScannerConfig>) -> Self {
        Self { config }
    }
}

#[async_trait]
impl Fetcher for PortsFetcher {
    fn id(&self) -> String {
        "ports".to_string()
    }

    fn name(&self) -> String {
        "Ports".to_string()
    }

    async fn scan(&self, subject: &mut ScanningSubject) -> Result<String, ScanError> {
        let port_iterator =
            PortIterator::new(&self.config.port_string).map_err(ScanError::PortScanFailed)?;

        if port_iterator.is_empty() {
            return Ok("[n/s]".to_string());
        }

        let mut open_ports = Vec::new();
        let timeout_ms = subject.adapted_port_timeout();

        for port in port_iterator {
            let addr = format!("{}:{}", subject.address(), port);

            if let Ok(Ok(_)) =
                timeout(Duration::from_millis(timeout_ms), TcpStream::connect(&addr)).await
            {
                open_ports.push(port);
            }
        }

        if !open_ports.is_empty() {
            subject.set_result_type(ResultType::WithPorts);
            Ok(format_ports(&open_ports))
        } else {
            Ok("[n/a]".to_string())
        }
    }
}

fn format_ports(ports: &[u16]) -> String {
    if ports.is_empty() {
        return String::new();
    }

    let mut ranges = Vec::new();
    let mut start = ports[0];
    let mut end = ports[0];

    for &port in &ports[1..] {
        if port == end + 1 {
            end = port;
        } else {
            if start == end {
                ranges.push(format!("{}", start));
            } else {
                ranges.push(format!("{}-{}", start, end));
            }
            start = port;
            end = port;
        }
    }

    if start == end {
        ranges.push(format!("{}", start));
    } else {
        ranges.push(format!("{}-{}", start, end));
    }

    ranges.join(",")
}
