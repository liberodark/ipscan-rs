use thiserror::Error;

#[derive(Error, Debug)]
pub enum ScanError {
    #[error("Network error: {0}")]
    Network(String),

    #[error("Invalid IP range")]
    InvalidRange,

    #[error("Ping failed: {0}")]
    PingFailed(String),

    #[error("Port scan failed: {0}")]
    PortScanFailed(String),

    #[error("DNS resolution failed: {0}")]
    DnsResolutionFailed(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}
