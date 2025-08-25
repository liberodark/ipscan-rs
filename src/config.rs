use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScannerConfig {
    pub max_threads: usize,
    pub ping_timeout_ms: u64,
    pub scan_dead_hosts: bool,
    pub port_string: String,
    pub use_requested_ports: bool,
    pub ping_count: u8,
    pub port_timeout_ms: u64,
    pub min_port_timeout_ms: u64,
    pub adapt_port_timeout: bool,
}

impl Default for ScannerConfig {
    fn default() -> Self {
        Self {
            max_threads: 100,
            ping_timeout_ms: 2000,
            scan_dead_hosts: false,
            port_string: "80,443,8080,3389,22,23,21,25,110,139,445".to_string(),
            use_requested_ports: false,
            ping_count: 3,
            port_timeout_ms: 500,
            min_port_timeout_ms: 100,
            adapt_port_timeout: true,
        }
    }
}
