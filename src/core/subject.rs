use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

use super::result::ResultType;
use crate::config::ScannerConfig;

pub struct ScanningSubject {
    address: IpAddr,
    config: Arc<ScannerConfig>,
    parameters: HashMap<String, Box<dyn std::any::Any + Send + Sync>>,
    result_type: ResultType,
    aborted: bool,
    adapted_port_timeout: Option<u64>,
}

impl ScanningSubject {
    pub fn new(address: IpAddr, config: Arc<ScannerConfig>) -> Self {
        Self {
            address,
            config,
            parameters: HashMap::new(),
            result_type: ResultType::Unknown,
            aborted: false,
            adapted_port_timeout: None,
        }
    }

    pub fn address(&self) -> IpAddr {
        self.address
    }

    pub fn config(&self) -> &ScannerConfig {
        &self.config
    }

    pub fn set_parameter<T: 'static + Send + Sync>(&mut self, key: String, value: T) {
        self.parameters.insert(key, Box::new(value));
    }

    pub fn get_parameter<T: 'static>(&self, key: &str) -> Option<&T> {
        self.parameters.get(key)?.downcast_ref()
    }

    pub fn set_result_type(&mut self, result_type: ResultType) {
        self.result_type = result_type;
    }

    pub fn result_type(&self) -> ResultType {
        self.result_type
    }

    pub fn abort(&mut self) {
        self.aborted = true;
    }

    pub fn is_aborted(&self) -> bool {
        self.aborted
    }

    pub fn set_adapted_port_timeout(&mut self, timeout: u64) {
        self.adapted_port_timeout = Some(timeout);
    }

    pub fn adapted_port_timeout(&self) -> u64 {
        self.adapted_port_timeout
            .unwrap_or(self.config.port_timeout_ms)
    }
}
