use std::collections::HashMap;
use std::net::IpAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResultType {
    Unknown,
    Dead,
    Alive,
    WithPorts,
}

pub struct ScanningResult {
    address: IpAddr,
    values: HashMap<String, String>,
    result_type: ResultType,
    mac: Option<String>,
}

impl ScanningResult {
    pub fn new(address: IpAddr) -> Self {
        Self {
            address,
            values: HashMap::new(),
            result_type: ResultType::Unknown,
            mac: None,
        }
    }

    pub fn address(&self) -> IpAddr {
        self.address
    }

    pub fn add_value(&mut self, key: String, value: String) {
        self.values.insert(key, value);
    }

    pub fn get_value(&self, key: &str) -> Option<&String> {
        self.values.get(key)
    }

    pub fn set_type(&mut self, result_type: ResultType) {
        self.result_type = result_type;
    }

    pub fn result_type(&self) -> ResultType {
        self.result_type
    }

    pub fn set_mac(&mut self, mac: String) {
        self.mac = Some(mac);
    }

    pub fn mac(&self) -> Option<&String> {
        self.mac.as_ref()
    }
}
