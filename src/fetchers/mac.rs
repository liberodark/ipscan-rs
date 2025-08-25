use async_trait::async_trait;
use std::net::IpAddr;
use std::process::Command;

use super::traits::Fetcher;
use crate::core::subject::ScanningSubject;
use crate::errors::ScanError;

pub struct MacFetcher;

impl MacFetcher {
    pub fn new() -> Self {
        Self
    }

    #[cfg(target_os = "linux")]
    fn get_mac_linux(ip: &IpAddr) -> Option<String> {
        let ip_str = ip.to_string();

        if let Ok(arp_data) = std::fs::read_to_string("/proc/net/arp") {
            for line in arp_data.lines().skip(1) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 6 && parts[0] == ip_str {
                    let mac = parts[3];
                    if mac != "00:00:00:00:00:00" && mac != "*" {
                        return Some(mac.to_uppercase());
                    }
                }
            }
        }

        if let Ok(output) = Command::new("ip")
            .arg("neigh")
            .arg("show")
            .arg(&ip_str)
            .output()
        {
            let result = String::from_utf8_lossy(&output.stdout);
            if result.contains("lladdr") {
                let parts: Vec<&str> = result.split_whitespace().collect();
                if let Some(pos) = parts.iter().position(|&x| x == "lladdr") {
                    if let Some(mac) = parts.get(pos + 1) {
                        return Some(mac.to_uppercase());
                    }
                }
            }
        }

        if let Ok(output) = Command::new("arp").arg("-n").arg(&ip_str).output() {
            let result = String::from_utf8_lossy(&output.stdout);
            for line in result.lines() {
                if line.contains(&ip_str) {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 3 && parts[1] == "ether" {
                        return Some(parts[2].to_uppercase());
                    }
                }
            }
        }

        None
    }

    #[cfg(target_os = "windows")]
    fn get_mac_windows(ip: &IpAddr) -> Option<String> {
        let ip_str = ip.to_string();

        if let Ok(output) = Command::new("arp").arg("-a").arg(&ip_str).output() {
            let result = String::from_utf8_lossy(&output.stdout);
            for line in result.lines() {
                if line.contains(&ip_str) {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 2 {
                        let mac = parts[1].replace('-', ":");
                        if mac.len() == 17 {
                            return Some(mac.to_uppercase());
                        }
                    }
                }
            }
        }
        None
    }

    #[cfg(target_os = "macos")]
    fn get_mac_macos(ip: &IpAddr) -> Option<String> {
        let ip_str = ip.to_string();

        if let Ok(output) = Command::new("arp").arg("-n").arg(&ip_str).output() {
            let result = String::from_utf8_lossy(&output.stdout);
            for line in result.lines() {
                if line.contains(&ip_str) {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 4 {
                        let mac = parts[3];
                        if mac.contains(':') && mac.len() == 17 {
                            return Some(mac.to_uppercase());
                        }
                    }
                }
            }
        }
        None
    }
}

#[async_trait]
impl Fetcher for MacFetcher {
    fn id(&self) -> String {
        "mac".to_string()
    }

    fn name(&self) -> String {
        "MAC Address".to_string()
    }

    async fn scan(&self, subject: &mut ScanningSubject) -> Result<String, ScanError> {
        let ip = subject.address();

        let mac = tokio::task::spawn_blocking(move || {
            #[cfg(target_os = "linux")]
            {
                MacFetcher::get_mac_linux(&ip)
            }
            #[cfg(target_os = "windows")]
            {
                MacFetcher::get_mac_windows(&ip)
            }
            #[cfg(target_os = "macos")]
            {
                MacFetcher::get_mac_macos(&ip)
            }
            #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
            {
                None
            }
        })
        .await
        .map_err(|e| ScanError::Network(format!("MAC lookup failed: {}", e)))?;

        Ok(mac.unwrap_or_else(|| "[n/a]".to_string()))
    }
}

impl Default for MacFetcher {
    fn default() -> Self {
        Self::new()
    }
}
