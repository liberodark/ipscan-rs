#[cfg(test)]
mod tests {
    use crate::config::ScannerConfig;
    use crate::core::port_iterator::PortIterator;
    use crate::core::result::{ResultType, ScanningResult};
    use crate::core::subject::ScanningSubject;
    use crate::errors::ScanError;
    use crate::feeders::range::RangeFeeder;
    use crate::feeders::traits::Feeder;
    use crate::fetchers::hostname::HostnameFetcher;
    use crate::fetchers::mac::MacFetcher;
    use crate::fetchers::ping::PingFetcher;
    use crate::fetchers::ports::PortsFetcher;
    use crate::fetchers::registry::FetcherRegistry;
    use crate::fetchers::traits::Fetcher;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::sync::Arc;

    #[test]
    fn test_port_iterator_single_port() {
        let mut iter = PortIterator::new("80").unwrap();
        assert_eq!(iter.next(), Some(80));
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn test_port_iterator_range() {
        let mut iter = PortIterator::new("80-82").unwrap();
        assert_eq!(iter.next(), Some(80));
        assert_eq!(iter.next(), Some(81));
        assert_eq!(iter.next(), Some(82));
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn test_port_iterator_mixed() {
        let iter = PortIterator::new("22,80-82,443").unwrap();
        let ports: Vec<u16> = iter.collect();
        assert_eq!(ports, vec![22, 80, 81, 82, 443]);
    }

    #[test]
    fn test_port_iterator_invalid() {
        assert!(PortIterator::new("invalid").is_err());
        assert!(PortIterator::new("80-70").is_err()); // Invalid range
        assert!(PortIterator::new("99999").is_err()); // Port too high
    }

    #[test]
    fn test_port_iterator_duplicates() {
        let iter = PortIterator::new("80,80,81,80-82").unwrap();
        let ports: Vec<u16> = iter.collect();
        assert_eq!(ports, vec![80, 81, 82]);
    }

    #[test]
    fn test_port_iterator_empty_check() {
        let iter = PortIterator::new("80").unwrap();
        assert!(!iter.is_empty());

        match PortIterator::new("") {
            Ok(iter) => assert!(iter.is_empty()),
            Err(_) => {
                // OK - empty string might be rejected
            }
        }
    }

    #[test]
    fn test_port_iterator_complex_ranges() {
        let iter = PortIterator::new("1-3,10-12,20").unwrap();
        let ports: Vec<u16> = iter.collect();
        assert_eq!(ports, vec![1, 2, 3, 10, 11, 12, 20]);
    }

    #[test]
    fn test_port_iterator_max_port() {
        assert!(PortIterator::new("65535").is_ok());
        assert!(PortIterator::new("65536").is_err());
    }

    #[tokio::test]
    async fn test_range_feeder_ipv4() {
        let start = IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1));
        let end = IpAddr::V4(Ipv4Addr::new(192, 168, 0, 3));

        let mut feeder = RangeFeeder::new(start, end).unwrap();

        assert_eq!(
            feeder.next_address().await,
            Some(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1)))
        );
        assert_eq!(
            feeder.next_address().await,
            Some(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 2)))
        );
        assert_eq!(
            feeder.next_address().await,
            Some(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 3)))
        );
        assert_eq!(feeder.next_address().await, None);
    }

    #[tokio::test]
    async fn test_range_feeder_ipv6() {
        let start = IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1));
        let end = IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 3));

        let mut feeder = RangeFeeder::new(start, end).unwrap();

        assert_eq!(
            feeder.next_address().await,
            Some(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)))
        );
        assert_eq!(
            feeder.next_address().await,
            Some(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 2)))
        );
        assert_eq!(
            feeder.next_address().await,
            Some(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 3)))
        );
        assert_eq!(feeder.next_address().await, None);
    }

    #[tokio::test]
    async fn test_range_feeder_invalid() {
        let start = IpAddr::V4(Ipv4Addr::new(192, 168, 0, 10));
        let end = IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1));

        assert!(RangeFeeder::new(start, end).is_err());
    }

    #[tokio::test]
    async fn test_range_feeder_mixed_types() {
        let start = IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1));
        let end = IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1));

        assert!(RangeFeeder::new(start, end).is_err());
    }

    #[tokio::test]
    async fn test_range_feeder_single_ip() {
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1));

        let mut feeder = RangeFeeder::new(ip, ip).unwrap();

        assert_eq!(feeder.next_address().await, Some(ip));
        assert_eq!(feeder.next_address().await, None);
    }

    #[test]
    fn test_range_feeder_total_addresses() {
        let start = IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1));
        let end = IpAddr::V4(Ipv4Addr::new(192, 168, 0, 254));

        let feeder = RangeFeeder::new(start, end).unwrap();
        assert_eq!(feeder.total_addresses(), 254);
    }

    #[test]
    fn test_scanning_result() {
        let addr = IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1));
        let mut result = ScanningResult::new(addr);

        assert_eq!(result.address(), addr);
        assert_eq!(result.result_type(), ResultType::Unknown);

        result.add_value("ping".to_string(), "5 ms".to_string());
        result.set_type(ResultType::Alive);

        assert_eq!(result.get_value("ping"), Some(&"5 ms".to_string()));
        assert_eq!(result.result_type(), ResultType::Alive);
    }

    #[test]
    fn test_scanning_result_mac() {
        let addr = IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1));
        let mut result = ScanningResult::new(addr);

        assert_eq!(result.mac(), None);

        result.set_mac("AA:BB:CC:DD:EE:FF".to_string());
        assert_eq!(result.mac(), Some(&"AA:BB:CC:DD:EE:FF".to_string()));
    }

    #[test]
    fn test_scanning_result_multiple_values() {
        let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let mut result = ScanningResult::new(addr);

        result.add_value("hostname".to_string(), "test.local".to_string());
        result.add_value("ports".to_string(), "80,443".to_string());
        result.add_value("ping".to_string(), "10 ms".to_string());

        assert_eq!(
            result.get_value("hostname"),
            Some(&"test.local".to_string())
        );
        assert_eq!(result.get_value("ports"), Some(&"80,443".to_string()));
        assert_eq!(result.get_value("ping"), Some(&"10 ms".to_string()));
        assert_eq!(result.get_value("nonexistent"), None);
    }

    #[test]
    fn test_scanning_subject() {
        let config = Arc::new(ScannerConfig::default());
        let addr = IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1));
        let mut subject = ScanningSubject::new(addr, config.clone());

        assert_eq!(subject.address(), addr);
        assert!(!subject.is_aborted());
        assert_eq!(subject.result_type(), ResultType::Unknown);

        subject.set_result_type(ResultType::Alive);
        assert_eq!(subject.result_type(), ResultType::Alive);

        subject.abort();
        assert!(subject.is_aborted());
    }

    #[test]
    fn test_scanning_subject_parameters() {
        let config = Arc::new(ScannerConfig::default());
        let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let mut subject = ScanningSubject::new(addr, config);

        subject.set_parameter("test_key".to_string(), 42u32);
        subject.set_parameter("string_key".to_string(), "test_value".to_string());

        assert_eq!(subject.get_parameter::<u32>("test_key"), Some(&42u32));
        assert_eq!(
            subject.get_parameter::<String>("string_key"),
            Some(&"test_value".to_string())
        );
        assert_eq!(subject.get_parameter::<u32>("nonexistent"), None);
    }

    #[test]
    fn test_scanning_subject_port_timeout() {
        let config = Arc::new(ScannerConfig {
            port_timeout_ms: 500,
            ..Default::default()
        });
        let addr = IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1));
        let mut subject = ScanningSubject::new(addr, config);

        assert_eq!(subject.adapted_port_timeout(), 500);

        subject.set_adapted_port_timeout(200);
        assert_eq!(subject.adapted_port_timeout(), 200);
    }

    #[test]
    fn test_scanner_config_default() {
        let config = ScannerConfig::default();

        assert_eq!(config.max_threads, 100);
        assert_eq!(config.ping_timeout_ms, 2000);
        assert!(!config.scan_dead_hosts);
        assert_eq!(config.ping_count, 3);
        assert_eq!(config.port_timeout_ms, 500);
        assert_eq!(config.min_port_timeout_ms, 100);
        assert!(config.adapt_port_timeout);
    }

    #[test]
    fn test_scanner_config_custom() {
        let config = ScannerConfig {
            max_threads: 50,
            ping_timeout_ms: 1000,
            scan_dead_hosts: true,
            port_string: "22,80,443".to_string(),
            use_requested_ports: true,
            ping_count: 5,
            port_timeout_ms: 1000,
            min_port_timeout_ms: 50,
            adapt_port_timeout: false,
        };

        assert_eq!(config.max_threads, 50);
        assert_eq!(config.ping_timeout_ms, 1000);
        assert!(config.scan_dead_hosts);
        assert_eq!(config.port_string, "22,80,443");
        assert!(config.use_requested_ports);
        assert_eq!(config.ping_count, 5);
        assert_eq!(config.port_timeout_ms, 1000);
        assert_eq!(config.min_port_timeout_ms, 50);
        assert!(!config.adapt_port_timeout);
    }

    #[test]
    fn test_result_type() {
        let unknown = ResultType::Unknown;
        let dead = ResultType::Dead;
        let alive = ResultType::Alive;
        let with_ports = ResultType::WithPorts;

        assert_ne!(unknown, dead);
        assert_ne!(alive, dead);
        assert_ne!(alive, with_ports);
        assert_eq!(unknown, unknown.clone());
    }

    #[test]
    fn test_scan_error_display() {
        let err = ScanError::InvalidRange;
        assert_eq!(err.to_string(), "Invalid IP range");

        let err = ScanError::PingFailed("timeout".to_string());
        assert_eq!(err.to_string(), "Ping failed: timeout");

        let err = ScanError::PortScanFailed("connection refused".to_string());
        assert_eq!(err.to_string(), "Port scan failed: connection refused");

        let err = ScanError::DnsResolutionFailed("host not found".to_string());
        assert_eq!(err.to_string(), "DNS resolution failed: host not found");

        let err = ScanError::Network("connection lost".to_string());
        assert_eq!(err.to_string(), "Network error: connection lost");
    }

    #[test]
    fn test_scan_error_from_io_error() {
        use std::io;
        let io_error = io::Error::new(io::ErrorKind::NotFound, "file not found");
        let scan_error = ScanError::from(io_error);
        assert!(scan_error.to_string().contains("file not found"));
    }

    #[test]
    fn test_fetcher_registry_new() {
        let registry = FetcherRegistry::new();
        assert_eq!(registry.get_selected_fetchers().len(), 0);
    }

    #[test]
    fn test_fetcher_registry_register() {
        let config = Arc::new(ScannerConfig::default());
        let mut registry = FetcherRegistry::new();

        registry.register(Arc::new(PingFetcher::new(config.clone())));
        assert_eq!(registry.get_selected_fetchers().len(), 0);

        registry.register_default_fetchers(config);
        assert!(registry.get_selected_fetchers().len() > 0);
    }

    #[tokio::test]
    async fn test_hostname_fetcher() {
        let fetcher = HostnameFetcher::new();
        assert_eq!(fetcher.id(), "hostname");
        assert_eq!(fetcher.name(), "Hostname");

        let config = Arc::new(ScannerConfig::default());
        let addr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let mut subject = ScanningSubject::new(addr, config);
        let _ = fetcher.scan(&mut subject).await;
    }

    #[tokio::test]
    async fn test_mac_fetcher() {
        let fetcher = MacFetcher::new();
        assert_eq!(fetcher.id(), "mac");
        assert_eq!(fetcher.name(), "MAC Address");

        let config = Arc::new(ScannerConfig::default());
        let addr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let mut subject = ScanningSubject::new(addr, config);
        let result = fetcher.scan(&mut subject).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_ports_fetcher() {
        let config = Arc::new(ScannerConfig {
            port_string: "65534-65535".to_string(),
            port_timeout_ms: 100,
            ..Default::default()
        });
        let fetcher = PortsFetcher::new(config.clone());

        assert_eq!(fetcher.id(), "ports");
        assert_eq!(fetcher.name(), "Ports");

        let addr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let mut subject = ScanningSubject::new(addr, config);

        let result = fetcher.scan(&mut subject).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_ping_fetcher() {
        let config = Arc::new(ScannerConfig {
            ping_count: 1,
            ping_timeout_ms: 100,
            adapt_port_timeout: false,
            ..Default::default()
        });
        let fetcher = PingFetcher::new(config.clone());

        assert_eq!(fetcher.id(), "ping");
        assert_eq!(fetcher.name(), "Ping");

        let addr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let mut subject = ScanningSubject::new(addr, config);

        let _ = fetcher.scan(&mut subject).await;
    }

    #[tokio::test]
    async fn test_scanning_workflow() {
        let config = Arc::new(ScannerConfig {
            port_string: "".to_string(),
            ping_count: 1,
            ping_timeout_ms: 100,
            ..Default::default()
        });

        let addr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let mut subject = ScanningSubject::new(addr, config.clone());
        let mut result = ScanningResult::new(addr);

        subject.set_result_type(ResultType::Alive);
        result.add_value("ping".to_string(), "1 ms".to_string());
        result.add_value("hostname".to_string(), "localhost".to_string());
        result.set_type(subject.result_type());

        assert_eq!(result.result_type(), ResultType::Alive);
        assert_eq!(result.get_value("ping"), Some(&"1 ms".to_string()));
        assert_eq!(result.get_value("hostname"), Some(&"localhost".to_string()));
    }

    #[test]
    fn test_cidr_calculation() {
        let cidr = "192.168.0.0/24";
        let parts: Vec<&str> = cidr.split('/').collect();
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[0], "192.168.0.0");
        assert_eq!(parts[1], "24");

        let mask_bits: u32 = parts[1].parse().unwrap();
        assert_eq!(mask_bits, 24);

        let cidr = "192.168.0.1/32";
        let parts: Vec<&str> = cidr.split('/').collect();
        let mask_bits: u32 = parts[1].parse().unwrap();
        assert_eq!(mask_bits, 32);
    }

    #[test]
    fn test_cidr_range_calculation() {
        let base_ip = "192.168.1.0";
        let mask_bits = 24u32;

        let octets: Vec<u8> = base_ip.split('.').filter_map(|s| s.parse().ok()).collect();
        let ip_num = u32::from_be_bytes([octets[0], octets[1], octets[2], octets[3]]);

        let network_mask = !0u32 << (32 - mask_bits);
        let network_addr = ip_num & network_mask;
        let broadcast_addr = network_addr | !network_mask;

        let first_addr = network_addr + 1;
        let last_addr = broadcast_addr - 1;

        assert_eq!(last_addr - first_addr + 1, 254); // /24 has 254 usable hosts
    }

    #[test]
    fn test_format_ports_function() {
        let format_ports = |ports: &[u16]| -> String {
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
        };

        assert_eq!(format_ports(&[80]), "80");
        assert_eq!(format_ports(&[80, 81, 82]), "80-82");
        assert_eq!(format_ports(&[22, 80, 81, 82, 443]), "22,80-82,443");
        assert_eq!(format_ports(&[]), "");
    }
}
