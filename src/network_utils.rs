use std::net::IpAddr;

pub fn get_local_network() -> Option<(String, String, String)> {
    use pnet::datalink;

    let interfaces = datalink::interfaces();

    for interface in interfaces {
        if !interface.is_up() || interface.is_loopback() || interface.ips.is_empty() {
            continue;
        }

        for ip_network in &interface.ips {
            if let IpAddr::V4(ipv4) = ip_network.ip() {
                let octets = ipv4.octets();

                // Ignorer les adresses link-local et localhost
                if (octets[0] == 169 && octets[1] == 254) || octets[0] == 127 {
                    continue;
                }

                let network_base = format!("{}.{}.{}.0", octets[0], octets[1], octets[2]);
                let network_start = format!("{}.{}.{}.1", octets[0], octets[1], octets[2]);
                let network_end = format!("{}.{}.{}.254", octets[0], octets[1], octets[2]);
                let cidr = format!("{}/24", network_base);

                return Some((network_start, network_end, cidr));
            }
        }
    }

    None
}

pub fn parse_ip_for_sorting(ip_str: &str) -> Option<IpAddr> {
    ip_str.parse().ok()
}
