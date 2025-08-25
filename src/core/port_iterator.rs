use std::str::FromStr;

pub struct PortIterator {
    ports: Vec<u16>,
    current: usize,
}

impl PortIterator {
    pub fn new(port_string: &str) -> Result<Self, String> {
        const MAX_PORTS: usize = 65535;

        let mut ports = Vec::new();

        for part in port_string.split(',') {
            let part = part.trim();
            if part.contains('-') {
                let range: Vec<&str> = part.split('-').collect();
                if range.len() != 2 {
                    return Err(format!("Invalid port range: {}", part));
                }

                let start = u16::from_str(range[0].trim())
                    .map_err(|_| format!("Invalid port number: {}", range[0]))?;
                let end = u16::from_str(range[1].trim())
                    .map_err(|_| format!("Invalid port number: {}", range[1]))?;

                if start > end {
                    return Err(format!("Invalid range: {} > {}", start, end));
                }

                let range_size = (end - start + 1) as usize;
                if ports.len() + range_size > MAX_PORTS {
                    return Err(format!("Too many ports specified (max: {})", MAX_PORTS));
                }

                for port in start..=end {
                    ports.push(port);
                }
            } else {
                let port =
                    u16::from_str(part).map_err(|_| format!("Invalid port number: {}", part))?;
                ports.push(port);
            }
        }

        ports.sort_unstable();
        ports.dedup();

        if ports.len() > MAX_PORTS {
            return Err(format!(
                "Too many unique ports specified (max: {})",
                MAX_PORTS
            ));
        }

        Ok(Self { ports, current: 0 })
    }

    pub fn len(&self) -> usize {
        self.ports.len()
    }

    pub fn is_empty(&self) -> bool {
        self.ports.is_empty()
    }
}

impl Iterator for PortIterator {
    type Item = u16;

    fn next(&mut self) -> Option<Self::Item> {
        if self.current < self.ports.len() {
            let port = self.ports[self.current];
            self.current += 1;
            Some(port)
        } else {
            None
        }
    }
}
