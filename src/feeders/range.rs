use async_trait::async_trait;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::traits::Feeder;
use crate::errors::ScanError;

pub struct RangeFeeder {
    current: IpAddr,
    end: IpAddr,
    finished: bool,
}

impl RangeFeeder {
    pub fn new(start: IpAddr, end: IpAddr) -> Result<Self, ScanError> {
        match (start, end) {
            (IpAddr::V4(_), IpAddr::V4(_)) | (IpAddr::V6(_), IpAddr::V6(_)) => {
                if start > end {
                    return Err(ScanError::InvalidRange);
                }
                Ok(Self {
                    current: start,
                    end,
                    finished: false,
                })
            }
            _ => Err(ScanError::InvalidRange),
        }
    }
}

#[async_trait]
impl Feeder for RangeFeeder {
    async fn next_address(&mut self) -> Option<IpAddr> {
        if self.finished {
            return None;
        }

        let result = self.current;

        if self.current == self.end {
            self.finished = true;
        } else {
            self.current = match self.current {
                IpAddr::V4(ip) => {
                    let octets = ip.octets();
                    let num = u32::from_be_bytes(octets) + 1;
                    IpAddr::V4(Ipv4Addr::from(num.to_be_bytes()))
                }
                IpAddr::V6(ip) => {
                    let octets = ip.octets();
                    let num = u128::from_be_bytes(octets) + 1;
                    IpAddr::V6(Ipv6Addr::from(num.to_be_bytes()))
                }
            };
        }

        Some(result)
    }

    fn total_addresses(&self) -> usize {
        match (self.current, self.end) {
            (IpAddr::V4(start), IpAddr::V4(end)) => {
                let start_num = u32::from_be_bytes(start.octets());
                let end_num = u32::from_be_bytes(end.octets());
                (end_num - start_num + 1) as usize
            }
            (IpAddr::V6(start), IpAddr::V6(end)) => {
                let start_num = u128::from_be_bytes(start.octets());
                let end_num = u128::from_be_bytes(end.octets());
                ((end_num - start_num + 1) as usize).min(usize::MAX)
            }
            _ => 0,
        }
    }
}
