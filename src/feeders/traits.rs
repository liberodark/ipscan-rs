use async_trait::async_trait;
use std::net::IpAddr;

#[async_trait]
pub trait Feeder: Send + Sync {
    async fn next_address(&mut self) -> Option<IpAddr>;
    fn total_addresses(&self) -> usize;
}
