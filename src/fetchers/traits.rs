use crate::core::subject::ScanningSubject;
use crate::errors::ScanError;
use async_trait::async_trait;

#[async_trait]
pub trait Fetcher: Send + Sync {
    fn id(&self) -> String;
    fn name(&self) -> String;
    async fn scan(&self, subject: &mut ScanningSubject) -> Result<String, ScanError>;
}
