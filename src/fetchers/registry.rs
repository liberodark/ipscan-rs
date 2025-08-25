use super::hostname::HostnameFetcher;
use super::mac::MacFetcher;
use super::ping::PingFetcher;
use super::ports::PortsFetcher;
use super::traits::Fetcher;
use crate::config::ScannerConfig;
use std::sync::Arc;

pub struct FetcherRegistry {
    fetchers: Vec<Arc<dyn Fetcher>>,
    selected: Vec<usize>,
}

impl FetcherRegistry {
    pub fn new() -> Self {
        Self {
            fetchers: Vec::new(),
            selected: Vec::new(),
        }
    }

    pub fn register(&mut self, fetcher: Arc<dyn Fetcher>) {
        self.fetchers.push(fetcher);
    }

    pub fn register_default_fetchers(&mut self, config: Arc<ScannerConfig>) {
        self.register(Arc::new(PingFetcher::new(config.clone())));
        self.register(Arc::new(HostnameFetcher::new()));
        self.register(Arc::new(PortsFetcher::new(config.clone())));
        self.register(Arc::new(MacFetcher::new()));
        self.selected = (0..self.fetchers.len()).collect();
    }

    pub fn get_selected_fetchers(&self) -> Vec<Arc<dyn Fetcher>> {
        self.selected
            .iter()
            .filter_map(|&i| self.fetchers.get(i).cloned())
            .collect()
    }
}

impl Default for FetcherRegistry {
    fn default() -> Self {
        Self::new()
    }
}
