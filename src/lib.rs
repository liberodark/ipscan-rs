pub mod config;
pub mod errors;
pub mod network_utils;

pub mod core {
    pub mod port_iterator;
    pub mod result;
    pub mod scanner;
    pub mod subject;
}

pub mod fetchers {
    pub mod hostname;
    pub mod mac;
    pub mod ping;
    pub mod ports;
    pub mod registry;
    pub mod traits;
}

pub mod feeders {
    pub mod range;
    pub mod traits;
}

pub use config::ScannerConfig;
pub use core::result::{ResultType, ScanningResult};
pub use core::scanner::Scanner;
pub use core::subject::ScanningSubject;
pub use errors::ScanError;
pub use feeders::range::RangeFeeder;
pub use feeders::traits::Feeder;
pub use fetchers::registry::FetcherRegistry;

#[cfg(test)]
mod tests;
