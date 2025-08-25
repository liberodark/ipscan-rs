use clap::Parser;
use ipscan_rs::{FetcherRegistry, RangeFeeder, Scanner, ScannerConfig};
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{error, info};

#[derive(Parser, Debug)]
#[command(name = "ipscan")]
#[command(about = "Fast and friendly network scanner", long_about = None)]
struct Args {
    #[arg(short, long)]
    start: Option<IpAddr>,

    #[arg(short, long)]
    end: Option<IpAddr>,

    #[arg(short, long, default_value = "100")]
    threads: usize,

    #[arg(short, long)]
    ports: Option<String>,

    #[arg(long, default_value = "2000")]
    timeout: u64,

    #[arg(long)]
    scan_dead: bool,

    #[arg(long)]
    auto_start: bool,

    #[arg(long)]
    auto_quit: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let args = Args::parse();

    let config = Arc::new(ScannerConfig {
        max_threads: args.threads,
        ping_timeout_ms: args.timeout,
        scan_dead_hosts: args.scan_dead,
        port_string: args
            .ports
            .clone()
            .unwrap_or_else(|| "80,443,8080".to_string()),
        use_requested_ports: args.ports.is_some(),
        ping_count: 3,
        port_timeout_ms: 500,
        min_port_timeout_ms: 100,
        adapt_port_timeout: true,
    });

    let fetcher_registry = Arc::new(RwLock::new(FetcherRegistry::new()));
    fetcher_registry
        .write()
        .await
        .register_default_fetchers(config.clone());

    let scanner = Scanner::new(fetcher_registry.clone(), config.clone());

    if let (Some(start), Some(end)) = (args.start, args.end) {
        let feeder = Box::new(RangeFeeder::new(start, end)?);

        if args.auto_start {
            info!("Starting scan from {} to {}", start, end);
            scanner.scan(feeder).await?;

            if args.auto_quit {
                info!("Scan completed, exiting");
            }
        }
    } else {
        error!("Please specify start and end IP addresses");
    }

    Ok(())
}
