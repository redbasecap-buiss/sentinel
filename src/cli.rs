use clap::{Parser, Subcommand};
use sentinel::connection::ConnectionTracker;
use sentinel::detect::DetectionEngine;
use sentinel::packet::ParsedPacket;
use sentinel::pcap;
use sentinel::rule;
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "sentinel",
    version,
    about = "Lightweight network IDS in pure Rust"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Monitor a network interface for threats
    Monitor {
        /// Network interface name
        #[arg(short, long)]
        interface: String,
        /// Path to rules file
        #[arg(short, long)]
        rules: Option<PathBuf>,
        /// Enable verbose output
        #[arg(short, long)]
        verbose: bool,
    },
    /// Analyze a pcap capture file
    Analyze {
        /// Path to pcap file
        path: PathBuf,
        /// Path to rules file
        #[arg(short, long)]
        rules: Option<PathBuf>,
        /// Show connection summary
        #[arg(short, long)]
        connections: bool,
    },
    /// Manage detection rules
    Rules {
        #[command(subcommand)]
        action: RulesAction,
    },
}

#[derive(Subcommand)]
pub enum RulesAction {
    /// List all loaded rules
    List {
        /// Path to rules file
        #[arg(short, long)]
        path: Option<PathBuf>,
    },
    /// Validate a rules file
    Validate {
        /// Path to rules file
        path: PathBuf,
    },
}

pub fn parse() -> Cli {
    Cli::parse()
}

pub fn run(cli: Cli) {
    match cli.command {
        Command::Monitor {
            interface,
            rules,
            verbose,
        } => {
            println!("Monitoring interface: {interface}");
            if let Some(rules_path) = rules {
                match rule::load_rules_file(&rules_path) {
                    Ok(rules) => println!("Loaded {} rules", rules.len()),
                    Err(e) => eprintln!("Failed to load rules: {e}"),
                }
            }
            if verbose {
                println!("Verbose mode enabled");
            }
        }
        Command::Analyze {
            path,
            rules,
            connections,
        } => {
            // Read pcap
            let pcap_file = match pcap::read_pcap(&path) {
                Ok(f) => f,
                Err(e) => {
                    eprintln!("Failed to read pcap: {e}");
                    std::process::exit(1);
                }
            };
            println!(
                "Loaded {} packets from {}",
                pcap_file.records.len(),
                path.display()
            );

            // Load rules if provided
            let engine = rules.and_then(|rules_path| match rule::load_rules_file(&rules_path) {
                Ok(rules) => {
                    println!("Loaded {} rules", rules.len());
                    Some(DetectionEngine::new(rules))
                }
                Err(e) => {
                    eprintln!("Failed to load rules: {e}");
                    None
                }
            });

            let mut tracker = ConnectionTracker::new();
            let mut total_alerts = 0;

            for (i, record) in pcap_file.records.iter().enumerate() {
                match ParsedPacket::parse(&record.data) {
                    Ok(packet) => {
                        tracker.track(&packet, record.ts_sec as u64);

                        if let Some(ref eng) = engine {
                            let alerts = eng.check(&packet);
                            for alert in &alerts {
                                println!("{}", alert.colored_string());
                            }
                            total_alerts += alerts.len();
                        }
                    }
                    Err(e) => {
                        eprintln!("Packet {i}: parse error: {e}");
                    }
                }
            }

            println!("\n--- Summary ---");
            println!("Packets: {}", pcap_file.records.len());
            println!("Alerts:  {total_alerts}");
            println!("Flows:   {}", tracker.flow_count());

            if connections {
                println!("\n--- Top Flows (by bytes) ---");
                for (key, stats) in tracker.top_flows_by_bytes(10) {
                    println!(
                        "  {key}  pkts={} bytes={} state={}",
                        stats.packets, stats.bytes, stats.tcp_state
                    );
                }
            }
        }
        Command::Rules { action } => match action {
            RulesAction::List { path } => {
                let rules_path = path.unwrap_or_else(|| "rules.toml".into());
                match rule::load_rules_file(&rules_path) {
                    Ok(rules) => {
                        for r in &rules {
                            println!("{r}");
                        }
                    }
                    Err(e) => eprintln!("Failed to load rules: {e}"),
                }
            }
            RulesAction::Validate { path } => match rule::load_rules_file(&path) {
                Ok(rules) => println!("✓ Valid — {} rules loaded", rules.len()),
                Err(e) => eprintln!("✗ Invalid: {e}"),
            },
        },
    }
}
