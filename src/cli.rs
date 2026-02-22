use clap::{Parser, Subcommand};
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
        Command::Analyze { path, rules } => {
            println!("Analyzing: {}", path.display());
            if let Some(rules_path) = rules {
                match rule::load_rules_file(&rules_path) {
                    Ok(rules) => println!("Loaded {} rules", rules.len()),
                    Err(e) => eprintln!("Failed to load rules: {e}"),
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
