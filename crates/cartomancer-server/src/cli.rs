//! Clap CLI definitions.

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "cartomancer", about = "PR review with blast radius awareness")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,

    /// Path to config file
    #[arg(long, env = "CARTOMANCER_CONFIG", default_value = ".cartomancer.toml")]
    pub config: String,
}

#[derive(Subcommand)]
pub enum Command {
    /// Scan a local directory (no GitHub needed)
    Scan {
        /// Directory to scan (default: current directory)
        #[arg(default_value = ".")]
        path: String,

        /// Output format
        #[arg(long, default_value = "text")]
        format: OutputFormat,
    },
    /// Start the webhook server
    Serve {
        /// Port to listen on
        #[arg(long, env = "CARTOMANCER_PORT", default_value = "3000")]
        port: u16,
    },
    /// Review a PR by number (one-shot mode)
    Review {
        /// Repository (owner/repo)
        #[arg(long)]
        repo: String,
        /// PR number
        #[arg(long)]
        pr: u64,
    },
}

#[derive(Clone, clap::ValueEnum)]
pub enum OutputFormat {
    Text,
    Json,
}
