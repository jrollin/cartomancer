//! Clap CLI definitions.

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "cartomancer",
    version,
    about = "PR review with blast radius awareness"
)]
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
    /// Review a GitHub PR (one-shot mode)
    Review {
        /// Repository (owner/repo)
        repo: String,

        /// PR number
        pr: u64,

        /// Working directory: reuse existing checkout or clone into this path.
        /// If omitted, clones to a temporary directory (auto-cleaned).
        #[arg(long)]
        work_dir: Option<String>,

        /// Output the ReviewResult JSON without posting to GitHub
        #[arg(long)]
        dry_run: bool,

        /// Output format
        #[arg(long, default_value = "text")]
        format: OutputFormat,
    },
}

#[derive(Debug, Clone, clap::ValueEnum)]
pub enum OutputFormat {
    Text,
    Json,
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn cli_parse_review_minimal() {
        let cli = Cli::try_parse_from(["cartomancer", "review", "owner/repo", "42"]).unwrap();
        match cli.command {
            Command::Review {
                repo,
                pr,
                work_dir,
                dry_run,
                ..
            } => {
                assert_eq!(repo, "owner/repo");
                assert_eq!(pr, 42);
                assert!(work_dir.is_none());
                assert!(!dry_run);
            }
            _ => panic!("expected Review command"),
        }
    }

    #[test]
    fn cli_parse_review_with_all_flags() {
        let cli = Cli::try_parse_from([
            "cartomancer",
            "review",
            "owner/repo",
            "7",
            "--work-dir",
            "/tmp/repo",
            "--dry-run",
            "--format",
            "json",
        ])
        .unwrap();
        match cli.command {
            Command::Review {
                repo,
                pr,
                work_dir,
                dry_run,
                format,
            } => {
                assert_eq!(repo, "owner/repo");
                assert_eq!(pr, 7);
                assert_eq!(work_dir.as_deref(), Some("/tmp/repo"));
                assert!(dry_run);
                assert!(matches!(format, OutputFormat::Json));
            }
            _ => panic!("expected Review command"),
        }
    }

    #[test]
    fn cli_parse_scan_still_works() {
        let cli = Cli::try_parse_from(["cartomancer", "scan", ".", "--format", "json"]).unwrap();
        assert!(matches!(cli.command, Command::Scan { .. }));
    }

    #[test]
    fn cli_review_repo_is_positional() {
        // repo and pr are positional, not --repo/--pr
        let result = Cli::try_parse_from(["cartomancer", "review", "--repo", "a/b", "--pr", "1"]);
        // This should fail since repo/pr are now positional
        assert!(result.is_err());
    }
}
