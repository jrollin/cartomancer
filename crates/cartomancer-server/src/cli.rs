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
    /// Browse scan history
    History {
        /// Filter by branch name
        #[arg(long)]
        branch: Option<String>,

        /// Output format
        #[arg(long, default_value = "text")]
        format: OutputFormat,
    },
    /// Browse findings for a scan or search across scans
    Findings {
        /// Scan ID to show findings for (omit to search across scans)
        scan_id: Option<i64>,

        /// Filter by rule_id (substring match)
        #[arg(long)]
        rule: Option<String>,

        /// Filter by minimum severity
        #[arg(long)]
        severity: Option<String>,

        /// Filter by file path (substring match)
        #[arg(long)]
        file: Option<String>,

        /// Filter by branch name
        #[arg(long)]
        branch: Option<String>,

        /// Output format
        #[arg(long, default_value = "text")]
        format: OutputFormat,
    },
    /// Dismiss a finding as false positive
    Dismiss {
        /// Scan ID containing the finding
        scan_id: i64,

        /// Finding index (1-based, from findings output)
        finding_index: usize,

        /// Reason for dismissal
        #[arg(long)]
        reason: Option<String>,
    },
    /// List all dismissed findings
    Dismissed {
        /// Output format
        #[arg(long, default_value = "text")]
        format: OutputFormat,
    },
    /// Remove a dismissal
    Undismiss {
        /// Dismissal ID (from dismissed output)
        dismissal_id: i64,
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

        /// Resume a previously failed scan from its last completed stage
        #[arg(long)]
        resume: Option<i64>,

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
                resume,
                ..
            } => {
                assert_eq!(repo, "owner/repo");
                assert_eq!(pr, 42);
                assert!(work_dir.is_none());
                assert!(!dry_run);
                assert!(resume.is_none());
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
            "--resume",
            "42",
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
                resume,
                format,
            } => {
                assert_eq!(repo, "owner/repo");
                assert_eq!(pr, 7);
                assert_eq!(work_dir.as_deref(), Some("/tmp/repo"));
                assert!(dry_run);
                assert_eq!(resume, Some(42));
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
    fn cli_parse_history_defaults() {
        let cli = Cli::try_parse_from(["cartomancer", "history"]).unwrap();
        match cli.command {
            Command::History { branch, format } => {
                assert!(branch.is_none());
                assert!(matches!(format, OutputFormat::Text));
            }
            _ => panic!("expected History command"),
        }
    }

    #[test]
    fn cli_parse_history_with_branch() {
        let cli = Cli::try_parse_from([
            "cartomancer",
            "history",
            "--branch",
            "main",
            "--format",
            "json",
        ])
        .unwrap();
        match cli.command {
            Command::History { branch, format } => {
                assert_eq!(branch.as_deref(), Some("main"));
                assert!(matches!(format, OutputFormat::Json));
            }
            _ => panic!("expected History command"),
        }
    }

    #[test]
    fn cli_parse_findings_by_scan_id() {
        let cli = Cli::try_parse_from(["cartomancer", "findings", "42"]).unwrap();
        match cli.command {
            Command::Findings { scan_id, .. } => {
                assert_eq!(scan_id, Some(42));
            }
            _ => panic!("expected Findings command"),
        }
    }

    #[test]
    fn cli_parse_findings_with_filters() {
        let cli = Cli::try_parse_from([
            "cartomancer",
            "findings",
            "--rule",
            "sql",
            "--severity",
            "error",
            "--file",
            "auth",
            "--branch",
            "main",
        ])
        .unwrap();
        match cli.command {
            Command::Findings {
                scan_id,
                rule,
                severity,
                file,
                branch,
                ..
            } => {
                assert!(scan_id.is_none());
                assert_eq!(rule.as_deref(), Some("sql"));
                assert_eq!(severity.as_deref(), Some("error"));
                assert_eq!(file.as_deref(), Some("auth"));
                assert_eq!(branch.as_deref(), Some("main"));
            }
            _ => panic!("expected Findings command"),
        }
    }

    #[test]
    fn cli_parse_dismiss() {
        let cli = Cli::try_parse_from([
            "cartomancer",
            "dismiss",
            "1",
            "3",
            "--reason",
            "false positive",
        ])
        .unwrap();
        match cli.command {
            Command::Dismiss {
                scan_id,
                finding_index,
                reason,
            } => {
                assert_eq!(scan_id, 1);
                assert_eq!(finding_index, 3);
                assert_eq!(reason.as_deref(), Some("false positive"));
            }
            _ => panic!("expected Dismiss command"),
        }
    }

    #[test]
    fn cli_parse_dismissed() {
        let cli = Cli::try_parse_from(["cartomancer", "dismissed", "--format", "json"]).unwrap();
        match cli.command {
            Command::Dismissed { format } => {
                assert!(matches!(format, OutputFormat::Json));
            }
            _ => panic!("expected Dismissed command"),
        }
    }

    #[test]
    fn cli_parse_undismiss() {
        let cli = Cli::try_parse_from(["cartomancer", "undismiss", "5"]).unwrap();
        match cli.command {
            Command::Undismiss { dismissal_id } => {
                assert_eq!(dismissal_id, 5);
            }
            _ => panic!("expected Undismiss command"),
        }
    }

    #[test]
    fn cli_review_repo_is_positional() {
        // repo and pr are positional, not --repo/--pr
        let result = Cli::try_parse_from(["cartomancer", "review", "--repo", "a/b", "--pr", "1"]);
        // This should fail since repo/pr are now positional
        assert!(result.is_err());
    }
}
