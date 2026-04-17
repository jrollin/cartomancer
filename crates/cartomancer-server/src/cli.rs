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

    /// Output as JSON
    #[arg(long, global = true)]
    pub json: bool,
}

#[derive(Subcommand)]
pub enum Command {
    /// Scan a local directory (no GitHub needed)
    Scan {
        /// Directory to scan (default: current directory)
        #[arg(default_value = ".")]
        path: String,
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
    Dismissed,
    /// Remove a dismissal
    Undismiss {
        /// Dismissal ID (from dismissed output)
        dismissal_id: i64,
    },
    /// Check that all dependencies and configuration are valid
    Doctor,
    /// Scaffold a commented .cartomancer.toml in the current directory
    Init {
        /// Overwrite an existing config file
        #[arg(long)]
        force: bool,
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
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn cli_json_defaults_to_false() {
        let cli = Cli::try_parse_from(["cartomancer", "doctor"]).unwrap();
        assert!(!cli.json);
    }

    #[test]
    fn cli_json_global_flag() {
        let cli = Cli::try_parse_from(["cartomancer", "--json", "doctor"]).unwrap();
        assert!(cli.json);
    }

    #[test]
    fn cli_json_after_subcommand() {
        let cli = Cli::try_parse_from(["cartomancer", "doctor", "--json"]).unwrap();
        assert!(cli.json);
    }

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
            } => {
                assert_eq!(repo, "owner/repo");
                assert_eq!(pr, 42);
                assert!(work_dir.is_none());
                assert!(!dry_run);
                assert!(resume.is_none());
                assert!(!cli.json);
            }
            _ => panic!("expected Review command"),
        }
    }

    #[test]
    fn cli_parse_review_with_all_flags() {
        let cli = Cli::try_parse_from([
            "cartomancer",
            "--json",
            "review",
            "owner/repo",
            "7",
            "--work-dir",
            "/tmp/repo",
            "--dry-run",
            "--resume",
            "42",
        ])
        .unwrap();
        match cli.command {
            Command::Review {
                repo,
                pr,
                work_dir,
                dry_run,
                resume,
            } => {
                assert_eq!(repo, "owner/repo");
                assert_eq!(pr, 7);
                assert_eq!(work_dir.as_deref(), Some("/tmp/repo"));
                assert!(dry_run);
                assert_eq!(resume, Some(42));
                assert!(cli.json);
            }
            _ => panic!("expected Review command"),
        }
    }

    #[test]
    fn cli_parse_scan_with_json() {
        let cli = Cli::try_parse_from(["cartomancer", "scan", ".", "--json"]).unwrap();
        assert!(matches!(cli.command, Command::Scan { .. }));
        assert!(cli.json);
    }

    #[test]
    fn cli_parse_history_defaults() {
        let cli = Cli::try_parse_from(["cartomancer", "history"]).unwrap();
        match cli.command {
            Command::History { branch } => {
                assert!(branch.is_none());
                assert!(!cli.json);
            }
            _ => panic!("expected History command"),
        }
    }

    #[test]
    fn cli_parse_history_with_branch() {
        let cli =
            Cli::try_parse_from(["cartomancer", "history", "--branch", "main", "--json"]).unwrap();
        match cli.command {
            Command::History { branch } => {
                assert_eq!(branch.as_deref(), Some("main"));
                assert!(cli.json);
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
        let cli = Cli::try_parse_from(["cartomancer", "dismissed", "--json"]).unwrap();
        assert!(matches!(cli.command, Command::Dismissed));
        assert!(cli.json);
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
    fn cli_parse_doctor_defaults() {
        let cli = Cli::try_parse_from(["cartomancer", "doctor"]).unwrap();
        assert!(matches!(cli.command, Command::Doctor));
        assert!(!cli.json);
    }

    #[test]
    fn cli_parse_doctor_json() {
        let cli = Cli::try_parse_from(["cartomancer", "doctor", "--json"]).unwrap();
        assert!(matches!(cli.command, Command::Doctor));
        assert!(cli.json);
    }

    #[test]
    fn cli_review_repo_is_positional() {
        let result = Cli::try_parse_from(["cartomancer", "review", "--repo", "a/b", "--pr", "1"]);
        assert!(result.is_err());
    }
}
