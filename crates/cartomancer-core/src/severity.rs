//! Severity levels with escalation support.

use std::fmt;

use serde::{Deserialize, Serialize};

/// Severity level for a finding, ordered from lowest to highest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Warning,
    Error,
    Critical,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Info => write!(f, "info"),
            Self::Warning => write!(f, "warning"),
            Self::Error => write!(f, "error"),
            Self::Critical => write!(f, "critical"),
        }
    }
}

impl std::str::FromStr for Severity {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "info" => Ok(Self::Info),
            "warning" => Ok(Self::Warning),
            "error" => Ok(Self::Error),
            "critical" => Ok(Self::Critical),
            other => Err(format!("unknown severity: '{other}'")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_ordering() {
        assert!(Severity::Info < Severity::Warning);
        assert!(Severity::Warning < Severity::Error);
        assert!(Severity::Error < Severity::Critical);
    }

    #[test]
    fn severity_display() {
        assert_eq!(Severity::Critical.to_string(), "critical");
        assert_eq!(Severity::Info.to_string(), "info");
    }

    #[test]
    fn severity_from_str() {
        assert_eq!("info".parse::<Severity>(), Ok(Severity::Info));
        assert_eq!("WARNING".parse::<Severity>(), Ok(Severity::Warning));
        assert_eq!("Error".parse::<Severity>(), Ok(Severity::Error));
        assert_eq!("CRITICAL".parse::<Severity>(), Ok(Severity::Critical));
        assert!("unknown".parse::<Severity>().is_err());
    }
}
