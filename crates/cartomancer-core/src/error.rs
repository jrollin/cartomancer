//! Domain error types.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum CartomancerError {
    #[error("GitHub API error: {0}")]
    GitHub(String),

    #[error("Opengrep execution failed: {0}")]
    Opengrep(String),

    #[error("Cartog graph error: {0}")]
    Graph(String),

    #[error("LLM API error: {0}")]
    Llm(String),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Diff parsing error: {0}")]
    DiffParse(String),

    #[error("Pipeline error: {0}")]
    Pipeline(String),
}
