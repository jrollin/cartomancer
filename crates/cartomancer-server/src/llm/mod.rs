//! LLM provider abstraction for finding deepening.
//!
//! Supports multiple backends:
//! - Ollama (local, default for dev/testing)
//! - Anthropic (production)

pub mod anthropic;
pub mod ollama;

use anyhow::Result;
use async_trait::async_trait;

use cartomancer_core::config::LlmConfig;
use cartomancer_core::finding::Finding;

/// Trait for LLM providers that can deepen findings with analysis.
#[async_trait]
pub trait LlmProvider: Send + Sync {
    /// Provider name (e.g. "ollama", "anthropic").
    fn name(&self) -> &str;

    /// Verify connectivity and model availability. Call before the pipeline
    /// to fail fast instead of discovering issues mid-scan.
    async fn health_check(&self) -> Result<()>;

    /// Send a prompt and return the completion text.
    async fn complete(&self, prompt: &str) -> Result<String>;

    /// Deepen a finding by generating LLM analysis from its context.
    async fn deepen(&self, finding: &mut Finding) -> Result<()> {
        let prompt = build_deepening_prompt(finding);
        let raw = self.complete(&prompt).await?;
        let (analysis, fix) = parse_llm_response(&raw);
        finding.llm_analysis = Some(analysis);
        if let Some(ref fix) = fix {
            finding.agent_prompt = Some(build_agent_prompt(finding, fix));
        }
        finding.suggested_fix = fix;
        Ok(())
    }
}

/// Create a provider from configuration.
pub fn create_provider(config: &LlmConfig) -> Result<Box<dyn LlmProvider>> {
    match config.provider {
        cartomancer_core::config::LlmBackend::Ollama => {
            let base_url = config
                .ollama_base_url
                .as_deref()
                .unwrap_or("http://localhost:11434");
            let model = config.ollama_model.as_deref().unwrap_or("gemma4");
            Ok(Box::new(ollama::OllamaProvider::new(base_url, model)))
        }
        cartomancer_core::config::LlmBackend::Anthropic => {
            let api_key = config
                .anthropic_api_key
                .clone()
                .or_else(|| std::env::var("ANTHROPIC_API_KEY").ok())
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "Anthropic API key required: set llm.anthropic_api_key or ANTHROPIC_API_KEY"
                    )
                })?;
            let model = config
                .anthropic_model
                .as_deref()
                .unwrap_or("claude-sonnet-4-20250514");
            Ok(Box::new(anthropic::AnthropicProvider::new(
                &api_key,
                model,
                config.max_tokens,
            )))
        }
    }
}

/// Build the deepening prompt for a finding with its graph context.
pub fn build_deepening_prompt(finding: &Finding) -> String {
    let mut prompt = format!(
        "Analyze this code finding and explain its impact.\n\n\
         ## Finding\n\
         Rule: {}\n\
         Message: {}\n\
         Severity: {}\n\
         File: {}:{}\n\
         Code: {}\n",
        finding.rule_id,
        finding.message,
        finding.severity,
        finding.file_path,
        finding.start_line,
        finding.snippet,
    );

    if let Some(enclosing) = &finding.enclosing_context {
        let truncated = if enclosing.len() > 2000 {
            // Find a valid UTF-8 char boundary at or before byte 2000
            let boundary = enclosing[..2000]
                .char_indices()
                .next_back()
                .map(|(i, c)| i + c.len_utf8())
                .unwrap_or(0);
            format!("{} [truncated]", &enclosing[..boundary])
        } else {
            enclosing.clone()
        };
        prompt.push_str(&format!("\n## Enclosing Function\n```\n{truncated}\n```\n"));
    }

    if let Some(ctx) = &finding.graph_context {
        prompt.push_str(&format!(
            "\n## Structural Context\n\
             Symbol: {}\n\
             Blast radius: {} symbols affected\n\
             Callers ({}):\n",
            ctx.symbol_name.as_deref().unwrap_or("unknown"),
            ctx.blast_radius,
            ctx.callers.len(),
        ));
        for caller in ctx.callers.iter().take(10) {
            prompt.push_str(&format!("  - {caller}\n"));
        }
        if !ctx.domain_tags.is_empty() {
            prompt.push_str(&format!("Domain: {}\n", ctx.domain_tags.join(", ")));
        }
    }

    prompt.push_str(
        "\n## Task\n\
         First, explain why this finding matters given the callers and blast radius above.\n\
         Be concise (2-3 sentences). Focus on the real-world impact.\n\n\
         Then, provide a suggested fix inside a ```diff fenced code block.\n\
         If no fix is appropriate, omit the diff block.",
    );

    prompt
}

/// Parse LLM response into analysis text and optional suggested fix.
/// Looks for the first ```diff ... ``` fenced block.
/// Everything outside the fence is analysis text.
pub fn parse_llm_response(response: &str) -> (String, Option<String>) {
    let fence_start_markers = ["```diff\n", "```diff\r\n"];
    let mut fence_start = None;
    let mut marker_len = 0;

    for marker in &fence_start_markers {
        if let Some(pos) = response.find(marker) {
            if fence_start.is_none() || pos < fence_start.unwrap() {
                fence_start = Some(pos);
                marker_len = marker.len();
            }
        }
    }

    let Some(start_pos) = fence_start else {
        return (response.trim().to_string(), None);
    };

    let content_start = start_pos + marker_len;

    // Line-aware search: only match closing ``` that appears on its own line
    let mut closing_offset = None;
    let mut offset = 0;
    for line in response[content_start..].split_inclusive('\n') {
        if line.trim() == "```" {
            closing_offset = Some(offset);
            break;
        }
        offset += line.len();
    }

    let Some(closing_offset) = closing_offset else {
        // No closing fence: treat entire response as analysis
        return (response.trim().to_string(), None);
    };

    let fix = &response[content_start..content_start + closing_offset];
    let fence_end = content_start + closing_offset + 3;

    let before = response[..start_pos].trim();
    let after = response[fence_end..].trim();

    let analysis = match (before.is_empty(), after.is_empty()) {
        (true, true) => String::new(),
        (false, true) => before.to_string(),
        (true, false) => after.to_string(),
        (false, false) => format!("{before}\n\n{after}"),
    };

    let fix_str = fix.to_string();
    let fix_opt = if fix_str.trim().is_empty() {
        None
    } else {
        Some(fix_str)
    };
    (analysis, fix_opt)
}

/// Build a self-contained prompt for AI agents to apply a fix.
pub fn build_agent_prompt(finding: &Finding, suggested_fix: &str) -> String {
    let mut prompt = format!(
        "In `@{file_path}` around lines {start}-{end}, {message}. Rule: {rule}.",
        file_path = finding.file_path,
        start = finding.start_line,
        end = finding.end_line,
        message = finding.message,
        rule = finding.rule_id,
    );

    prompt.push_str(&format!(" Severity: {}.", finding.severity));

    if let Some(ref cwe) = finding.cwe {
        prompt.push_str(&format!(" CWE: {cwe}."));
    }

    prompt.push_str(&format!(
        " Apply this fix:\n\n```diff\n{suggested_fix}\n```"
    ));

    prompt
}

#[cfg(test)]
mod tests {
    use super::*;
    use cartomancer_core::severity::Severity;

    fn make_finding() -> Finding {
        Finding {
            rule_id: "test.rule".into(),
            message: "test message".into(),
            severity: Severity::Error,
            file_path: "src/lib.rs".into(),
            start_line: 10,
            end_line: 12,
            snippet: "let x = dangerous();".into(),
            cwe: None,
            graph_context: None,
            llm_analysis: None,
            escalation_reasons: vec![],
            is_new: None,
            enclosing_context: None,
            suggested_fix: None,
            agent_prompt: None,
        }
    }

    #[test]
    fn build_prompt_includes_finding_details() {
        let f = make_finding();
        let prompt = build_deepening_prompt(&f);
        assert!(prompt.contains("test.rule"));
        assert!(prompt.contains("test message"));
        assert!(prompt.contains("src/lib.rs:10"));
        assert!(prompt.contains("let x = dangerous();"));
    }

    #[test]
    fn build_prompt_with_enclosing_context() {
        let mut f = make_finding();
        f.enclosing_context = Some("fn handler() {\n    let x = dangerous();\n}".into());
        let prompt = build_deepening_prompt(&f);
        assert!(prompt.contains("## Enclosing Function"));
        assert!(prompt.contains("fn handler()"));
    }

    #[test]
    fn build_prompt_without_enclosing_context() {
        let f = make_finding();
        let prompt = build_deepening_prompt(&f);
        assert!(!prompt.contains("Enclosing Function"));
    }

    #[test]
    fn build_prompt_truncates_long_enclosing_context() {
        let mut f = make_finding();
        let long_ctx = "x".repeat(3000);
        f.enclosing_context = Some(long_ctx);
        let prompt = build_deepening_prompt(&f);
        assert!(prompt.contains("[truncated]"));
        // The 2000-char prefix should be present
        assert!(prompt.contains(&"x".repeat(2000)));
        // But not the full 3000
        assert!(!prompt.contains(&"x".repeat(2001)));
    }

    #[test]
    fn parse_response_with_diff_block() {
        let response = "This is dangerous because of SQL injection.\n\n\
                        ```diff\n\
                        -let q = format!(\"SELECT * FROM t WHERE id={}\", id);\n\
                        +let q = sqlx::query(\"SELECT * FROM t WHERE id=?\").bind(id);\n\
                        ```\n\
                        Some trailing note.";
        let (analysis, fix) = parse_llm_response(response);
        assert!(analysis.contains("SQL injection"));
        assert!(analysis.contains("trailing note"));
        let fix = fix.expect("should have a fix");
        assert!(fix.contains("-let q = format!"));
        assert!(fix.contains("+let q = sqlx::query"));
    }

    #[test]
    fn parse_response_without_diff_block() {
        let response = "This finding has low impact, no fix needed.";
        let (analysis, fix) = parse_llm_response(response);
        assert_eq!(analysis, "This finding has low impact, no fix needed.");
        assert!(fix.is_none());
    }

    #[test]
    fn parse_response_with_empty_diff_block() {
        let response = "Analysis here.\n\n```diff\n```";
        let (analysis, fix) = parse_llm_response(response);
        assert_eq!(analysis, "Analysis here.");
        assert!(fix.is_none(), "empty diff block should normalize to None");
    }

    #[test]
    fn parse_response_with_text_before_and_after_diff() {
        let response = "Before text.\n\n```diff\n-old\n+new\n```\n\nAfter text.";
        let (analysis, fix) = parse_llm_response(response);
        assert!(analysis.contains("Before text."));
        assert!(analysis.contains("After text."));
        let fix = fix.unwrap();
        assert!(fix.contains("-old"));
        assert!(fix.contains("+new"));
    }

    #[test]
    fn parse_response_backticks_inside_diff_not_treated_as_closing() {
        let response = "Analysis.\n\n```diff\n-let s = \"```\";\n+let s = \"fixed\";\n```\n";
        let (analysis, fix) = parse_llm_response(response);
        assert_eq!(analysis, "Analysis.");
        let fix = fix.expect("should extract diff");
        assert!(fix.contains("-let s = \"```\";"));
        assert!(fix.contains("+let s = \"fixed\";"));
    }

    #[test]
    fn build_agent_prompt_includes_required_fields() {
        let f = make_finding();
        let fix = "-old line\n+new line";
        let prompt = build_agent_prompt(&f, fix);
        assert!(prompt.contains("@src/lib.rs"));
        assert!(prompt.contains("lines 10-12"));
        assert!(prompt.contains("test.rule"));
        assert!(prompt.contains("test message"));
        assert!(prompt.contains("```diff\n-old line\n+new line\n```"));
        assert!(prompt.contains("Severity: error"));
    }

    #[test]
    fn build_agent_prompt_includes_cwe_when_present() {
        let mut f = make_finding();
        f.cwe = Some("CWE-89".into());
        let prompt = build_agent_prompt(&f, "-old\n+new");
        assert!(prompt.contains("CWE: CWE-89"));
    }

    #[test]
    fn build_prompt_truncates_multibyte_utf8_safely() {
        let mut f = make_finding();
        // 'é' is 2 bytes in UTF-8; fill so byte 2000 falls mid-character
        let ctx = "é".repeat(1500); // 3000 bytes, 1500 chars
        f.enclosing_context = Some(ctx);
        // Must not panic
        let prompt = build_deepening_prompt(&f);
        assert!(prompt.contains("[truncated]"));
    }

    #[test]
    fn build_prompt_truncates_4byte_emoji_safely() {
        let mut f = make_finding();
        // '🔥' is 4 bytes in UTF-8; 501 emojis = 2004 bytes, boundary at 2000 = mid-char
        let ctx = "🔥".repeat(501);
        assert_eq!(ctx.len(), 2004);
        f.enclosing_context = Some(ctx);
        // Must not panic
        let prompt = build_deepening_prompt(&f);
        assert!(prompt.contains("[truncated]"));
        // Should contain exactly 500 emojis (2000 bytes)
        assert!(prompt.contains(&"🔥".repeat(500)));
    }

    #[test]
    fn parse_response_multiple_diff_blocks_takes_first() {
        let response = "Analysis.\n\n```diff\n-first\n+fixed\n```\n\nMore text.\n\n```diff\n-second\n+also fixed\n```";
        let (analysis, fix) = parse_llm_response(response);
        let fix = fix.expect("should extract first diff");
        assert!(fix.contains("-first"));
        assert!(!fix.contains("-second"));
        assert!(analysis.contains("Analysis."));
    }

    /// Mock provider that returns a fixed response for testing the deepen trait method.
    struct MockProvider {
        response: String,
    }

    #[async_trait::async_trait]
    impl LlmProvider for MockProvider {
        fn name(&self) -> &str {
            "mock"
        }
        async fn health_check(&self) -> anyhow::Result<()> {
            Ok(())
        }
        async fn complete(&self, _prompt: &str) -> anyhow::Result<String> {
            Ok(self.response.clone())
        }
    }

    #[tokio::test]
    async fn deepen_trait_method_parses_and_populates_fields() {
        let provider = MockProvider {
            response: "This is dangerous.\n\n```diff\n-old\n+new\n```\n".into(),
        };
        let mut f = make_finding();
        provider.deepen(&mut f).await.unwrap();

        assert_eq!(f.llm_analysis.as_deref(), Some("This is dangerous."));
        assert_eq!(f.suggested_fix.as_deref(), Some("-old\n+new\n"));
        assert!(f.agent_prompt.is_some());
        assert!(f.agent_prompt.as_ref().unwrap().contains("@src/lib.rs"));
    }

    #[tokio::test]
    async fn deepen_trait_method_no_fix_leaves_fields_none() {
        let provider = MockProvider {
            response: "Low impact, no fix needed.".into(),
        };
        let mut f = make_finding();
        provider.deepen(&mut f).await.unwrap();

        assert_eq!(
            f.llm_analysis.as_deref(),
            Some("Low impact, no fix needed.")
        );
        assert!(f.suggested_fix.is_none());
        assert!(f.agent_prompt.is_none());
    }
}
