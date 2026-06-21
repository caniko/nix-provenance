//! Apply result parsing.
//!
//! Parses `stalwart-cli apply` stdout to extract structured operation counts
//! and error details. This enables the provisioner to report exactly what
//! changed and which operations failed.

use std::path::Path;

use anyhow::{Context, Result};

use crate::recovery::{ApplyResult, apply_document};

/// Structured result of applying a plan document.
#[derive(Debug, Default)]
pub struct PlanResult {
    pub success: bool,
    pub created: usize,
    pub updated: usize,
    pub destroyed: usize,
    pub failed: usize,
    pub errors: Vec<String>,
}

/// Apply a plan document and parse the output into structured counts.
pub fn apply_plan(
    cli_binary: &Path,
    url: &str,
    username: &str,
    password: &str,
    plan_file: &Path,
    continue_on_error: bool,
) -> Result<PlanResult> {
    let result = apply_document(
        cli_binary,
        url,
        username,
        password,
        plan_file,
        continue_on_error,
    )
    .context(format!("applying plan from {}", plan_file.display()))?;

    Ok(parse_apply_output(&result))
}

/// Parse stalwart-cli apply output into a structured result.
///
/// Expected output lines:
///   ✓ created NetworkListener (4)
///   ✓ updated Authentication (1)
///   ✓ destroyed NetworkListener (1)
///   ✗ create AcmeProvider: ... failed ...
fn parse_apply_output(result: &ApplyResult) -> PlanResult {
    let mut plan = PlanResult {
        success: result.exit_code == 0,
        ..Default::default()
    };

    // Parse the "Done:" summary line if present
    for line in result.stderr.lines().chain(result.stdout.lines()) {
        let line = line.trim();

        // Parse individual operation results
        if line.contains("created") && line.contains('✓') {
            plan.created += parse_count(line);
        } else if line.contains("updated") && line.contains('✓') {
            plan.updated += parse_count(line);
        } else if line.contains("destroyed") && line.contains('✓') {
            plan.destroyed += parse_count(line);
        } else if line.contains('✗') {
            plan.failed += 1;
            plan.errors.push(line.to_string());
        }

        // Parse "Done: N destroyed, N updated, N created (N failed)" summary
        if let Some(done) = line.strip_prefix("Done:") {
            let done = done.trim();
            // Reset counts from summary if available (more accurate)
            plan.created = 0;
            plan.updated = 0;
            plan.destroyed = 0;
            plan.failed = 0;

            for part in done.split(',') {
                let part = part.trim();
                if let Some(n) = parse_count_pair(part, "created") {
                    plan.created = n;
                } else if let Some(n) = parse_count_pair(part, "updated") {
                    plan.updated = n;
                } else if let Some(n) = parse_count_pair(part, "destroyed") {
                    plan.destroyed = n;
                }
            }

            // Parse "(N failed)" at the end
            if let Some(failed_part) = done
                .strip_suffix(')')
                .and_then(|s| s.rfind('(').map(|i| &s[i + 1..]))
                && let Some(n) = parse_count_pair(failed_part, "failed")
            {
                plan.failed = n;
            }
        }
    }

    plan
}

/// Parse "N <word>" from a string, returning the count.
/// Handles trailing parenthesized suffixes like "(0 failed)".
fn parse_count_pair(s: &str, word: &str) -> Option<usize> {
    let s = s.trim();
    // Strip trailing parenthesized suffix, e.g. "(0 failed)"
    let s = if let Some(pos) = s.rfind('(') {
        s[..pos].trim()
    } else {
        s
    };
    s.strip_suffix(word)
        .and_then(|num_str| num_str.trim().parse().ok())
}

/// Extract a trailing parenthesized count like "(4)" from a line.
fn parse_count(line: &str) -> usize {
    line.rfind('(')
        .and_then(|start| {
            line[start + 1..]
                .find(')')
                .map(|end| &line[start + 1..start + 1 + end])
        })
        .and_then(|s| s.parse().ok())
        .unwrap_or(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_apply_output_success() {
        let result = ApplyResult {
            exit_code: 0,
            stdout: String::new(),
            stderr: "\
                ✓ destroyed NetworkListener (1)\n\
                ✓ destroyed NetworkListener (1)\n\
                ✓ destroyed NetworkListener (1)\n\
                ✓ destroyed NetworkListener (1)\n\
                ✓ created NetworkListener (4)\n\
                ✓ created Role (1)\n\
                ✓ created Directory (1)\n\
                ✓ updated Authentication (1)\n\
                ✓ updated Security (1)\n\
                ✓ created Tracer (1)\n\
                ✓ created DnsServer (1)\n\
                ✓ updated AcmeProvider (1)\n\
                ✓ created MtaRoute (1)\n\
                ✓ updated MtaOutboundStrategy (1)\n\
                Done: 4 destroyed, 4 updated, 7 created (0 failed)\n"
                .to_string(),
        };

        let plan = parse_apply_output(&result);
        assert!(plan.success);
        assert_eq!(plan.created, 7);
        assert_eq!(plan.updated, 4);
        assert_eq!(plan.destroyed, 4);
        assert_eq!(plan.failed, 0);
        assert!(plan.errors.is_empty());
    }

    #[test]
    fn test_parse_apply_output_failure() {
        let result = ApplyResult {
            exit_code: 1,
            stdout: String::new(),
            stderr: "\
                ✓ created Role (1)\n\
                ✓ created Directory (1)\n\
                ✓ created Tracer (1)\n\
                ✓ created DnsServer (1)\n\
                ✗ create AcmeProvider: AcmeProvider: create failed for `letsencrypt`: Rate limited\n\
                Done: 0 destroyed, 0 updated, 4 created (1 failed)\n"
                .to_string(),
        };

        let plan = parse_apply_output(&result);
        assert!(!plan.success);
        assert_eq!(plan.created, 4);
        assert_eq!(plan.failed, 1);
        assert_eq!(plan.errors.len(), 1);
        assert!(plan.errors[0].contains("AcmeProvider"));
    }

    #[test]
    fn test_parse_count() {
        assert_eq!(parse_count("✓ created NetworkListener (4)"), 4);
        assert_eq!(parse_count("✓ updated Authentication (1)"), 1);
        assert_eq!(parse_count("some random line"), 1);
    }

    #[test]
    fn test_parse_count_pair() {
        assert_eq!(parse_count_pair("4 created", "created"), Some(4));
        assert_eq!(parse_count_pair("0 failed", "failed"), Some(0));
        assert_eq!(parse_count_pair("4 created", "destroyed"), None);
    }
}
