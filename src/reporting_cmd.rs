//! CLI report commands (`fozzy report ...`).

use clap::Subcommand;
use serde::{Deserialize, Serialize};

use std::path::PathBuf;

use crate::{render_html, render_junit_xml, Config, FozzyError, FozzyResult, Reporter, RunSummary, TraceFile};

#[derive(Debug, Subcommand)]
pub enum ReportCommand {
    Show {
        run: String,
        #[arg(long, default_value = "pretty")]
        format: Reporter,
    },
    Query {
        run: String,
        #[arg(long)]
        jq: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportEnvelope {
    pub format: Reporter,
    pub content: String,
}

pub fn report_command(config: &Config, command: &ReportCommand) -> FozzyResult<serde_json::Value> {
    match command {
        ReportCommand::Show { run, format } => {
            let summary = load_summary(config, run)?;
            match format {
                Reporter::Json => Ok(serde_json::to_value(summary)?),
                Reporter::Pretty => Ok(serde_json::to_value(ReportEnvelope { format: *format, content: summary.pretty() })?),
                Reporter::Junit => Ok(serde_json::to_value(ReportEnvelope {
                    format: *format,
                    content: render_junit_xml(&summary),
                })?),
                Reporter::Html => Ok(serde_json::to_value(ReportEnvelope { format: *format, content: render_html(&summary) })?),
            }
        }

        ReportCommand::Query { run, jq } => {
            let summary = load_summary(config, run)?;
            let value = serde_json::to_value(summary)?;
            query_value(&value, jq)
        }
    }
}

fn load_summary(config: &Config, run: &str) -> FozzyResult<RunSummary> {
    let artifacts_dir = crate::resolve_artifacts_dir(config, run)?;
    let report_json = artifacts_dir.join("report.json");
    if report_json.exists() {
        let bytes = std::fs::read(report_json)?;
        let summary: RunSummary = serde_json::from_slice(&bytes)?;
        return Ok(summary);
    }

    let input_path = PathBuf::from(run);
    let trace_path = if input_path.exists() {
        let is_trace = input_path
            .extension()
            .and_then(|s| s.to_str())
            .is_some_and(|s| s.eq_ignore_ascii_case("fozzy"));
        if !is_trace {
            return Err(FozzyError::Report(format!(
                "invalid run identifier {run:?}: expected run id or .fozzy trace path"
            )));
        }
        input_path
    } else {
        artifacts_dir.join("trace.fozzy")
    };
    if trace_path.exists() {
        let trace = TraceFile::read_json(&trace_path)?;
        return Ok(trace.summary);
    }

    Err(FozzyError::Report(format!(
        "no report found for {run:?} (looked for {} and {})",
        report_json.display(),
        trace_path.display()
    )))
}

fn query_value(root: &serde_json::Value, expr: &str) -> FozzyResult<serde_json::Value> {
    let expr = expr.trim();
    if expr == "." {
        return Ok(root.clone());
    }
    if !expr.starts_with('.') {
        return Err(FozzyError::Report(format!(
            "unsupported jq expression {expr:?}; supported forms: '.', '.a.b', '.arr[0]'"
        )));
    }

    let tokens = parse_expr(expr)?;
    let mut cur = root;
    for token in tokens {
        match token {
            QueryToken::Field(name) => {
                cur = cur.get(&name).ok_or_else(|| FozzyError::Report(format!("field not found: {name}")))?;
            }
            QueryToken::Index(idx) => {
                cur = cur
                    .get(idx)
                    .ok_or_else(|| FozzyError::Report(format!("index out of bounds: {idx}")))?;
            }
        }
    }
    Ok(cur.clone())
}

#[derive(Debug, Clone)]
enum QueryToken {
    Field(String),
    Index(usize),
}

fn parse_expr(expr: &str) -> FozzyResult<Vec<QueryToken>> {
    let mut tokens = Vec::new();
    let chars: Vec<char> = expr.chars().collect();
    let mut i = 1usize; // skip leading '.'

    while i < chars.len() {
        if chars[i] == '.' {
            i += 1;
            continue;
        }
        if chars[i] == '[' {
            i += 1;
            let start = i;
            while i < chars.len() && chars[i].is_ascii_digit() {
                i += 1;
            }
            if i >= chars.len() || chars[i] != ']' || start == i {
                return Err(FozzyError::Report(format!("invalid index expression in {expr:?}")));
            }
            let idx_str: String = chars[start..i].iter().collect();
            i += 1; // skip ]
            let idx: usize = idx_str
                .parse()
                .map_err(|_| FozzyError::Report(format!("invalid index {idx_str:?}")))?;
            tokens.push(QueryToken::Index(idx));
            continue;
        }

        let start = i;
        while i < chars.len() && chars[i] != '.' && chars[i] != '[' {
            i += 1;
        }
        let field: String = chars[start..i].iter().collect();
        if field.is_empty() {
            return Err(FozzyError::Report(format!("invalid field expression in {expr:?}")));
        }
        tokens.push(QueryToken::Field(field));
    }

    Ok(tokens)
}
