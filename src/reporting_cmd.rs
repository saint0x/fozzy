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
    Flaky {
        runs: Vec<String>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportEnvelope {
    pub format: Reporter,
    pub content: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlakyReport {
    #[serde(rename = "runCount")]
    pub run_count: usize,
    #[serde(rename = "statusCounts")]
    pub status_counts: std::collections::BTreeMap<String, usize>,
    #[serde(rename = "findingTitleSets")]
    pub finding_title_sets: Vec<Vec<String>>,
    #[serde(rename = "isFlaky")]
    pub is_flaky: bool,
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
        ReportCommand::Flaky { runs } => flaky_command(config, runs),
    }
}

fn flaky_command(config: &Config, runs: &[String]) -> FozzyResult<serde_json::Value> {
    if runs.len() < 2 {
        return Err(FozzyError::Report(
            "flaky analysis requires at least two runs/traces".to_string(),
        ));
    }

    let mut status_counts = std::collections::BTreeMap::<String, usize>::new();
    let mut finding_sets = std::collections::BTreeSet::<Vec<String>>::new();

    for run in runs {
        let summary = load_summary(config, run)?;
        let status_key = format!("{:?}", summary.status).to_lowercase();
        *status_counts.entry(status_key).or_insert(0) += 1;

        let mut titles: Vec<String> = summary.findings.iter().map(|f| f.title.clone()).collect();
        titles.sort();
        titles.dedup();
        finding_sets.insert(titles);
    }

    let is_flaky = status_counts.len() > 1 || finding_sets.len() > 1;
    let out = FlakyReport {
        run_count: runs.len(),
        status_counts,
        finding_title_sets: finding_sets.into_iter().collect(),
        is_flaky,
    };
    Ok(serde_json::to_value(out)?)
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
    if expr == "." || expr == "$" {
        return Ok(root.clone());
    }
    let normalized = apply_query_aliases(&normalize_query_expr(expr)?);
    let tokens = parse_expr(&normalized)?;
    let mut current: Vec<&serde_json::Value> = vec![root];
    for token in tokens {
        let mut next = Vec::new();
        match token {
            QueryToken::Field(name) => {
                for v in &current {
                    if let Some(arr) = v.as_array() {
                        if let Ok(idx) = name.parse::<usize>() {
                            if let Some(item) = arr.get(idx) {
                                next.push(item);
                                continue;
                            }
                        }
                    }
                    if let Some(field) = v.get(&name) {
                        next.push(field);
                    }
                }
            }
            QueryToken::Index(idx) => {
                for v in &current {
                    if let Some(item) = v.get(idx) {
                        next.push(item);
                    }
                }
            }
            QueryToken::AllIndices => {
                for v in &current {
                    if let Some(arr) = v.as_array() {
                        for item in arr {
                            next.push(item);
                        }
                    }
                }
            }
        }
        current = next;
    }

    if current.is_empty() {
        return Err(FozzyError::Report(format!(
            "query matched no values for expression {expr:?}"
        )));
    }
    if current.len() == 1 {
        return Ok(current[0].clone());
    }
    Ok(serde_json::Value::Array(
        current.into_iter().cloned().collect(),
    ))
}

fn apply_query_aliases(expr: &str) -> String {
    // Common DX aliases for top-level identity fields.
    // Example: `runId` -> `.identity.runId`.
    const ALIASES: &[(&str, &str)] = &[
        (".runId", ".identity.runId"),
        (".seed", ".identity.seed"),
        (".tracePath", ".identity.tracePath"),
        (".reportPath", ".identity.reportPath"),
        (".artifactsDir", ".identity.artifactsDir"),
    ];
    for (from, to) in ALIASES {
        if expr == *from {
            return (*to).to_string();
        }
        if let Some(rest) = expr.strip_prefix(from) {
            if rest.starts_with('.') || rest.starts_with('[') {
                return format!("{to}{rest}");
            }
        }
    }
    expr.to_string()
}

fn normalize_query_expr(expr: &str) -> FozzyResult<String> {
    if expr.is_empty() {
        return Err(FozzyError::Report(
            "empty jq expression; examples: '.', '.identity.runId', 'findings[0].title', '.findings[].title'"
                .to_string(),
        ));
    }

    if let Some(rest) = expr.strip_prefix("$.") {
        return Ok(format!(".{rest}"));
    }
    if let Some(rest) = expr.strip_prefix('$') {
        if rest.starts_with('[') {
            return Ok(format!(".{rest}"));
        }
        return Err(FozzyError::Report(format!(
            "unsupported jq expression {expr:?}; supported path subset examples: '.', '.a.b', 'a.b', '.arr[0]', '.arr[].field'"
        )));
    }
    if expr.starts_with('.') {
        return Ok(expr.to_string());
    }
    if expr.starts_with('[') || expr.chars().next().is_some_and(|c| c.is_ascii_alphabetic() || c == '_') {
        return Ok(format!(".{expr}"));
    }
    Err(FozzyError::Report(format!(
        "unsupported jq expression {expr:?}; supported path subset examples: '.', '.a.b', 'a.b', '.arr[0]', '.arr[].field'"
    )))
}

#[derive(Debug, Clone)]
enum QueryToken {
    Field(String),
    Index(usize),
    AllIndices,
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
            if i < chars.len() && chars[i] == ']' {
                i += 1;
                tokens.push(QueryToken::AllIndices);
                continue;
            }
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
