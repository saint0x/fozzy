//! Reporting types and renderers.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Reporter {
    Pretty,
    Json,
    Junit,
    Html,
}

impl clap::ValueEnum for Reporter {
    fn value_variants<'a>() -> &'a [Self] {
        &[Self::Pretty, Self::Json, Self::Junit, Self::Html]
    }

    fn to_possible_value(&self) -> Option<clap::builder::PossibleValue> {
        Some(match self {
            Self::Pretty => clap::builder::PossibleValue::new("pretty"),
            Self::Json => clap::builder::PossibleValue::new("json"),
            Self::Junit => clap::builder::PossibleValue::new("junit"),
            Self::Html => clap::builder::PossibleValue::new("html"),
        })
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ExitStatus {
    Pass,
    Fail,
    Error,
    Timeout,
    Crash,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunMode {
    Test,
    Run,
    Fuzz,
    Explore,
    Replay,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunIdentity {
    #[serde(rename = "runId")]
    pub run_id: String,
    pub seed: u64,
    #[serde(rename = "tracePath", skip_serializing_if = "Option::is_none")]
    pub trace_path: Option<String>,
    #[serde(rename = "reportPath", skip_serializing_if = "Option::is_none")]
    pub report_path: Option<String>,
    #[serde(rename = "artifactsDir", skip_serializing_if = "Option::is_none")]
    pub artifacts_dir: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingLocation {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub col: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub kind: FindingKind,
    pub title: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<FindingLocation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingKind {
    Assertion,
    Panic,
    Hang,
    Invariant,
    Checker,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunSummary {
    pub status: ExitStatus,
    pub mode: RunMode,
    pub identity: RunIdentity,
    #[serde(rename = "startedAt")]
    pub started_at: String,
    #[serde(rename = "finishedAt")]
    pub finished_at: String,
    #[serde(rename = "durationMs")]
    pub duration_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tests: Option<TestCounts>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub findings: Vec<Finding>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestCounts {
    pub passed: u64,
    pub failed: u64,
    pub skipped: u64,
}

impl RunSummary {
    pub fn pretty(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!(
            "status={:?} mode={:?} runId={} seed={}\n",
            self.status, self.mode, self.identity.run_id, self.identity.seed
        ));
        if let Some(path) = &self.identity.trace_path {
            out.push_str(&format!("trace={path}\n"));
        }
        if let Some(path) = &self.identity.report_path {
            out.push_str(&format!("report={path}\n"));
        }
        if let Some(dir) = &self.identity.artifacts_dir {
            out.push_str(&format!("artifacts={dir}\n"));
        }
        if let Some(tests) = &self.tests {
            out.push_str(&format!(
                "tests: passed={} failed={} skipped={}\n",
                tests.passed, tests.failed, tests.skipped
            ));
        }
        for finding in &self.findings {
            out.push_str(&format!("- {:?}: {}: {}\n", finding.kind, finding.title, finding.message));
        }
        out.trim_end().to_string()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportOutput {
    pub format: Reporter,
    pub content: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunManifest {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "runId")]
    pub run_id: String,
    pub mode: RunMode,
    pub status: ExitStatus,
    pub seed: u64,
    #[serde(rename = "startedAt")]
    pub started_at: String,
    #[serde(rename = "finishedAt")]
    pub finished_at: String,
    #[serde(rename = "durationMs")]
    pub duration_ms: u64,
    #[serde(rename = "tracePath", skip_serializing_if = "Option::is_none")]
    pub trace_path: Option<String>,
    #[serde(rename = "reportPath", skip_serializing_if = "Option::is_none")]
    pub report_path: Option<String>,
    #[serde(rename = "artifactsDir", skip_serializing_if = "Option::is_none")]
    pub artifacts_dir: Option<String>,
    #[serde(rename = "findingsCount")]
    pub findings_count: usize,
    #[serde(rename = "testsPassed", skip_serializing_if = "Option::is_none")]
    pub tests_passed: Option<u64>,
    #[serde(rename = "testsFailed", skip_serializing_if = "Option::is_none")]
    pub tests_failed: Option<u64>,
    #[serde(rename = "testsSkipped", skip_serializing_if = "Option::is_none")]
    pub tests_skipped: Option<u64>,
}

pub fn write_run_manifest(summary: &RunSummary, artifacts_dir: &Path) -> crate::FozzyResult<PathBuf> {
    std::fs::create_dir_all(artifacts_dir)?;
    let manifest = RunManifest {
        schema_version: "fozzy.run_manifest.v1".to_string(),
        run_id: summary.identity.run_id.clone(),
        mode: summary.mode,
        status: summary.status,
        seed: summary.identity.seed,
        started_at: summary.started_at.clone(),
        finished_at: summary.finished_at.clone(),
        duration_ms: summary.duration_ms,
        trace_path: summary.identity.trace_path.clone(),
        report_path: summary.identity.report_path.clone(),
        artifacts_dir: summary.identity.artifacts_dir.clone(),
        findings_count: summary.findings.len(),
        tests_passed: summary.tests.as_ref().map(|t| t.passed),
        tests_failed: summary.tests.as_ref().map(|t| t.failed),
        tests_skipped: summary.tests.as_ref().map(|t| t.skipped),
    };
    let out = artifacts_dir.join("manifest.json");
    std::fs::write(&out, serde_json::to_vec_pretty(&manifest)?)?;
    Ok(out)
}

pub fn render_junit_xml(summary: &RunSummary) -> String {
    // Minimal JUnit report: one suite, one testcase per finding (or one testcase for pass).
    let tests = summary.findings.len().max(1);
    let failures = summary
        .findings
        .iter()
        .filter(|f| matches!(f.kind, FindingKind::Assertion | FindingKind::Invariant | FindingKind::Checker))
        .count();

    let mut out = String::new();
    out.push_str(r#"<?xml version="1.0" encoding="UTF-8"?>"#);
    out.push('\n');
    out.push_str(&format!(
        r#"<testsuite name="fozzy" tests="{tests}" failures="{failures}" time="{}">"#,
        (summary.duration_ms as f64) / 1000.0
    ));
    out.push('\n');

    if summary.findings.is_empty() {
        out.push_str(&format!(
            r#"<testcase classname="fozzy" name="{}"/>"#,
            xml_escape(&summary.identity.run_id)
        ));
        out.push('\n');
    } else {
        for (i, f) in summary.findings.iter().enumerate() {
            out.push_str(&format!(
                r#"<testcase classname="fozzy" name="finding_{i}">"#
            ));
            out.push('\n');
            out.push_str(&format!(
                r#"<failure message="{}">{}</failure>"#,
                xml_escape(&f.title),
                xml_escape(&f.message)
            ));
            out.push('\n');
            out.push_str(r#"</testcase>"#);
            out.push('\n');
        }
    }

    out.push_str(r#"</testsuite>"#);
    out.push('\n');
    out
}

pub fn render_html(summary: &RunSummary) -> String {
    let status = format!("{:?}", summary.status);
    let mut items = String::new();
    for f in &summary.findings {
        items.push_str("<li>");
        items.push_str(&html_escape(&format!("{:?}: {}: {}", f.kind, f.title, f.message)));
        items.push_str("</li>");
    }
    if summary.findings.is_empty() {
        items.push_str("<li>no findings</li>");
    }

    format!(
        r#"<!doctype html>
<html>
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>fozzy report</title>
  <style>
    body {{ font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace; padding: 24px; }}
    .meta {{ opacity: 0.8; }}
    .status {{ font-weight: 700; }}
  </style>
</head>
<body>
  <div class="status">status: {status}</div>
  <div class="meta">runId: {run_id} seed: {seed}</div>
  <div class="meta">startedAt: {started_at}</div>
  <div class="meta">finishedAt: {finished_at}</div>
  <h2>findings</h2>
  <ul>{items}</ul>
</body>
</html>"#,
        status = html_escape(&status),
        run_id = html_escape(&summary.identity.run_id),
        seed = summary.identity.seed,
        started_at = html_escape(&summary.started_at),
        finished_at = html_escape(&summary.finished_at),
        items = items
    )
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('\"', "&quot;").replace('\'', "&apos;")
}

fn html_escape(s: &str) -> String {
    xml_escape(s)
}
