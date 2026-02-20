//! Topology and hotspot mapping commands (`fozzy map ...`).

use clap::{Subcommand, ValueEnum};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

use crate::{Config, FozzyError, FozzyResult};

const SUITE_TEST_DET: &str = "test_det";
const SUITE_RUN_REPLAY_CI: &str = "run_record_replay_ci";
const SUITE_FUZZ: &str = "fuzz_inputs";
const SUITE_EXPLORE: &str = "explore_schedule_faults";
const SUITE_HOST: &str = "host_backends_run";
const SUITE_MEMORY: &str = "memory_graph_diff_top";
const SUITE_SHRINK: &str = "shrink_failure_trace";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, ValueEnum, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TopologyProfile {
    Balanced,
    Pedantic,
    Overkill,
}

#[derive(Debug, Subcommand)]
pub enum MapCommand {
    /// Analyze repository hotspots and risk-ranked candidate areas for granular suites
    Hotspots {
        #[arg(long, default_value = ".")]
        root: PathBuf,
        #[arg(long, default_value_t = 60)]
        min_risk: u8,
        #[arg(long, default_value_t = 50)]
        limit: usize,
    },
    /// Discover service/module boundaries from language-agnostic repo signals
    Services {
        #[arg(long, default_value = ".")]
        root: PathBuf,
    },
    /// Build suite recommendations and scenario-coverage gaps for high-risk hotspots
    Suites {
        #[arg(long, default_value = ".")]
        root: PathBuf,
        #[arg(long, default_value = "tests")]
        scenario_root: PathBuf,
        #[arg(long, default_value_t = 60)]
        min_risk: u8,
        #[arg(long, default_value = "pedantic")]
        profile: TopologyProfile,
        #[arg(long, default_value_t = 100)]
        limit: usize,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MapHotspotsReport {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    pub root: String,
    #[serde(rename = "scannedFiles")]
    pub scanned_files: usize,
    #[serde(rename = "minRisk")]
    pub min_risk: u8,
    pub hotspots: Vec<MapHotspot>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MapServicesReport {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    pub root: String,
    #[serde(rename = "scannedFiles")]
    pub scanned_files: usize,
    pub services: Vec<ServiceBoundary>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MapSuitesReport {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    pub root: String,
    #[serde(rename = "scenarioRoot")]
    pub scenario_root: String,
    #[serde(rename = "scannedFiles")]
    pub scanned_files: usize,
    pub profile: TopologyProfile,
    #[serde(rename = "baseMinRisk")]
    pub base_min_risk: u8,
    #[serde(rename = "effectiveMinRisk")]
    pub effective_min_risk: u8,
    #[serde(rename = "scenarioCount")]
    pub scenario_count: usize,
    #[serde(rename = "requiredHotspotCount")]
    pub required_hotspot_count: usize,
    #[serde(rename = "coveredHotspotCount")]
    pub covered_hotspot_count: usize,
    #[serde(rename = "uncoveredHotspotCount")]
    pub uncovered_hotspot_count: usize,
    pub suites: Vec<SuiteRecommendation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MapHotspot {
    pub id: String,
    pub component: String,
    pub path: String,
    #[serde(rename = "riskScore")]
    pub risk_score: u8,
    pub reasons: Vec<String>,
    pub signals: HotspotSignals,
    #[serde(rename = "recommendedSuites")]
    pub recommended_suites: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HotspotSignals {
    #[serde(rename = "lineCount")]
    pub line_count: usize,
    #[serde(rename = "branchSignals")]
    pub branch_signals: usize,
    #[serde(rename = "concurrencySignals")]
    pub concurrency_signals: usize,
    #[serde(rename = "externalSignals")]
    pub external_signals: usize,
    #[serde(rename = "failureSignals")]
    pub failure_signals: usize,
    #[serde(rename = "memorySignals")]
    pub memory_signals: usize,
    #[serde(rename = "entrypointSignals")]
    pub entrypoint_signals: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceBoundary {
    pub name: String,
    pub path: String,
    pub kind: String,
    #[serde(rename = "fileCount")]
    pub file_count: usize,
    #[serde(rename = "entrypointSignals")]
    pub entrypoint_signals: usize,
    #[serde(rename = "externalSignals")]
    pub external_signals: usize,
    #[serde(rename = "concurrencySignals")]
    pub concurrency_signals: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuiteRecommendation {
    #[serde(rename = "hotspotId")]
    pub hotspot_id: String,
    pub component: String,
    pub path: String,
    #[serde(rename = "riskScore")]
    pub risk_score: u8,
    #[serde(rename = "requiredByPolicy")]
    pub required_by_policy: bool,
    pub covered: bool,
    #[serde(rename = "coverageHints")]
    pub coverage_hints: Vec<String>,
    #[serde(rename = "requiredSuites")]
    pub required_suites: Vec<String>,
    #[serde(rename = "coveredSuites")]
    pub covered_suites: Vec<String>,
    #[serde(rename = "missingRequiredSuites")]
    pub missing_required_suites: Vec<String>,
    #[serde(rename = "whyRequired")]
    pub why_required: Vec<String>,
    pub reasons: Vec<String>,
    #[serde(rename = "recommendedSuites")]
    pub recommended_suites: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct MapSuitesOptions {
    pub root: PathBuf,
    pub scenario_root: PathBuf,
    pub min_risk: u8,
    pub profile: TopologyProfile,
    pub limit: usize,
}

#[derive(Debug, Clone)]
struct RepoFacts {
    root: PathBuf,
    scanned_files: usize,
    hotspots: Vec<MapHotspot>,
    services: Vec<ServiceBoundary>,
}

#[derive(Debug, Clone)]
struct ScanRecord {
    rel: PathBuf,
    component: String,
    signal: HotspotSignals,
    risk_score: u8,
    reasons: Vec<String>,
}

#[derive(Debug, Clone)]
struct ScenarioFact {
    haystack: String,
    has_explore: bool,
    has_fuzz: bool,
    has_host: bool,
    has_memory: bool,
    has_failure: bool,
}

pub fn map_command(_config: &Config, command: &MapCommand) -> FozzyResult<serde_json::Value> {
    match command {
        MapCommand::Hotspots {
            root,
            min_risk,
            limit,
        } => {
            let facts = scan_repo(root)?;
            let mut hotspots: Vec<MapHotspot> = facts
                .hotspots
                .into_iter()
                .filter(|h| h.risk_score >= *min_risk)
                .collect();
            hotspots.sort_by(|a, b| {
                b.risk_score
                    .cmp(&a.risk_score)
                    .then_with(|| a.path.cmp(&b.path))
            });
            hotspots.truncate(*limit);
            Ok(serde_json::to_value(MapHotspotsReport {
                schema_version: "fozzy.map_hotspots.v2".to_string(),
                root: facts.root.display().to_string(),
                scanned_files: facts.scanned_files,
                min_risk: *min_risk,
                hotspots,
            })?)
        }
        MapCommand::Services { root } => {
            let facts = scan_repo(root)?;
            Ok(serde_json::to_value(MapServicesReport {
                schema_version: "fozzy.map_services.v2".to_string(),
                root: facts.root.display().to_string(),
                scanned_files: facts.scanned_files,
                services: facts.services,
            })?)
        }
        MapCommand::Suites {
            root,
            scenario_root,
            min_risk,
            profile,
            limit,
        } => {
            let report = map_suites(&MapSuitesOptions {
                root: root.clone(),
                scenario_root: scenario_root.clone(),
                min_risk: *min_risk,
                profile: *profile,
                limit: *limit,
            })?;
            Ok(serde_json::to_value(report)?)
        }
    }
}

pub fn map_suites(opt: &MapSuitesOptions) -> FozzyResult<MapSuitesReport> {
    let facts = scan_repo(&opt.root)?;
    let scenario_files = discover_scenarios(&opt.scenario_root)?;
    let scenario_facts = build_scenario_facts(&scenario_files);

    let effective_min_risk = effective_min_risk(opt.min_risk, opt.profile);
    let mut suites = Vec::<SuiteRecommendation>::new();
    let mut required_hotspot_count = 0usize;
    let mut covered_hotspot_count = 0usize;

    for hotspot in facts.hotspots {
        let hints = hotspot_hints(&hotspot);
        let required_by_policy = hotspot.risk_score >= effective_min_risk;
        if required_by_policy {
            required_hotspot_count += 1;
        }

        let required_suites = required_suites_for_hotspot(opt.profile, &hotspot.signals);
        let covered_suites = covered_suites_for_hotspot(&required_suites, &hints, &scenario_facts);
        let missing_required_suites = required_suites
            .iter()
            .filter(|s| !covered_suites.contains(*s))
            .cloned()
            .collect::<Vec<_>>();
        let covered = !required_by_policy || missing_required_suites.is_empty();
        if required_by_policy && covered {
            covered_hotspot_count += 1;
        }

        let why_required = why_required(hotspot.risk_score, effective_min_risk, &hotspot.signals);
        let mut recommended = required_suites.clone();
        for extra in recommended_suites_for_hotspot(&hotspot.signals) {
            if !recommended.contains(&extra) {
                recommended.push(extra);
            }
        }

        suites.push(SuiteRecommendation {
            hotspot_id: hotspot.id,
            component: hotspot.component,
            path: hotspot.path,
            risk_score: hotspot.risk_score,
            required_by_policy,
            covered,
            coverage_hints: hints,
            required_suites,
            covered_suites,
            missing_required_suites,
            why_required,
            reasons: hotspot.reasons,
            recommended_suites: recommended,
        });
    }

    suites.sort_by(|a, b| {
        b.risk_score
            .cmp(&a.risk_score)
            .then_with(|| a.path.cmp(&b.path))
    });
    suites.truncate(opt.limit);

    let uncovered_hotspot_count = required_hotspot_count.saturating_sub(covered_hotspot_count);

    Ok(MapSuitesReport {
        schema_version: "fozzy.map_suites.v2".to_string(),
        root: facts.root.display().to_string(),
        scenario_root: opt.scenario_root.display().to_string(),
        scanned_files: facts.scanned_files,
        profile: opt.profile,
        base_min_risk: opt.min_risk,
        effective_min_risk,
        scenario_count: scenario_files.len(),
        required_hotspot_count,
        covered_hotspot_count,
        uncovered_hotspot_count,
        suites,
    })
}

fn effective_min_risk(base: u8, profile: TopologyProfile) -> u8 {
    match profile {
        TopologyProfile::Balanced => base.saturating_add(15).min(100),
        TopologyProfile::Pedantic => base.saturating_sub(5),
        TopologyProfile::Overkill => base.saturating_sub(15),
    }
}

fn required_suites_for_hotspot(profile: TopologyProfile, s: &HotspotSignals) -> Vec<String> {
    let mut out = BTreeSet::<String>::new();
    out.insert(SUITE_TEST_DET.to_string());
    out.insert(SUITE_RUN_REPLAY_CI.to_string());

    match profile {
        TopologyProfile::Balanced => {
            if s.concurrency_signals > 0 {
                out.insert(SUITE_EXPLORE.to_string());
            }
            if s.external_signals > 0 {
                out.insert(SUITE_HOST.to_string());
            }
            if s.failure_signals > 0 {
                out.insert(SUITE_SHRINK.to_string());
            }
            if s.memory_signals > 2 {
                out.insert(SUITE_MEMORY.to_string());
            }
            if s.branch_signals > 20 {
                out.insert(SUITE_FUZZ.to_string());
            }
        }
        TopologyProfile::Pedantic => {
            out.insert(SUITE_SHRINK.to_string());
            if s.concurrency_signals > 0 || s.failure_signals >= 4 {
                out.insert(SUITE_EXPLORE.to_string());
            }
            if s.external_signals > 0 || s.entrypoint_signals > 0 {
                out.insert(SUITE_HOST.to_string());
            }
            if s.memory_signals > 0 {
                out.insert(SUITE_MEMORY.to_string());
            }
            if s.branch_signals > 6 || s.failure_signals > 0 {
                out.insert(SUITE_FUZZ.to_string());
            }
        }
        TopologyProfile::Overkill => {
            out.insert(SUITE_FUZZ.to_string());
            out.insert(SUITE_EXPLORE.to_string());
            out.insert(SUITE_HOST.to_string());
            out.insert(SUITE_MEMORY.to_string());
            out.insert(SUITE_SHRINK.to_string());
        }
    }

    out.into_iter().collect()
}

fn recommended_suites_for_hotspot(s: &HotspotSignals) -> Vec<String> {
    let mut out = BTreeSet::<String>::new();
    out.insert(SUITE_TEST_DET.to_string());
    out.insert(SUITE_RUN_REPLAY_CI.to_string());
    if s.concurrency_signals > 0 {
        out.insert(SUITE_EXPLORE.to_string());
    }
    if s.external_signals > 0 {
        out.insert(SUITE_HOST.to_string());
    }
    if s.failure_signals > 0 {
        out.insert(SUITE_SHRINK.to_string());
    }
    if s.memory_signals > 0 {
        out.insert(SUITE_MEMORY.to_string());
    }
    if s.branch_signals > 8 {
        out.insert(SUITE_FUZZ.to_string());
    }
    out.into_iter().collect()
}

fn why_required(risk: u8, threshold: u8, s: &HotspotSignals) -> Vec<String> {
    let mut out = Vec::<String>::new();
    if risk >= threshold {
        out.push(format!("risk_score {} >= threshold {}", risk, threshold));
    }
    if s.concurrency_signals > 0 {
        out.push("concurrency hotspot".to_string());
    }
    if s.external_signals > 0 {
        out.push("external side-effects present".to_string());
    }
    if s.failure_signals > 0 {
        out.push("failure/retry/timeout behavior present".to_string());
    }
    if s.memory_signals > 0 {
        out.push("memory behavior present".to_string());
    }
    out
}

fn covered_suites_for_hotspot(
    required: &[String],
    hints: &[String],
    scenarios: &[ScenarioFact],
) -> Vec<String> {
    required
        .iter()
        .filter(|suite| {
            scenarios
                .iter()
                .any(|s| matches_suite_signal(s, suite.as_str()) && matches_hints(s, hints))
        })
        .cloned()
        .collect()
}

fn matches_hints(s: &ScenarioFact, hints: &[String]) -> bool {
    hints.iter().any(|h| s.haystack.contains(h))
}

fn matches_suite_signal(s: &ScenarioFact, suite: &str) -> bool {
    match suite {
        SUITE_TEST_DET => true,
        SUITE_RUN_REPLAY_CI => true,
        SUITE_FUZZ => s.has_fuzz,
        SUITE_EXPLORE => s.has_explore,
        SUITE_HOST => s.has_host,
        SUITE_MEMORY => s.has_memory,
        SUITE_SHRINK => s.has_failure,
        _ => false,
    }
}

fn build_scenario_facts(paths: &[PathBuf]) -> Vec<ScenarioFact> {
    paths.iter().filter_map(|p| scenario_fact(p).ok()).collect()
}

fn scenario_fact(path: &Path) -> FozzyResult<ScenarioFact> {
    let content = std::fs::read_to_string(path)?;
    let lower = content.to_ascii_lowercase();
    let name = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    let haystack = format!("{} {}", path.to_string_lossy().to_ascii_lowercase(), lower);

    let has_explore = name.contains("explore") || lower.contains("\"distributed\"");
    let has_fuzz = name.contains("fuzz") || lower.contains("\"mode\":\"fuzz\"");
    let has_host = name.contains("host")
        || lower.contains("proc_spawn")
        || lower.contains("http_request")
        || lower.contains("fs_write");
    let has_memory = name.contains("memory") || lower.contains("memory_");
    let has_failure = name.contains("fail")
        || name.contains("timeout")
        || name.contains("panic")
        || lower.contains("\"type\":\"fail\"")
        || lower.contains("\"type\":\"panic\"");

    Ok(ScenarioFact {
        haystack,
        has_explore,
        has_fuzz,
        has_host,
        has_memory,
        has_failure,
    })
}

fn scan_repo(root: &Path) -> FozzyResult<RepoFacts> {
    if !root.exists() {
        return Err(FozzyError::InvalidArgument(format!(
            "map root does not exist: {}",
            root.display()
        )));
    }

    let mut records = Vec::<ScanRecord>::new();
    let mut scanned_files = 0usize;
    for entry in WalkDir::new(root).into_iter().flatten() {
        if !entry.file_type().is_file() {
            continue;
        }
        let p = entry.path();
        if should_skip_path(p) || !is_candidate_file(p) {
            continue;
        }
        let Ok(bytes) = std::fs::read(p) else {
            continue;
        };
        let content = String::from_utf8_lossy(&bytes);
        let line_count = content.lines().count();
        let rel = p.strip_prefix(root).unwrap_or(p).to_path_buf();
        scanned_files += 1;

        let signal = build_signals(&content, line_count);
        let (risk_score, reasons) = score_signals(&signal);
        if risk_score == 0 {
            continue;
        }
        records.push(ScanRecord {
            component: component_for_path(&rel),
            rel,
            signal,
            risk_score,
            reasons,
        });
    }

    let mut hotspots = Vec::<MapHotspot>::new();
    for rec in &records {
        hotspots.push(MapHotspot {
            id: format!("{}:{}", rec.component, rec.rel.display()),
            component: rec.component.clone(),
            path: rec.rel.display().to_string(),
            risk_score: rec.risk_score,
            reasons: rec.reasons.clone(),
            signals: rec.signal.clone(),
            recommended_suites: recommended_suites_for_hotspot(&rec.signal),
        });
    }
    hotspots.sort_by(|a, b| {
        b.risk_score
            .cmp(&a.risk_score)
            .then_with(|| a.path.cmp(&b.path))
    });

    let mut by_component = BTreeMap::<String, (usize, usize, usize, usize)>::new();
    for rec in &records {
        let e = by_component
            .entry(rec.component.clone())
            .or_insert((0usize, 0usize, 0usize, 0usize));
        e.0 += 1;
        e.1 += rec.signal.entrypoint_signals;
        e.2 += rec.signal.external_signals;
        e.3 += rec.signal.concurrency_signals;
    }

    let mut services = Vec::<ServiceBoundary>::new();
    for (name, (file_count, entrypoint, external, concurrency)) in by_component {
        if file_count < 2 {
            continue;
        }
        let kind = if entrypoint > 0 && external > 0 {
            "service"
        } else if concurrency > 0 {
            "worker"
        } else {
            "library"
        };
        services.push(ServiceBoundary {
            path: name.clone(),
            name,
            kind: kind.to_string(),
            file_count,
            entrypoint_signals: entrypoint,
            external_signals: external,
            concurrency_signals: concurrency,
        });
    }
    services.sort_by(|a, b| {
        b.file_count
            .cmp(&a.file_count)
            .then_with(|| a.path.cmp(&b.path))
    });

    Ok(RepoFacts {
        root: root.to_path_buf(),
        scanned_files,
        hotspots,
        services,
    })
}

fn discover_scenarios(root: &Path) -> FozzyResult<Vec<PathBuf>> {
    if !root.exists() {
        return Ok(Vec::new());
    }
    let mut out = Vec::<PathBuf>::new();
    for entry in WalkDir::new(root).into_iter().flatten() {
        if !entry.file_type().is_file() {
            continue;
        }
        let p = entry.path();
        if p.file_name()
            .and_then(|s| s.to_str())
            .is_some_and(|n| n.ends_with(".fozzy.json"))
        {
            out.push(p.to_path_buf());
        }
    }
    out.sort();
    Ok(out)
}

fn hotspot_hints(h: &MapHotspot) -> Vec<String> {
    let mut out = BTreeSet::<String>::new();
    out.insert(h.component.to_ascii_lowercase());
    if let Some(stem) = Path::new(&h.path).file_stem().and_then(|s| s.to_str()) {
        out.insert(stem.to_ascii_lowercase().replace('.', "-"));
        out.insert(stem.to_ascii_lowercase().replace('.', "_"));
    }
    out.into_iter().filter(|s| s.len() >= 3).collect()
}

fn should_skip_path(p: &Path) -> bool {
    let s = p.to_string_lossy().to_ascii_lowercase();
    [
        "/.git/",
        "/target/",
        "/node_modules/",
        "/.fozzy/",
        "/dist/",
        "/build/",
        "/out/",
        "/coverage/",
        "/vendor/",
        "/.next/",
    ]
    .iter()
    .any(|needle| s.contains(needle))
}

fn is_candidate_file(p: &Path) -> bool {
    if p.file_name()
        .and_then(|s| s.to_str())
        .is_some_and(|n| n.eq_ignore_ascii_case("dockerfile"))
    {
        return true;
    }
    let Some(ext) = p.extension().and_then(|s| s.to_str()) else {
        return false;
    };
    matches!(
        ext.to_ascii_lowercase().as_str(),
        "rs" | "go"
            | "js"
            | "jsx"
            | "ts"
            | "tsx"
            | "py"
            | "java"
            | "kt"
            | "c"
            | "cc"
            | "cpp"
            | "h"
            | "hpp"
            | "cs"
            | "swift"
            | "rb"
            | "php"
            | "scala"
            | "sql"
            | "yaml"
            | "yml"
            | "toml"
            | "json"
            | "ini"
            | "conf"
            | "sh"
    )
}

fn build_signals(content: &str, line_count: usize) -> HotspotSignals {
    let lower = content.to_ascii_lowercase();
    let count =
        |needles: &[&str]| -> usize { needles.iter().map(|n| lower.matches(n).count()).sum() };

    HotspotSignals {
        line_count,
        branch_signals: count(&[" if ", " else ", " match ", " switch ", " case ", " catch "]),
        concurrency_signals: count(&[
            " async ",
            ".await",
            "thread",
            "mutex",
            "rwlock",
            "channel",
            "spawn",
            "tokio::",
            "select!",
            "goroutine",
            "go func",
        ]),
        external_signals: count(&[
            "http://",
            "https://",
            "grpc",
            "sql",
            "redis",
            "kafka",
            "rabbit",
            "nats",
            "s3",
            "command::new",
            "std::fs",
            "subprocess",
            "socket",
            "database",
            "postgres",
            "mysql",
            "mongodb",
        ]),
        failure_signals: count(&[
            "timeout",
            "retry",
            "backoff",
            "circuit",
            "panic",
            "throw",
            "except",
            "rollback",
            "compensat",
            "fail",
            "error",
        ]),
        memory_signals: count(&["alloc", "free", "leak", "memory", "heap"]),
        entrypoint_signals: count(&[
            "fn main",
            "main(",
            "applisten",
            "listen(",
            "router",
            "fastapi",
            "express(",
            "httpserver",
            "grpcserver",
            "deployment",
            "kind: service",
        ]),
    }
}

fn score_signals(s: &HotspotSignals) -> (u8, Vec<String>) {
    let mut reasons = Vec::<String>::new();
    let mut score = 0usize;

    score += s.branch_signals.min(30);
    if s.branch_signals > 8 {
        reasons.push(format!("high branch density ({})", s.branch_signals));
    }

    score += s.concurrency_signals.saturating_mul(6).min(30);
    if s.concurrency_signals > 0 {
        reasons.push(format!("concurrency signals ({})", s.concurrency_signals));
    }

    score += s.external_signals.saturating_mul(5).min(25);
    if s.external_signals > 0 {
        reasons.push(format!(
            "external side-effect signals ({})",
            s.external_signals
        ));
    }

    score += s.failure_signals.saturating_mul(3).min(15);
    if s.failure_signals > 3 {
        reasons.push(format!(
            "failure/timeout/retry signals ({})",
            s.failure_signals
        ));
    }

    if s.memory_signals > 2 {
        score += 8;
        reasons.push(format!("memory management signals ({})", s.memory_signals));
    }

    if s.entrypoint_signals > 0 {
        score += 5;
        reasons.push("service/entrypoint boundary indicators".to_string());
    }

    if s.line_count > 500 {
        score += 7;
        reasons.push(format!("large file size ({} lines)", s.line_count));
    } else if s.line_count > 250 {
        score += 4;
    }

    (score.min(100) as u8, reasons)
}

fn component_for_path(rel: &Path) -> String {
    let parts: Vec<String> = rel
        .components()
        .filter_map(|c| c.as_os_str().to_str())
        .map(|s| s.to_ascii_lowercase())
        .collect();
    if parts.is_empty() {
        return "root".to_string();
    }
    for marker in ["services", "apps", "packages", "crates", "modules"] {
        if let Some(i) = parts.iter().position(|p| p == marker)
            && let Some(next) = parts.get(i + 1)
        {
            return format!("{marker}/{next}");
        }
    }
    parts.first().cloned().unwrap_or_else(|| "root".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("fozzy-map-{name}-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        dir
    }

    #[test]
    fn map_suites_reports_uncovered_hotspots() {
        let root = temp_dir("coverage");
        let src = root.join("services/payments");
        let tests = root.join("tests");
        std::fs::create_dir_all(&src).expect("src");
        std::fs::create_dir_all(&tests).expect("tests");
        std::fs::write(
            src.join("handler.rs"),
            r#"
            async fn handle() {
                if retry { tokio::spawn(async move {}); }
                let _ = std::fs::read("x");
                if timeout { panic!("boom"); }
            }
            "#,
        )
        .expect("write source");

        let report = map_suites(&MapSuitesOptions {
            root: root.clone(),
            scenario_root: tests.clone(),
            min_risk: 10,
            profile: TopologyProfile::Pedantic,
            limit: 50,
        })
        .expect("map suites");
        assert!(report.required_hotspot_count > 0);
        assert!(report.uncovered_hotspot_count > 0);
    }

    #[test]
    fn profiles_are_progressively_stricter() {
        let signals = HotspotSignals {
            line_count: 300,
            branch_signals: 10,
            concurrency_signals: 1,
            external_signals: 1,
            failure_signals: 1,
            memory_signals: 1,
            entrypoint_signals: 1,
        };
        let balanced = required_suites_for_hotspot(TopologyProfile::Balanced, &signals).len();
        let pedantic = required_suites_for_hotspot(TopologyProfile::Pedantic, &signals).len();
        let overkill = required_suites_for_hotspot(TopologyProfile::Overkill, &signals).len();
        assert!(balanced <= pedantic, "balanced should be least strict");
        assert!(pedantic <= overkill, "overkill should be most strict");
    }
}
