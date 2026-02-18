//! Core engine: scenario execution, deterministic runtime, record/replay, shrinking.

use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore as _, SeedableRng as _};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use crate::{
    wall_time_iso_utc, Config, Decision, DecisionLog, ExitStatus, Finding, FindingKind, Reporter,
    RunIdentity, RunMode, RunSummary, Scenario, ScenarioPath, ScenarioV1Steps, TraceEvent,
    TraceFile, TracePath,
};

use crate::{FozzyError, FozzyResult};

#[derive(Debug, Clone)]
pub enum InitTemplate {
    Ts,
    Rust,
    Minimal,
}

impl clap::ValueEnum for InitTemplate {
    fn value_variants<'a>() -> &'a [Self] {
        &[Self::Ts, Self::Rust, Self::Minimal]
    }

    fn to_possible_value(&self) -> Option<clap::builder::PossibleValue> {
        Some(match self {
            Self::Ts => clap::builder::PossibleValue::new("ts"),
            Self::Rust => clap::builder::PossibleValue::new("rust"),
            Self::Minimal => clap::builder::PossibleValue::new("minimal"),
        })
    }
}

impl InitTemplate {
    pub fn from_option(opt: Option<&InitTemplate>) -> Self {
        opt.cloned().unwrap_or(Self::Minimal)
    }
}

#[derive(Debug, Clone)]
pub struct RunOptions {
    pub det: bool,
    pub seed: Option<u64>,
    pub timeout: Option<Duration>,
    pub reporter: Reporter,
    pub record_trace_to: Option<PathBuf>,
    pub filter: Option<String>,
    pub jobs: Option<usize>,
    pub fail_fast: bool,
}

#[derive(Debug, Clone)]
pub struct ReplayOptions {
    pub step: bool,
    pub until: Option<Duration>,
    pub dump_events: bool,
    pub reporter: Reporter,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShrinkMinimize {
    Input,
    Schedule,
    Faults,
    All,
}

impl clap::ValueEnum for ShrinkMinimize {
    fn value_variants<'a>() -> &'a [Self] {
        &[Self::Input, Self::Schedule, Self::Faults, Self::All]
    }

    fn to_possible_value(&self) -> Option<clap::builder::PossibleValue> {
        Some(match self {
            Self::Input => clap::builder::PossibleValue::new("input"),
            Self::Schedule => clap::builder::PossibleValue::new("schedule"),
            Self::Faults => clap::builder::PossibleValue::new("faults"),
            Self::All => clap::builder::PossibleValue::new("all"),
        })
    }
}

#[derive(Debug, Clone)]
pub struct ShrinkOptions {
    pub out_trace_path: Option<PathBuf>,
    pub budget: Option<Duration>,
    pub aggressive: bool,
    pub minimize: ShrinkMinimize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DoctorReport {
    pub ok: bool,
    pub issues: Vec<DoctorIssue>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nondeterminism_signals: Option<Vec<NondeterminismSignal>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub determinism_audit: Option<DeterminismAudit>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DoctorIssue {
    pub code: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hint: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NondeterminismSignal {
    pub source: String,
    pub detail: String,
}

#[derive(Debug, Clone)]
pub struct DoctorOptions {
    pub deep: bool,
    pub scenario: Option<ScenarioPath>,
    pub runs: u32,
    pub seed: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeterminismAudit {
    pub scenario: String,
    pub runs: u32,
    pub seed: u64,
    pub consistent: bool,
    pub signatures: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_mismatch_run: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct RunResult {
    pub summary: RunSummary,
}

#[derive(Debug, Clone)]
pub struct ShrinkResult {
    pub out_trace_path: String,
    pub result: RunResult,
}

pub fn init_project(config: &Config, template: &InitTemplate, force: bool) -> FozzyResult<()> {
    let base = &config.base_dir;
    if base.exists() && !force {
        return Err(FozzyError::InvalidArgument(format!(
            "{} already exists (use --force to overwrite)",
            base.display()
        )));
    }

    std::fs::create_dir_all(config.runs_dir())?;
    std::fs::create_dir_all(config.corpora_dir())?;

    // Write a minimal config if it doesn't exist.
    let config_path = PathBuf::from("fozzy.toml");
    if force || !config_path.exists() {
        let cfg = toml::to_string_pretty(config).map_err(|e| FozzyError::Config(e.to_string()))?;
        std::fs::write(&config_path, cfg)?;
    }

    std::fs::create_dir_all("tests")?;
    let scenario_path = PathBuf::from("tests").join("example.fozzy.json");
    if force || !scenario_path.exists() {
        let example = Scenario::example();
        std::fs::write(&scenario_path, serde_json::to_vec_pretty(&example)?)?;
    }

    match template {
        InitTemplate::Minimal => {}
        InitTemplate::Rust => {
            let readme = PathBuf::from("README.md");
            if force || !readme.exists() {
                std::fs::write(
                    &readme,
                    "Fozzy project (Rust template)\n\n- scenarios live in `tests/*.fozzy.json`\n- run: `fozzy test --det --json`\n",
                )?;
            }
        }
        InitTemplate::Ts => {
            // v0.1 doesn't scaffold npm; it only creates the core config + example scenarios.
        }
    }

    Ok(())
}

pub fn run_tests(config: &Config, globs: &[String], opt: &RunOptions) -> FozzyResult<RunResult> {
    let patterns = if globs.is_empty() {
        vec!["tests/**/*.fozzy.json".to_string()]
    } else {
        globs.to_vec()
    };

    let scenario_paths = crate::find_matching_files(&patterns)?;
    if scenario_paths.is_empty() {
        return Err(FozzyError::InvalidArgument(format!(
            "no scenario files matched (patterns={patterns:?})"
        )));
    }

    let mut passed = 0u64;
    let mut failed = 0u64;
    let mut skipped = 0u64;
    let mut findings = Vec::new();
    let mut test_runs: Vec<ScenarioRun> = Vec::new();

    let started_at = wall_time_iso_utc();
    let started = Instant::now();
    let seed = opt.seed.unwrap_or_else(gen_seed);
    let run_id = Uuid::new_v4().to_string();

    for p in scenario_paths {
        if let Some(filter) = &opt.filter {
            if !p.to_string_lossy().contains(filter) {
                skipped += 1;
                continue;
            }
        }

        let run = match run_scenario_inner(config, RunMode::Test, ScenarioPath::new(p.clone()), seed, opt.det, opt.timeout) {
            Ok(run) => run,
            Err(FozzyError::Scenario(msg)) if msg.contains("use `fozzy explore`") => {
                skipped += 1;
                continue;
            }
            Err(err) => return Err(err),
        };
        match run.status {
            ExitStatus::Pass => passed += 1,
            _ => {
                failed += 1;
                findings.extend(run.findings.clone());
                test_runs.push(run);
                if opt.fail_fast {
                    break;
                }
                continue;
            }
        }
        test_runs.push(run);
    }

    let finished_at = wall_time_iso_utc();
    let duration_ms = started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64;

    let status = if failed == 0 { ExitStatus::Pass } else { ExitStatus::Fail };

    let artifacts_dir = config.runs_dir().join(&run_id);
    std::fs::create_dir_all(&artifacts_dir)?;
    let report_path = artifacts_dir.join("report.json");

    let summary = RunSummary {
        status,
        mode: RunMode::Test,
        identity: RunIdentity {
            run_id,
            seed,
            trace_path: None,
            report_path: Some(report_path.to_string_lossy().to_string()),
            artifacts_dir: Some(artifacts_dir.to_string_lossy().to_string()),
        },
        started_at,
        finished_at,
        duration_ms,
        tests: Some(crate::TestCounts { passed, failed, skipped }),
        findings,
    };

    std::fs::write(&report_path, serde_json::to_vec_pretty(&summary)?)?;

    if let Some(record_base) = &opt.record_trace_to {
        write_test_traces(record_base, &test_runs, seed)?;
    }

    if matches!(opt.reporter, Reporter::Junit) {
        std::fs::write(artifacts_dir.join("junit.xml"), crate::render_junit_xml(&summary))?;
    }
    if matches!(opt.reporter, Reporter::Html) {
        std::fs::write(artifacts_dir.join("report.html"), crate::render_html(&summary))?;
    }

    Ok(RunResult { summary })
}

fn write_test_traces(record_base: &PathBuf, runs: &[ScenarioRun], seed: u64) -> FozzyResult<()> {
    if runs.is_empty() {
        return Ok(());
    }
    if runs.len() == 1 {
        let run = &runs[0];
        let summary = RunSummary {
            status: run.status,
            mode: RunMode::Test,
            identity: RunIdentity {
                run_id: Uuid::new_v4().to_string(),
                seed,
                trace_path: Some(record_base.to_string_lossy().to_string()),
                report_path: None,
                artifacts_dir: None,
            },
            started_at: wall_time_iso_utc(),
            finished_at: wall_time_iso_utc(),
            duration_ms: 0,
            tests: None,
            findings: run.findings.clone(),
        };
        let trace = TraceFile::new(
            RunMode::Test,
            Some(run.scenario_path.to_string_lossy().to_string()),
            Some(run.scenario_embedded.clone()),
            run.decisions.decisions.clone(),
            run.events.clone(),
            summary,
        );
        trace.write_json(record_base)?;
        return Ok(());
    }

    let parent = record_base.parent().unwrap_or_else(|| std::path::Path::new("."));
    let file_name = record_base
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("test-trace.fozzy");
    let base = if file_name.ends_with(".fozzy") {
        file_name.trim_end_matches(".fozzy")
    } else {
        file_name
    };
    std::fs::create_dir_all(parent)?;

    for (idx, run) in runs.iter().enumerate() {
        let out = parent.join(format!("{base}.{}.fozzy", idx + 1));
        let summary = RunSummary {
            status: run.status,
            mode: RunMode::Test,
            identity: RunIdentity {
                run_id: Uuid::new_v4().to_string(),
                seed,
                trace_path: Some(out.to_string_lossy().to_string()),
                report_path: None,
                artifacts_dir: None,
            },
            started_at: wall_time_iso_utc(),
            finished_at: wall_time_iso_utc(),
            duration_ms: 0,
            tests: None,
            findings: run.findings.clone(),
        };
        let trace = TraceFile::new(
            RunMode::Test,
            Some(run.scenario_path.to_string_lossy().to_string()),
            Some(run.scenario_embedded.clone()),
            run.decisions.decisions.clone(),
            run.events.clone(),
            summary,
        );
        trace.write_json(&out)?;
    }
    Ok(())
}

pub fn run_scenario(config: &Config, scenario_path: ScenarioPath, opt: &RunOptions) -> FozzyResult<RunResult> {
    let seed = opt.seed.unwrap_or_else(gen_seed);
    let run_id = Uuid::new_v4().to_string();

    let started_at = wall_time_iso_utc();
    let started = Instant::now();

    let run = run_scenario_inner(config, RunMode::Run, scenario_path.clone(), seed, opt.det, opt.timeout)?;
    let finished_at = wall_time_iso_utc();
    let duration_ms = started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64;

    let artifacts_dir = config.runs_dir().join(&run_id);
    std::fs::create_dir_all(&artifacts_dir)?;

    let report_path = artifacts_dir.join("report.json");
    let mut trace_path: Option<PathBuf> = None;

    let report_summary = RunSummary {
        status: run.status,
        mode: RunMode::Run,
        identity: RunIdentity {
            run_id: run_id.clone(),
            seed,
            trace_path: None,
            report_path: Some(report_path.to_string_lossy().to_string()),
            artifacts_dir: Some(artifacts_dir.to_string_lossy().to_string()),
        },
        started_at,
        finished_at,
        duration_ms,
        tests: None,
        findings: run.findings.clone(),
    };

    std::fs::write(&report_path, serde_json::to_vec_pretty(&report_summary)?)?;
    std::fs::write(artifacts_dir.join("events.json"), serde_json::to_vec_pretty(&run.events)?)?;
    crate::write_timeline(&run.events, &artifacts_dir.join("timeline.json"))?;

    if matches!(opt.reporter, Reporter::Junit) {
        std::fs::write(artifacts_dir.join("junit.xml"), crate::render_junit_xml(&report_summary))?;
    }
    if matches!(opt.reporter, Reporter::Html) {
        std::fs::write(artifacts_dir.join("report.html"), crate::render_html(&report_summary))?;
    }

    let should_record = opt.record_trace_to.is_some() || run.status != ExitStatus::Pass;
    if should_record {
        let path = opt
            .record_trace_to
            .clone()
            .unwrap_or_else(|| artifacts_dir.join("trace.fozzy"));
        let trace = TraceFile::new(
            RunMode::Run,
            Some(run.scenario_path.to_string_lossy().to_string()),
            Some(run.scenario_embedded),
            run.decisions.decisions,
            run.events,
            report_summary.clone(),
        );
        trace.write_json(&path)?;
        trace_path = Some(path);
    }

    let mut summary = report_summary;
    summary.identity.trace_path = trace_path.map(|p| p.to_string_lossy().to_string());

    Ok(RunResult { summary })
}

pub fn replay_trace(config: &Config, trace_path: TracePath, opt: &ReplayOptions) -> FozzyResult<RunResult> {
    let trace = TraceFile::read_json(trace_path.as_path())?;
    if trace.fuzz.is_some() && trace.scenario.is_none() {
        return crate::replay_fuzz_trace(config, &trace);
    }
    if trace.explore.is_some() && trace.scenario.is_none() {
        return crate::replay_explore_trace(config, &trace);
    }

    let seed = trace.summary.identity.seed;
    let run_id = Uuid::new_v4().to_string();

    let scenario = trace
        .scenario
        .clone()
        .ok_or_else(|| FozzyError::Trace("trace missing embedded scenario; cannot replay".to_string()))?;

    let scenario_path = trace
        .scenario_path
        .clone()
        .unwrap_or_else(|| "<embedded>".to_string());

    let started_at = wall_time_iso_utc();
    let started = Instant::now();

    let run = run_scenario_replay_inner(
        config,
        RunMode::Replay,
        &scenario,
        &scenario_path,
        seed,
        Some(&trace.decisions),
        opt.until,
        opt.step,
    )?;

    let finished_at = wall_time_iso_utc();
    let duration_ms = started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64;

    let artifacts_dir = config.runs_dir().join(&run_id);
    std::fs::create_dir_all(&artifacts_dir)?;
    let report_path = artifacts_dir.join("report.json");

    let summary = RunSummary {
        status: run.status,
        mode: RunMode::Replay,
        identity: RunIdentity {
            run_id,
            seed,
            trace_path: Some(trace_path.as_path().to_string_lossy().to_string()),
            report_path: Some(report_path.to_string_lossy().to_string()),
            artifacts_dir: Some(artifacts_dir.to_string_lossy().to_string()),
        },
        started_at,
        finished_at,
        duration_ms,
        tests: None,
        findings: run.findings.clone(),
    };

    std::fs::write(&report_path, serde_json::to_vec_pretty(&summary)?)?;
    if opt.dump_events {
        std::fs::write(artifacts_dir.join("events.json"), serde_json::to_vec_pretty(&run.events)?)?;
        crate::write_timeline(&run.events, &artifacts_dir.join("timeline.json"))?;
    }

    Ok(RunResult { summary })
}

pub fn shrink_trace(config: &Config, trace_path: TracePath, opt: &ShrinkOptions) -> FozzyResult<ShrinkResult> {
    let trace = TraceFile::read_json(trace_path.as_path())?;
    if trace.fuzz.is_some() && trace.scenario.is_none() {
        return crate::shrink_fuzz_trace(config, trace_path, opt);
    }
    if trace.explore.is_some() && trace.scenario.is_none() {
        return crate::shrink_explore_trace(config, trace_path, opt);
    }
    let target_status = trace.summary.status;
    let seed = trace.summary.identity.seed;

    let scenario = trace
        .scenario
        .clone()
        .ok_or_else(|| FozzyError::Trace("trace missing embedded scenario; cannot shrink".to_string()))?;

    if opt.minimize != ShrinkMinimize::All && opt.minimize != ShrinkMinimize::Input {
        return Err(FozzyError::InvalidArgument(
            "v0.1 shrink only supports input/step shrinking (use --minimize input|all)".to_string(),
        ));
    }

    let budget = opt.budget.unwrap_or(Duration::from_secs(15));
    let deadline = Instant::now() + budget;

    let mut best = scenario.steps.clone();
    let mut candidate = best.clone();

    // Delta-debugging style: try removing chunks of steps while keeping failure.
    let mut chunk = (candidate.len().max(1) + 1) / 2;
    while chunk > 0 && Instant::now() < deadline && candidate.len() > 1 {
        let mut improved = false;
        let mut i = 0usize;
        while i < candidate.len() && Instant::now() < deadline {
            let mut trial = candidate.clone();
            let end = (i + chunk).min(trial.len());
            trial.drain(i..end);
            if trial.is_empty() {
                i += chunk;
                continue;
            }

            let trial_scenario = ScenarioV1Steps {
                version: 1,
                name: scenario.name.clone(),
                steps: trial.clone(),
            };

            let res = run_scenario_replay_inner(
                config,
                RunMode::Run,
                &trial_scenario,
                "<shrunk>",
                seed,
                None, // not replaying decisions; we just want to see if it still fails
                None,
                false,
            )?;
            if shrink_status_matches(target_status, res.status) {
                candidate = trial;
                improved = true;
                continue;
            }

            i += chunk;
        }

        if !improved {
            if chunk == 1 {
                break;
            }
            chunk = (chunk + 1) / 2;
        }
    }

    best = candidate;
    let out_scenario = ScenarioV1Steps {
        version: 1,
        name: scenario.name.clone(),
        steps: best,
    };

    let out_path = opt
        .out_trace_path
        .clone()
        .unwrap_or_else(|| crate::default_min_trace_path(trace_path.as_path()));

    // Re-run once to produce a replayable trace for the minimized scenario.
    let run = run_embedded_scenario_inner(out_scenario.clone(), PathBuf::from("<shrunk>"), seed, true, None)?;

    let run_id = Uuid::new_v4().to_string();
    let started_at = wall_time_iso_utc();
    let finished_at = wall_time_iso_utc();
    let summary = RunSummary {
        status: run.status,
        mode: RunMode::Run,
        identity: RunIdentity {
            run_id,
            seed,
            trace_path: Some(out_path.to_string_lossy().to_string()),
            report_path: None,
            artifacts_dir: None,
        },
        started_at,
        finished_at,
        duration_ms: 0,
        tests: None,
        findings: run.findings.clone(),
    };

    let trace_out = TraceFile::new(
        RunMode::Run,
        None,
        Some(out_scenario),
        run.decisions.decisions,
        run.events,
        summary.clone(),
    );
    trace_out.write_json(&out_path).map_err(|err| {
        FozzyError::Trace(format!(
            "failed to write shrunk trace to {}: {err}",
            out_path.display()
        ))
    })?;

    Ok(ShrinkResult {
        out_trace_path: out_path.to_string_lossy().to_string(),
        result: RunResult { summary },
    })
}

pub(crate) fn shrink_status_matches(target: ExitStatus, candidate: ExitStatus) -> bool {
    if target == ExitStatus::Pass {
        candidate == ExitStatus::Pass
    } else {
        candidate != ExitStatus::Pass
    }
}

pub fn doctor(config: &Config, opt: &DoctorOptions) -> FozzyResult<DoctorReport> {
    let issues = Vec::new();
    let mut signals = Vec::new();

    if std::env::var("TZ").is_ok() {
        signals.push(NondeterminismSignal {
            source: "env".to_string(),
            detail: "TZ is set; local time can affect non-deterministic code paths".to_string(),
        });
    }

    if opt.deep {
        if std::env::var("RUST_BACKTRACE").is_ok() {
            signals.push(NondeterminismSignal {
                source: "env".to_string(),
                detail: "RUST_BACKTRACE is set; ok, but note it can change stderr output".to_string(),
            });
        }
    }
    let mut issues = issues;
    let determinism_audit = if opt.deep {
        if let Some(path) = opt.scenario.clone() {
            let runs = opt.runs.max(2);
            let seed = opt.seed.unwrap_or(0xC0DEC0DE_u64);
            let mut signatures = Vec::with_capacity(runs as usize);
            let mut consistent = true;
            let mut first_mismatch_run = None;
            let mut baseline: Option<String> = None;

            for i in 0..runs {
                let run = run_scenario_inner(config, RunMode::Run, path.clone(), seed, true, None)?;
                let sig = scenario_run_signature(&run);
                if let Some(b) = &baseline {
                    if b != &sig && first_mismatch_run.is_none() {
                        consistent = false;
                        first_mismatch_run = Some(i + 1);
                    }
                } else {
                    baseline = Some(sig.clone());
                }
                signatures.push(sig);
            }

            if !consistent {
                issues.push(DoctorIssue {
                    code: "determinism_audit_mismatch".to_string(),
                    message: format!(
                        "determinism audit mismatch for {} across {} runs (seed={seed})",
                        path.as_path().display(),
                        runs
                    ),
                    hint: Some(
                        "Run `fozzy run --det --seed <seed>` repeatedly and compare traces/events.".to_string(),
                    ),
                });
            }

            Some(DeterminismAudit {
                scenario: path.as_path().display().to_string(),
                runs,
                seed,
                consistent,
                signatures,
                first_mismatch_run,
            })
        } else {
            None
        }
    } else {
        None
    };

    let ok = issues.is_empty();
    Ok(DoctorReport {
        ok,
        issues,
        nondeterminism_signals: if signals.is_empty() { None } else { Some(signals) },
        determinism_audit,
    })
}

fn scenario_run_signature(run: &ScenarioRun) -> String {
    let payload = serde_json::json!({
        "status": run.status,
        "findings": run.findings,
        "decisions": run.decisions.decisions,
        "events": run.events,
    });
    let encoded = serde_json::to_vec(&payload).unwrap_or_default();
    blake3::hash(&encoded).to_hex().to_string()
}

fn gen_seed() -> u64 {
    let mut seed = [0u8; 8];
    rand_core::OsRng.fill_bytes(&mut seed);
    u64::from_le_bytes(seed)
}

#[derive(Debug, Clone)]
struct ScenarioRun {
    status: ExitStatus,
    findings: Vec<Finding>,
    decisions: DecisionLog,
    events: Vec<TraceEvent>,
    scenario_path: PathBuf,
    scenario_embedded: ScenarioV1Steps,
}

fn run_scenario_inner(
    _config: &Config,
    _mode: RunMode,
    scenario_path: ScenarioPath,
    seed: u64,
    det: bool,
    timeout: Option<Duration>,
) -> FozzyResult<ScenarioRun> {
    let loaded = Scenario::load(&scenario_path)?;
    loaded.validate()?;

    let embedded = ScenarioV1Steps {
        version: 1,
        name: loaded.name.clone(),
        steps: loaded.steps.clone(),
    };

    run_embedded_scenario_inner(embedded, scenario_path.as_path().to_path_buf(), seed, det, timeout)
}

fn run_embedded_scenario_inner(
    scenario: ScenarioV1Steps,
    scenario_path: PathBuf,
    seed: u64,
    det: bool,
    timeout: Option<Duration>,
) -> FozzyResult<ScenarioRun> {
    let mut ctx = ExecCtx::new(seed, det);
    let started = Instant::now();
    let start_virtual_ms = ctx.clock.now_ms();
    let deadline = timeout.map(|t| started + t);
    let mut scheduler = crate::DeterministicScheduler::new(crate::SchedulerMode::Fifo, seed);
    for (idx, step) in scenario.steps.iter().enumerate() {
        scheduler.enqueue(step.kind_name().to_string(), idx);
    }

    while let Some(item) = scheduler.pop_next() {
        let idx = item.payload;
        let step = &scenario.steps[idx];
        if timeout_reached(&ctx, det, timeout, deadline, start_virtual_ms) {
            ctx.findings.push(Finding {
                kind: FindingKind::Hang,
                title: "timeout".to_string(),
                message: "scenario timed out".to_string(),
                location: None,
            });
            return Ok(ctx.finish(ExitStatus::Timeout, scenario_path, scenario));
        }

        ctx.decisions.push(Decision::SchedulerPick {
            task_id: item.id,
            label: item.label,
        });
        if let Err(finding) = ctx.exec_step(step) {
            ctx.findings.push(finding);
            return Ok(ctx.finish(ExitStatus::Fail, scenario_path, scenario));
        }

        if timeout_reached(&ctx, det, timeout, deadline, start_virtual_ms) {
            ctx.findings.push(Finding {
                kind: FindingKind::Hang,
                title: "timeout".to_string(),
                message: "scenario timed out".to_string(),
                location: None,
            });
            return Ok(ctx.finish(ExitStatus::Timeout, scenario_path, scenario));
        }
    }

    Ok(ctx.finish(ExitStatus::Pass, scenario_path, scenario))
}

fn timeout_reached(
    ctx: &ExecCtx,
    det: bool,
    timeout: Option<Duration>,
    deadline: Option<Instant>,
    start_virtual_ms: u64,
) -> bool {
    let Some(limit) = timeout else {
        return false;
    };
    if det {
        let elapsed_ms = ctx.clock.now_ms().saturating_sub(start_virtual_ms);
        elapsed_ms >= limit.as_millis().min(u128::from(u64::MAX)) as u64
    } else {
        deadline.is_some_and(|dl| Instant::now() > dl)
    }
}

fn run_scenario_replay_inner(
    _config: &Config,
    _mode: RunMode,
    scenario: &ScenarioV1Steps,
    scenario_path: &str,
    seed: u64,
    decisions: Option<&[Decision]>,
    until: Option<Duration>,
    step: bool,
) -> FozzyResult<ScenarioRun> {
    if scenario.version != 1 {
        return Err(FozzyError::Scenario(format!(
            "unsupported scenario version {} (expected 1)",
            scenario.version
        )));
    }

    let mut ctx = ExecCtx::new(seed, true);
    if let Some(d) = decisions {
        ctx.replay = Some(ReplayCursor::new(d));
    }
    let has_scheduler_pick = decisions
        .map(|d| d.iter().any(|x| matches!(x, Decision::SchedulerPick { .. })))
        .unwrap_or(false);

    let started = Instant::now();
    let deadline = until.map(|t| started + t);

    if has_scheduler_pick {
        let mut scheduler = crate::DeterministicScheduler::new(crate::SchedulerMode::Fifo, seed);
        for (idx, step) in scenario.steps.iter().enumerate() {
            scheduler.enqueue(step.kind_name().to_string(), idx);
        }
        while let Some(item) = scheduler.pop_next() {
            let idx = item.payload;
            let step_def = &scenario.steps[idx];
            if let Some(dl) = deadline {
                if Instant::now() > dl {
                    ctx.findings.push(Finding {
                        kind: FindingKind::Hang,
                        title: "until".to_string(),
                        message: "replay stopped at --until budget".to_string(),
                        location: None,
                    });
                    return Ok(ctx.finish(ExitStatus::Timeout, PathBuf::from(scenario_path), scenario.clone()));
                }
            }

            if step {
                std::thread::sleep(Duration::from_millis(10));
            }

            ctx.expect_scheduler_pick(item.id, &item.label)?;
            if let Err(finding) = ctx.exec_step(step_def) {
                ctx.findings.push(finding);
                return Ok(ctx.finish(ExitStatus::Fail, PathBuf::from(scenario_path), scenario.clone()));
            }
        }
    } else {
        for (idx, step_def) in scenario.steps.iter().enumerate() {
            if let Some(dl) = deadline {
                if Instant::now() > dl {
                    ctx.findings.push(Finding {
                        kind: FindingKind::Hang,
                        title: "until".to_string(),
                        message: "replay stopped at --until budget".to_string(),
                        location: None,
                    });
                    return Ok(ctx.finish(ExitStatus::Timeout, PathBuf::from(scenario_path), scenario.clone()));
                }
            }

            if step {
                std::thread::sleep(Duration::from_millis(10));
            }

            ctx.expect_step(idx)?;
            if let Err(finding) = ctx.exec_step(step_def) {
                ctx.findings.push(finding);
                return Ok(ctx.finish(ExitStatus::Fail, PathBuf::from(scenario_path), scenario.clone()));
            }
        }
    }

    if let Some(cursor) = ctx.replay.as_ref() {
        if cursor.remaining() > 0 {
            ctx.findings.push(Finding {
                kind: FindingKind::Checker,
                title: "replay_unused_decisions".to_string(),
                message: format!("replay finished with {} unused decisions", cursor.remaining()),
                location: None,
            });
            return Ok(ctx.finish(ExitStatus::Fail, PathBuf::from(scenario_path), scenario.clone()));
        }
    }

    Ok(ctx.finish(ExitStatus::Pass, PathBuf::from(scenario_path), scenario.clone()))
}

#[derive(Debug, Clone)]
struct ExecCtx {
    det: bool,
    rng: ChaCha20Rng,
    clock: crate::VirtualClock,
    kv: BTreeMap<String, String>,
    fs: BTreeMap<String, String>,
    fs_snapshots: BTreeMap<String, BTreeMap<String, String>>,
    http_rules: Vec<HttpRule>,
    proc_rules: Vec<ProcRule>,
    net_queue: Vec<NetMessage>,
    net_inbox: BTreeMap<String, Vec<NetMessage>>,
    net_partitions: BTreeSet<(String, String)>,
    net_next_id: u64,
    net_drop_rate: f64,
    net_reorder: bool,
    decisions: DecisionLog,
    events: Vec<TraceEvent>,
    findings: Vec<Finding>,
    replay: Option<ReplayCursor>,
}

impl ExecCtx {
    fn new(seed: u64, det: bool) -> Self {
        let seed_bytes = blake3::hash(&seed.to_le_bytes()).as_bytes().to_owned();
        let mut seed32 = [0u8; 32];
        seed32.copy_from_slice(&seed_bytes[..32]);
        let rng = ChaCha20Rng::from_seed(seed32);
        Self {
            det,
            rng,
            clock: crate::VirtualClock::default(),
            kv: BTreeMap::new(),
            fs: BTreeMap::new(),
            fs_snapshots: BTreeMap::new(),
            http_rules: Vec::new(),
            proc_rules: Vec::new(),
            net_queue: Vec::new(),
            net_inbox: BTreeMap::new(),
            net_partitions: BTreeSet::new(),
            net_next_id: 1,
            net_drop_rate: 0.0,
            net_reorder: false,
            decisions: DecisionLog::default(),
            events: Vec::new(),
            findings: Vec::new(),
            replay: None,
        }
    }

    fn finish(self, status: ExitStatus, scenario_path: PathBuf, embedded: ScenarioV1Steps) -> ScenarioRun {
        ScenarioRun {
            status,
            findings: self.findings,
            decisions: self.decisions,
            events: self.events,
            scenario_path,
            scenario_embedded: embedded,
        }
    }

    fn expect_step(&mut self, idx: usize) -> FozzyResult<()> {
        let Some(cursor) = self.replay.as_mut() else {
            return Ok(());
        };
        match cursor.next() {
            Some(Decision::Step { index, .. }) if *index == idx => Ok(()),
            Some(other) => Err(FozzyError::Trace(format!("replay drift at step {idx}: expected step decision, got {other:?}"))),
            None => Err(FozzyError::Trace(format!("replay drift at step {idx}: missing decision"))),
        }
    }

    fn expect_scheduler_pick(&mut self, task_id: u64, _label: &str) -> FozzyResult<()> {
        let Some(cursor) = self.replay.as_mut() else {
            return Ok(());
        };
        match cursor.next() {
            Some(Decision::SchedulerPick {
                task_id: expected_id,
                ..
            }) if *expected_id == task_id => Ok(()),
            Some(other) => Err(FozzyError::Trace(format!(
                "replay drift: expected SchedulerPick(task_id={task_id}), got {other:?}"
            ))),
            None => Err(FozzyError::Trace(
                "replay drift: missing SchedulerPick decision".to_string(),
            )),
        }
    }

    fn replay_peek(&self) -> Option<&Decision> {
        self.replay.as_ref().and_then(|c| c.peek())
    }

    fn replay_take_if<F>(&mut self, pred: F) -> Option<Decision>
    where
        F: FnOnce(&Decision) -> bool,
    {
        let cursor = self.replay.as_mut()?;
        let next = cursor.peek()?;
        if pred(next) {
            cursor.next().cloned()
        } else {
            None
        }
    }

    fn exec_step(&mut self, step: &crate::Step) -> Result<(), Finding> {
        match step {
            crate::Step::TraceEvent { name, fields } => {
                self.events.push(TraceEvent {
                    time_ms: self.clock.now_ms(),
                    name: name.clone(),
                    fields: fields.clone(),
                });
                Ok(())
            }

            crate::Step::RandU64 { key } => {
                let value = self.rng.next_u64();
                self.decisions.push(Decision::RandU64 { value });
                if let Some(cur) = self.replay.as_mut() {
                    match cur.next() {
                        Some(Decision::RandU64 { value: expected }) if *expected == value => {}
                        Some(other) => {
                            return Err(Finding {
                                kind: FindingKind::Checker,
                                title: "replay_drift".to_string(),
                                message: format!("expected RandU64({value}), got {other:?}"),
                                location: None,
                            });
                        }
                        None => {
                            return Err(Finding {
                                kind: FindingKind::Checker,
                                title: "replay_drift".to_string(),
                                message: "missing RandU64 decision".to_string(),
                                location: None,
                            });
                        }
                    }
                }
                if let Some(key) = key {
                    self.kv.insert(key.clone(), value.to_string());
                }
                Ok(())
            }

            crate::Step::AssertOk { value, msg } => {
                if !value {
                    return Err(Finding {
                        kind: FindingKind::Assertion,
                        title: "assert_ok".to_string(),
                        message: msg.clone().unwrap_or_else(|| "assert_ok failed".to_string()),
                        location: None,
                    });
                }
                Ok(())
            }

            crate::Step::AssertEqInt { a, b, msg } => {
                if a != b {
                    return Err(Finding {
                        kind: FindingKind::Assertion,
                        title: "assert_eq_int".to_string(),
                        message: msg.clone().unwrap_or_else(|| format!("expected {a} == {b}")),
                        location: None,
                    });
                }
                Ok(())
            }

            crate::Step::AssertNeInt { a, b, msg } => {
                if a == b {
                    return Err(Finding {
                        kind: FindingKind::Assertion,
                        title: "assert_ne_int".to_string(),
                        message: msg.clone().unwrap_or_else(|| format!("expected {a} != {b}")),
                        location: None,
                    });
                }
                Ok(())
            }

            crate::Step::AssertEqStr { a, b, msg } => {
                if a != b {
                    return Err(Finding {
                        kind: FindingKind::Assertion,
                        title: "assert_eq_str".to_string(),
                        message: msg.clone().unwrap_or_else(|| format!("expected {a:?} == {b:?}")),
                        location: None,
                    });
                }
                Ok(())
            }

            crate::Step::AssertNeStr { a, b, msg } => {
                if a == b {
                    return Err(Finding {
                        kind: FindingKind::Assertion,
                        title: "assert_ne_str".to_string(),
                        message: msg.clone().unwrap_or_else(|| format!("expected {a:?} != {b:?}")),
                        location: None,
                    });
                }
                Ok(())
            }

            crate::Step::Sleep { duration } => {
                let d = crate::parse_duration(duration).map_err(|e| Finding {
                    kind: FindingKind::Checker,
                    title: "invalid_duration".to_string(),
                    message: e.to_string(),
                    location: None,
                })?;
                let ms = d.as_millis().min(u128::from(u64::MAX)) as u64;
                if self.det {
                    self.clock.sleep(d);
                    self.decisions.push(Decision::TimeSleepMs { ms });
                } else {
                    std::thread::sleep(d);
                }
                if let Some(cur) = self.replay.as_mut() {
                    match cur.next() {
                        Some(Decision::TimeSleepMs { ms: expected }) if *expected == ms => {}
                        Some(other) => {
                            return Err(Finding {
                                kind: FindingKind::Checker,
                                title: "replay_drift".to_string(),
                                message: format!("expected TimeSleepMs({ms}), got {other:?}"),
                                location: None,
                            });
                        }
                        None => {
                            return Err(Finding {
                                kind: FindingKind::Checker,
                                title: "replay_drift".to_string(),
                                message: "missing TimeSleepMs decision".to_string(),
                                location: None,
                            });
                        }
                    }
                }
                Ok(())
            }

            crate::Step::Advance { duration } => {
                let d = crate::parse_duration(duration).map_err(|e| Finding {
                    kind: FindingKind::Checker,
                    title: "invalid_duration".to_string(),
                    message: e.to_string(),
                    location: None,
                })?;
                let ms = d.as_millis().min(u128::from(u64::MAX)) as u64;
                if !self.det {
                    return Err(Finding {
                        kind: FindingKind::Checker,
                        title: "advance_requires_det".to_string(),
                        message: "Advance is only supported in deterministic mode (--det)".to_string(),
                        location: None,
                    });
                }

                self.clock.advance(d);
                self.decisions.push(Decision::TimeAdvanceMs { ms });
                if let Some(cur) = self.replay.as_mut() {
                    match cur.next() {
                        Some(Decision::TimeAdvanceMs { ms: expected }) if *expected == ms => {}
                        Some(other) => {
                            return Err(Finding {
                                kind: FindingKind::Checker,
                                title: "replay_drift".to_string(),
                                message: format!("expected TimeAdvanceMs({ms}), got {other:?}"),
                                location: None,
                            });
                        }
                        None => {
                            return Err(Finding {
                                kind: FindingKind::Checker,
                                title: "replay_drift".to_string(),
                                message: "missing TimeAdvanceMs decision".to_string(),
                                location: None,
                            });
                        }
                    }
                }
                Ok(())
            }

            crate::Step::Freeze { at_ms } => {
                self.clock.freeze(*at_ms);
                Ok(())
            }

            crate::Step::Unfreeze => {
                self.clock.unfreeze();
                Ok(())
            }

            crate::Step::SetKv { key, value } => {
                self.kv.insert(key.clone(), value.clone());
                Ok(())
            }

            crate::Step::GetKvAssert { key, equals, is_null } => {
                let v = self.kv.get(key).cloned();
                if is_null.unwrap_or(false) {
                    if v.is_some() {
                        return Err(Finding {
                            kind: FindingKind::Assertion,
                            title: "get_kv_assert".to_string(),
                            message: format!("expected {key:?} to be null"),
                            location: None,
                        });
                    }
                    return Ok(());
                }

                if let Some(expected) = equals {
                    if v.as_deref() != Some(expected.as_str()) {
                        return Err(Finding {
                            kind: FindingKind::Assertion,
                            title: "get_kv_assert".to_string(),
                            message: format!("expected {key:?} == {expected:?}, got {v:?}"),
                            location: None,
                        });
                    }
                } else if v.is_none() {
                    return Err(Finding {
                        kind: FindingKind::Assertion,
                        title: "get_kv_assert".to_string(),
                        message: format!("expected {key:?} to exist"),
                        location: None,
                    });
                }

                Ok(())
            }

            crate::Step::FsWrite { path, data } => {
                self.fs.insert(path.clone(), data.clone());
                Ok(())
            }

            crate::Step::FsReadAssert { path, equals } => {
                let got = self.fs.get(path).cloned();
                if got.as_deref() != Some(equals.as_str()) {
                    return Err(Finding {
                        kind: FindingKind::Assertion,
                        title: "fs_read_assert".to_string(),
                        message: format!("expected {path:?} == {equals:?}, got {got:?}"),
                        location: None,
                    });
                }
                Ok(())
            }

            crate::Step::FsSnapshot { name } => {
                self.fs_snapshots.insert(name.clone(), self.fs.clone());
                Ok(())
            }

            crate::Step::FsRestore { name } => {
                let Some(snapshot) = self.fs_snapshots.get(name).cloned() else {
                    return Err(Finding {
                        kind: FindingKind::Checker,
                        title: "fs_restore_missing_snapshot".to_string(),
                        message: format!("missing fs snapshot {name:?}"),
                        location: None,
                    });
                };
                self.fs = snapshot;
                Ok(())
            }

            crate::Step::HttpWhen {
                method,
                path,
                status,
                body,
                json,
                delay,
                times,
            } => {
                if body.is_some() && json.is_some() {
                    return Err(Finding {
                        kind: FindingKind::Checker,
                        title: "http_when_invalid".to_string(),
                        message: "HttpWhen: cannot set both body and json".to_string(),
                        location: None,
                    });
                }

                let delay_ms = if let Some(d) = delay {
                    let dur = crate::parse_duration(d).map_err(|e| Finding {
                        kind: FindingKind::Checker,
                        title: "invalid_duration".to_string(),
                        message: e.to_string(),
                        location: None,
                    })?;
                    dur.as_millis().min(u128::from(u64::MAX)) as u64
                } else {
                    0
                };

                self.http_rules.push(HttpRule {
                    method: method.clone(),
                    path: path.clone(),
                    status: *status,
                    body: body.clone(),
                    json: json.clone(),
                    delay_ms,
                    remaining: times.unwrap_or(u64::MAX),
                });
                Ok(())
            }

            crate::Step::HttpRequest {
                method,
                path,
                body,
                expect_status,
                expect_body,
                expect_json,
                save_body_as,
            } => {
                if expect_body.is_some() && expect_json.is_some() {
                    return Err(Finding {
                        kind: FindingKind::Checker,
                        title: "http_request_invalid".to_string(),
                        message: "HttpRequest: cannot set both expect_body and expect_json".to_string(),
                        location: None,
                    });
                }

                let rule_idx = self
                    .http_rules
                    .iter()
                    .position(|r| r.remaining > 0 && r.method == *method && r.path == *path);

                let Some(idx) = rule_idx else {
                    return Err(Finding {
                        kind: FindingKind::Assertion,
                        title: "http_unmatched".to_string(),
                        message: format!("no http mock matched {method} {path}"),
                        location: None,
                    });
                };

                let mut rule = self.http_rules[idx].clone();
                if rule.remaining != u64::MAX {
                    rule.remaining = rule.remaining.saturating_sub(1);
                }
                self.http_rules[idx] = rule.clone();

                if self.det && rule.delay_ms > 0 {
                    self.clock.advance(Duration::from_millis(rule.delay_ms));
                } else if !self.det && rule.delay_ms > 0 {
                    std::thread::sleep(Duration::from_millis(rule.delay_ms));
                }

                let resp_body = if let Some(j) = &rule.json {
                    serde_json::to_string(j).map_err(|e| Finding {
                        kind: FindingKind::Checker,
                        title: "http_json_serialize".to_string(),
                        message: e.to_string(),
                        location: None,
                    })?
                } else {
                    rule.body.clone().unwrap_or_default()
                };

                self.events.push(TraceEvent {
                    time_ms: self.clock.now_ms(),
                    name: "http_request".to_string(),
                    fields: serde_json::Map::from_iter([
                        ("method".to_string(), serde_json::Value::String(method.clone())),
                        ("path".to_string(), serde_json::Value::String(path.clone())),
                        (
                            "status".to_string(),
                            serde_json::Value::Number(serde_json::Number::from(rule.status)),
                        ),
                        (
                            "has_body".to_string(),
                            serde_json::Value::Bool(!resp_body.is_empty()),
                        ),
                    ]),
                });

                if let Some(expected) = expect_status {
                    if rule.status != *expected {
                        return Err(Finding {
                            kind: FindingKind::Assertion,
                            title: "http_status".to_string(),
                            message: format!("expected status {expected}, got {}", rule.status),
                            location: None,
                        });
                    }
                }

                if let Some(expected) = expect_body {
                    if resp_body != *expected {
                        return Err(Finding {
                            kind: FindingKind::Assertion,
                            title: "http_body".to_string(),
                            message: "http response body mismatch".to_string(),
                            location: None,
                        });
                    }
                }

                if let Some(expected) = expect_json {
                    let got: serde_json::Value = serde_json::from_str(&resp_body).map_err(|e| Finding {
                        kind: FindingKind::Assertion,
                        title: "http_json_parse".to_string(),
                        message: e.to_string(),
                        location: None,
                    })?;
                    if got != *expected {
                        return Err(Finding {
                            kind: FindingKind::Assertion,
                            title: "http_json".to_string(),
                            message: "http response json mismatch".to_string(),
                            location: None,
                        });
                    }
                }

                if let Some(key) = save_body_as {
                    self.kv.insert(key.clone(), resp_body);
                }

                let _ = body;
                Ok(())
            }

            crate::Step::ProcWhen {
                cmd,
                args,
                exit_code,
                stdout,
                stderr,
                times,
            } => {
                self.proc_rules.push(ProcRule {
                    cmd: cmd.clone(),
                    args: args.clone().unwrap_or_default(),
                    exit_code: *exit_code,
                    stdout: stdout.clone().unwrap_or_default(),
                    stderr: stderr.clone().unwrap_or_default(),
                    remaining: times.unwrap_or(u64::MAX),
                });
                Ok(())
            }

            crate::Step::ProcSpawn {
                cmd,
                args,
                expect_exit,
                expect_stdout,
                expect_stderr,
                save_stdout_as,
            } => {
                let call_args = args.clone().unwrap_or_default();
                let idx = self.proc_rules.iter().position(|r| {
                    r.remaining > 0 && r.cmd == *cmd && r.args == call_args
                });
                let Some(idx) = idx else {
                    return Err(Finding {
                        kind: FindingKind::Assertion,
                        title: "proc_unmatched".to_string(),
                        message: format!("no proc mock matched {cmd:?} {:?}", call_args),
                        location: None,
                    });
                };

                let mut rule = self.proc_rules[idx].clone();
                if rule.remaining != u64::MAX {
                    rule.remaining = rule.remaining.saturating_sub(1);
                }
                self.proc_rules[idx] = rule.clone();

                self.events.push(TraceEvent {
                    time_ms: self.clock.now_ms(),
                    name: "proc_spawn".to_string(),
                    fields: serde_json::Map::from_iter([
                        ("cmd".to_string(), serde_json::Value::String(cmd.clone())),
                        (
                            "exit_code".to_string(),
                            serde_json::Value::Number(serde_json::Number::from(rule.exit_code)),
                        ),
                    ]),
                });

                if let Some(expected) = expect_exit {
                    if rule.exit_code != *expected {
                        return Err(Finding {
                            kind: FindingKind::Assertion,
                            title: "proc_exit".to_string(),
                            message: format!("expected exit {expected}, got {}", rule.exit_code),
                            location: None,
                        });
                    }
                }
                if let Some(expected) = expect_stdout {
                    if &rule.stdout != expected {
                        return Err(Finding {
                            kind: FindingKind::Assertion,
                            title: "proc_stdout".to_string(),
                            message: "proc stdout mismatch".to_string(),
                            location: None,
                        });
                    }
                }
                if let Some(expected) = expect_stderr {
                    if &rule.stderr != expected {
                        return Err(Finding {
                            kind: FindingKind::Assertion,
                            title: "proc_stderr".to_string(),
                            message: "proc stderr mismatch".to_string(),
                            location: None,
                        });
                    }
                }
                if let Some(key) = save_stdout_as {
                    self.kv.insert(key.clone(), rule.stdout.clone());
                }

                Ok(())
            }

            crate::Step::NetPartition { a, b } => {
                self.net_partitions.insert(sorted_pair(a, b));
                Ok(())
            }

            crate::Step::NetHeal { a, b } => {
                self.net_partitions.remove(&sorted_pair(a, b));
                Ok(())
            }

            crate::Step::NetSetDropRate { rate } => {
                if !(0.0..=1.0).contains(rate) {
                    return Err(Finding {
                        kind: FindingKind::Checker,
                        title: "net_drop_rate".to_string(),
                        message: format!("invalid drop rate {rate}; expected [0,1]"),
                        location: None,
                    });
                }
                self.net_drop_rate = *rate;
                Ok(())
            }

            crate::Step::NetSetReorder { enabled } => {
                self.net_reorder = *enabled;
                Ok(())
            }

            crate::Step::NetSend { from, to, payload } => {
                let id = self.net_next_id;
                self.net_next_id = self.net_next_id.saturating_add(1);
                self.net_queue.push(NetMessage {
                    id,
                    from: from.clone(),
                    to: to.clone(),
                    payload: payload.clone(),
                });
                Ok(())
            }

            crate::Step::NetDeliverOne { strategy } => {
                let mut deliverable = Vec::new();
                for (idx, msg) in self.net_queue.iter().enumerate() {
                    if self.net_partitions.contains(&sorted_pair(&msg.from, &msg.to)) {
                        continue;
                    }
                    deliverable.push((idx, msg.id));
                }
                if deliverable.is_empty() {
                    return Err(Finding {
                        kind: FindingKind::Assertion,
                        title: "net_deliver".to_string(),
                        message: "no deliverable network message".to_string(),
                        location: None,
                    });
                }

                let use_random = strategy
                    .as_deref()
                    .map(|s| s.eq_ignore_ascii_case("random"))
                    .unwrap_or(self.net_reorder);

                let picked_message_id = match self.replay_peek() {
                    Some(Decision::NetDeliverPick { message_id }) => {
                        let id = *message_id;
                        if !deliverable.iter().any(|(_, m)| *m == id) {
                            return Err(Finding {
                                kind: FindingKind::Checker,
                                title: "replay_drift".to_string(),
                                message: format!(
                                    "replay net delivery drift: message id {id} is not deliverable"
                                ),
                                location: None,
                            });
                        }
                        let _ = self.replay_take_if(|d| matches!(d, Decision::NetDeliverPick { .. }));
                        id
                    }
                    _ => {
                        let pick_pos = if use_random {
                            (self.rng.next_u64() as usize) % deliverable.len()
                        } else {
                            0
                        };
                        deliverable[pick_pos].1
                    }
                };
                self.decisions.push(Decision::NetDeliverPick {
                    message_id: picked_message_id,
                });

                let Some((idx, _)) = deliverable.into_iter().find(|(_, id)| *id == picked_message_id) else {
                    return Err(Finding {
                        kind: FindingKind::Checker,
                        title: "net_deliver".to_string(),
                        message: format!("selected message id {picked_message_id} no longer in queue"),
                        location: None,
                    });
                };
                let msg = self.net_queue.remove(idx);

                if let Some(Decision::NetDrop { message_id, .. }) = self.replay_peek() {
                    if *message_id != msg.id {
                        return Err(Finding {
                            kind: FindingKind::Checker,
                            title: "replay_drift".to_string(),
                            message: format!(
                                "replay net drop drift: expected message id {}, got {}",
                                msg.id, message_id
                            ),
                            location: None,
                        });
                    }
                }

                let should_drop = match self.replay_take_if(|d| {
                    matches!(d, Decision::NetDrop { message_id, .. } if *message_id == msg.id)
                }) {
                    Some(Decision::NetDrop { dropped, .. }) => dropped,
                    _ => {
                        if self.net_drop_rate <= 0.0 {
                            false
                        } else {
                            let sample = (self.rng.next_u64() as f64) / (u64::MAX as f64);
                            sample < self.net_drop_rate
                        }
                    }
                };
                self.decisions.push(Decision::NetDrop {
                    message_id: msg.id,
                    dropped: should_drop,
                });

                if should_drop {
                    self.events.push(TraceEvent {
                        time_ms: self.clock.now_ms(),
                        name: "net_drop".to_string(),
                        fields: serde_json::Map::from_iter([
                            ("id".to_string(), serde_json::Value::Number(msg.id.into())),
                            ("from".to_string(), serde_json::Value::String(msg.from)),
                            ("to".to_string(), serde_json::Value::String(msg.to)),
                        ]),
                    });
                    return Ok(());
                }

                self.net_inbox.entry(msg.to.clone()).or_default().push(msg.clone());
                self.events.push(TraceEvent {
                    time_ms: self.clock.now_ms(),
                    name: "net_deliver".to_string(),
                    fields: serde_json::Map::from_iter([
                        ("id".to_string(), serde_json::Value::Number(msg.id.into())),
                        ("from".to_string(), serde_json::Value::String(msg.from)),
                        ("to".to_string(), serde_json::Value::String(msg.to)),
                    ]),
                });
                Ok(())
            }

            crate::Step::NetRecvAssert { node, from, payload } => {
                let inbox = self.net_inbox.entry(node.clone()).or_default();
                let pos = inbox.iter().position(|m| {
                    if let Some(f) = from {
                        if &m.from != f {
                            return false;
                        }
                    }
                    m.payload == *payload
                });
                let Some(pos) = pos else {
                    return Err(Finding {
                        kind: FindingKind::Assertion,
                        title: "net_recv_assert".to_string(),
                        message: format!("no matching inbox message for node {node:?} payload {payload:?}"),
                        location: None,
                    });
                };
                inbox.remove(pos);
                Ok(())
            }

            crate::Step::AssertThrows { steps } => self.exec_expect_failure("assert_throws", steps),
            crate::Step::AssertRejects { steps } => self.exec_expect_failure("assert_rejects", steps),

            crate::Step::AssertEventuallyKv {
                key,
                equals,
                within,
                poll,
                msg,
            } => {
                let within_d = crate::parse_duration(within).map_err(|e| Finding {
                    kind: FindingKind::Checker,
                    title: "invalid_duration".to_string(),
                    message: e.to_string(),
                    location: None,
                })?;
                let poll_d = crate::parse_duration(poll).map_err(|e| Finding {
                    kind: FindingKind::Checker,
                    title: "invalid_duration".to_string(),
                    message: e.to_string(),
                    location: None,
                })?;

                let deadline = Instant::now() + within_d;
                loop {
                    if self.kv.get(key).is_some_and(|v| v == equals) {
                        return Ok(());
                    }
                    if Instant::now() >= deadline {
                        return Err(Finding {
                            kind: FindingKind::Assertion,
                            title: "assert_eventually_kv".to_string(),
                            message: msg.clone().unwrap_or_else(|| {
                                format!("key {key:?} did not become {equals:?} within {}", within)
                            }),
                            location: None,
                        });
                    }
                    self.sleep_poll(poll_d);
                }
            }

            crate::Step::AssertNeverKv {
                key,
                equals,
                within,
                poll,
                msg,
            } => {
                let within_d = crate::parse_duration(within).map_err(|e| Finding {
                    kind: FindingKind::Checker,
                    title: "invalid_duration".to_string(),
                    message: e.to_string(),
                    location: None,
                })?;
                let poll_d = crate::parse_duration(poll).map_err(|e| Finding {
                    kind: FindingKind::Checker,
                    title: "invalid_duration".to_string(),
                    message: e.to_string(),
                    location: None,
                })?;

                let deadline = Instant::now() + within_d;
                loop {
                    if self.kv.get(key).is_some_and(|v| v == equals) {
                        return Err(Finding {
                            kind: FindingKind::Assertion,
                            title: "assert_never_kv".to_string(),
                            message: msg
                                .clone()
                                .unwrap_or_else(|| format!("key {key:?} became forbidden value {equals:?}")),
                            location: None,
                        });
                    }
                    if Instant::now() >= deadline {
                        return Ok(());
                    }
                    self.sleep_poll(poll_d);
                }
            }

            crate::Step::Fail { message } => Err(Finding {
                kind: FindingKind::Assertion,
                title: "fail".to_string(),
                message: message.clone(),
                location: None,
            }),

            crate::Step::Panic { message } => Err(Finding {
                kind: FindingKind::Panic,
                title: "panic".to_string(),
                message: message.clone(),
                location: None,
            }),
        }
    }

    fn exec_expect_failure(&mut self, title: &str, steps: &[crate::Step]) -> Result<(), Finding> {
        let mut shadow = self.clone();
        shadow.replay = None;
        shadow.decisions = DecisionLog::default();
        shadow.events.clear();
        shadow.findings.clear();

        for s in steps {
            if shadow.exec_step(s).is_err() {
                return Ok(());
            }
        }

        Err(Finding {
            kind: FindingKind::Assertion,
            title: title.to_string(),
            message: format!("{title} expected failure but nested steps passed"),
            location: None,
        })
    }

    fn sleep_poll(&mut self, d: Duration) {
        if self.det {
            self.clock.advance(d);
        } else {
            std::thread::sleep(d);
        }
    }
}

#[derive(Debug, Clone)]
struct HttpRule {
    method: String,
    path: String,
    status: u16,
    body: Option<String>,
    json: Option<serde_json::Value>,
    delay_ms: u64,
    remaining: u64,
}

#[derive(Debug, Clone)]
struct ProcRule {
    cmd: String,
    args: Vec<String>,
    exit_code: i32,
    stdout: String,
    stderr: String,
    remaining: u64,
}

#[derive(Debug, Clone)]
struct NetMessage {
    id: u64,
    from: String,
    to: String,
    payload: String,
}

fn sorted_pair(a: &str, b: &str) -> (String, String) {
    if a <= b {
        (a.to_string(), b.to_string())
    } else {
        (b.to_string(), a.to_string())
    }
}

#[derive(Debug, Clone)]
struct ReplayCursor {
    decisions: Vec<Decision>,
    index: usize,
}

impl ReplayCursor {
    fn new(decisions: &[Decision]) -> Self {
        Self {
            decisions: decisions.to_vec(),
            index: 0,
        }
    }

    fn next(&mut self) -> Option<&Decision> {
        let d = self.decisions.get(self.index);
        self.index = self.index.saturating_add(1);
        d
    }

    fn peek(&self) -> Option<&Decision> {
        self.decisions.get(self.index)
    }

    fn remaining(&self) -> usize {
        self.decisions.len().saturating_sub(self.index)
    }
}
