//! Fuzzing engine (v0.2): mutation + simple coverage feedback + crash recording.
//!
//! This is intentionally self-contained so fuzz targets can evolve without
//! entangling the core scenario runner.

use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore as _, SeedableRng as _};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::{
    wall_time_iso_utc, Config, ExitStatus, Finding, FindingKind, Reporter, RunIdentity, RunMode,
    RunSummary, TraceEvent, TraceFile,
};

use crate::{FozzyError, FozzyResult};

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FuzzMode {
    Coverage,
    Property,
}

impl clap::ValueEnum for FuzzMode {
    fn value_variants<'a>() -> &'a [Self] {
        &[Self::Coverage, Self::Property]
    }

    fn to_possible_value(&self) -> Option<clap::builder::PossibleValue> {
        Some(match self {
            Self::Coverage => clap::builder::PossibleValue::new("coverage"),
            Self::Property => clap::builder::PossibleValue::new("property"),
        })
    }
}

#[derive(Debug, Clone)]
pub enum FuzzTarget {
    Function { id: String },
}

impl std::str::FromStr for FuzzTarget {
    type Err = FozzyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();
        if let Some(rest) = s.strip_prefix("fn:") {
            let id = rest.trim().to_string();
            if id.is_empty() {
                return Err(FozzyError::InvalidArgument("fuzz target fn: requires an id".to_string()));
            }
            return Ok(Self::Function { id });
        }

        Err(FozzyError::InvalidArgument(format!(
            "unsupported fuzz target {s:?} (expected fn:<id>)"
        )))
    }
}

#[derive(Debug, Clone)]
pub struct FuzzOptions {
    pub mode: FuzzMode,
    pub seed: Option<u64>,
    pub time: Option<Duration>,
    pub runs: Option<u64>,
    pub max_input_bytes: usize,
    pub corpus_dir: Option<PathBuf>,
    pub mutator: Option<String>,
    pub shrink: bool,
    pub record_trace_to: Option<PathBuf>,
    pub reporter: Reporter,
    pub crash_only: bool,
    pub minimize: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuzzTrace {
    pub target: String,
    pub input_hex: String,
}

pub fn fuzz(config: &Config, target: &FuzzTarget, opt: &FuzzOptions) -> FozzyResult<crate::RunResult> {
    let seed = opt.seed.unwrap_or_else(gen_seed);
    let run_id = Uuid::new_v4().to_string();
    let started_at = wall_time_iso_utc();
    let started = Instant::now();

    let artifacts_dir = config.runs_dir().join(&run_id);
    std::fs::create_dir_all(&artifacts_dir)?;

    let corpus_dir = opt
        .corpus_dir
        .clone()
        .unwrap_or_else(|| config.corpora_dir().join("default"));
    std::fs::create_dir_all(&corpus_dir)?;
    std::fs::create_dir_all(corpus_dir.join("crashes"))?;

    let mut rng = rng_from_seed(seed);
    let deadline = opt.time.map(|t| started + t);
    let max_runs = opt.runs.unwrap_or(u64::MAX);

    let mut corpus = load_corpus(&corpus_dir)?;
    if corpus.is_empty() {
        corpus.push(Vec::new());
        corpus.push(vec![0u8]);
        corpus.push(vec![1u8, 2u8, 3u8]);
    }

    let mut global_coverage: HashSet<u64> = HashSet::new();
    let mut findings = Vec::new();
    let mut crash_trace_path: Option<PathBuf> = None;
    let mut crash_count = 0u64;

    let mut executed = 0u64;
    while executed < max_runs {
        if let Some(dl) = deadline {
            if Instant::now() >= dl {
                break;
            }
        }

        let base = &corpus[(rng.next_u64() as usize) % corpus.len()];
        let mut input = base.clone();
        mutate_bytes(&mut input, &mut rng, opt.max_input_bytes);

        let exec = execute_target(target, &input)?;
        executed += 1;

        let new_edges: Vec<u64> = exec
            .coverage
            .iter()
            .copied()
            .filter(|e| !global_coverage.contains(e))
            .collect();
        if !new_edges.is_empty() {
            for e in &new_edges {
                global_coverage.insert(*e);
            }
            if matches!(opt.mode, FuzzMode::Coverage) {
                corpus.push(input.clone());
                persist_corpus_input(&corpus_dir, &input)?;
            }
        }

        if exec.status != ExitStatus::Pass {
            crash_count += 1;
            findings.extend(exec.findings.clone());

            let _crash_path = persist_crash_input(&corpus_dir, &input)?;
            let report_path = artifacts_dir.join("report.json");

            let finished_at = wall_time_iso_utc();
            let duration_ms = started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64;

            let summary = RunSummary {
                status: exec.status,
                mode: RunMode::Fuzz,
                identity: RunIdentity {
                    run_id: run_id.clone(),
                    seed,
                    trace_path: None,
                    report_path: Some(report_path.to_string_lossy().to_string()),
                    artifacts_dir: Some(artifacts_dir.to_string_lossy().to_string()),
                },
                started_at: started_at.clone(),
                finished_at,
                duration_ms,
                tests: None,
                findings: exec.findings.clone(),
            };

            std::fs::write(&report_path, serde_json::to_vec_pretty(&summary)?)?;
            std::fs::write(artifacts_dir.join("events.json"), serde_json::to_vec_pretty(&exec.events)?)?;
            crate::write_timeline(&exec.events, &artifacts_dir.join("timeline.json"))?;

            if matches!(opt.reporter, Reporter::Junit) {
                std::fs::write(artifacts_dir.join("junit.xml"), crate::render_junit_xml(&summary))?;
            }
            if matches!(opt.reporter, Reporter::Html) {
                std::fs::write(artifacts_dir.join("report.html"), crate::render_html(&summary))?;
            }

            let trace_out = opt
                .record_trace_to
                .clone()
                .unwrap_or_else(|| artifacts_dir.join("trace.fozzy"));
            let trace = TraceFile::new_fuzz(target_string(target), &input, exec.events, summary.clone());
            trace.write_json(&trace_out)?;
            crash_trace_path = Some(trace_out);

            if opt.minimize || opt.shrink {
                let minimized = minimize_input(target, &input, opt.max_input_bytes)?;
                let _min_path = persist_crash_min_input(&corpus_dir, &minimized)?;
            }

            if opt.crash_only {
                // Stop on first crash by default when crash-only.
                break;
            }
        }
    }

    let finished_at = wall_time_iso_utc();
    let duration_ms = started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64;
    let status = if crash_count == 0 { ExitStatus::Pass } else { ExitStatus::Fail };
    let report_path = artifacts_dir.join("report.json");

    let summary = RunSummary {
        status,
        mode: RunMode::Fuzz,
        identity: RunIdentity {
            run_id: run_id.clone(),
            seed,
            trace_path: crash_trace_path.map(|p| p.to_string_lossy().to_string()),
            report_path: Some(report_path.to_string_lossy().to_string()),
            artifacts_dir: Some(artifacts_dir.to_string_lossy().to_string()),
        },
        started_at,
        finished_at,
        duration_ms,
        tests: None,
        findings,
    };

    std::fs::write(&report_path, serde_json::to_vec_pretty(&summary)?)?;
    Ok(crate::RunResult { summary })
}

pub fn replay_fuzz_trace(config: &Config, trace: &TraceFile) -> FozzyResult<crate::RunResult> {
    let Some(fuzz) = trace.fuzz.as_ref() else {
        return Err(FozzyError::Trace("not a fuzz trace".to_string()));
    };
    let target: FuzzTarget = fuzz.target.parse()?;
    let input = hex_decode(&fuzz.input_hex)?;
    let exec = execute_target(&target, &input)?;

    let run_id = Uuid::new_v4().to_string();
    let artifacts_dir = config.runs_dir().join(&run_id);
    std::fs::create_dir_all(&artifacts_dir)?;
    let report_path = artifacts_dir.join("report.json");

    let started_at = wall_time_iso_utc();
    let finished_at = wall_time_iso_utc();
    let summary = RunSummary {
        status: exec.status,
        mode: RunMode::Replay,
        identity: RunIdentity {
            run_id,
            seed: trace.summary.identity.seed,
            trace_path: Some("<embedded>".to_string()),
            report_path: Some(report_path.to_string_lossy().to_string()),
            artifacts_dir: Some(artifacts_dir.to_string_lossy().to_string()),
        },
        started_at,
        finished_at,
        duration_ms: 0,
        tests: None,
        findings: exec.findings.clone(),
    };

    std::fs::write(&report_path, serde_json::to_vec_pretty(&summary)?)?;
    std::fs::write(artifacts_dir.join("events.json"), serde_json::to_vec_pretty(&exec.events)?)?;
    crate::write_timeline(&exec.events, &artifacts_dir.join("timeline.json"))?;
    Ok(crate::RunResult { summary })
}

pub fn shrink_fuzz_trace(
    _config: &Config,
    trace_path: crate::TracePath,
    opt: &crate::ShrinkOptions,
) -> FozzyResult<crate::ShrinkResult> {
    let trace = TraceFile::read_json(trace_path.as_path())?;
    let Some(fuzz) = trace.fuzz.as_ref() else {
        return Err(FozzyError::Trace("not a fuzz trace".to_string()));
    };

    let target: FuzzTarget = fuzz.target.parse()?;
    let input = hex_decode(&fuzz.input_hex)?;

    if opt.minimize != crate::ShrinkMinimize::All && opt.minimize != crate::ShrinkMinimize::Input {
        return Err(FozzyError::InvalidArgument(
            "fuzz shrink only supports --minimize input|all".to_string(),
        ));
    }

    let minimized = minimize_input(&target, &input, 1024 * 1024)?;
    let exec = execute_target(&target, &minimized)?;

    let out_path = opt
        .out_trace_path
        .clone()
        .unwrap_or_else(|| crate::default_min_trace_path(trace_path.as_path()));

    let started_at = wall_time_iso_utc();
    let finished_at = wall_time_iso_utc();
    let summary = RunSummary {
        status: exec.status,
        mode: RunMode::Fuzz,
        identity: RunIdentity {
            run_id: Uuid::new_v4().to_string(),
            seed: trace.summary.identity.seed,
            trace_path: Some(out_path.to_string_lossy().to_string()),
            report_path: None,
            artifacts_dir: None,
        },
        started_at,
        finished_at,
        duration_ms: 0,
        tests: None,
        findings: exec.findings.clone(),
    };

    let trace_out = TraceFile::new_fuzz(target_string(&target), &minimized, exec.events, summary.clone());
    trace_out.write_json(&out_path).map_err(|err| {
        FozzyError::Trace(format!(
            "failed to write shrunk fuzz trace to {}: {err}",
            out_path.display()
        ))
    })?;

    Ok(crate::ShrinkResult {
        out_trace_path: out_path.to_string_lossy().to_string(),
        result: crate::RunResult { summary },
    })
}

fn target_string(target: &FuzzTarget) -> String {
    match target {
        FuzzTarget::Function { id } => format!("fn:{id}"),
    }
}

#[derive(Debug, Clone)]
struct FuzzExec {
    status: ExitStatus,
    findings: Vec<Finding>,
    events: Vec<TraceEvent>,
    coverage: BTreeSet<u64>,
}

fn execute_target(target: &FuzzTarget, input: &[u8]) -> FozzyResult<FuzzExec> {
    match target {
        FuzzTarget::Function { id } if id == "kv" => execute_kv(input),
        FuzzTarget::Function { id } => Err(FozzyError::InvalidArgument(format!(
            "unknown fuzz function target {id:?} (supported: fn:kv)"
        ))),
    }
}

fn execute_kv(input: &[u8]) -> FozzyResult<FuzzExec> {
    let mut map: BTreeMap<Vec<u8>, Vec<u8>> = BTreeMap::new();
    let mut events = Vec::new();
    let mut findings = Vec::new();
    let mut coverage = BTreeSet::new();

    let mut i = 0usize;
    let mut time_ms = 0u64;
    while i < input.len() {
        let op = input[i];
        i += 1;
        time_ms = time_ms.saturating_add(1);

        coverage.insert(stable_edge(&format!("op:{op:02x}")));
        events.push(TraceEvent {
            time_ms,
            name: "op".to_string(),
            fields: serde_json::Map::from_iter([(
                "opcode".to_string(),
                serde_json::Value::String(format!("{op:02x}")),
            )]),
        });

        match op {
            0x00 => {
                coverage.insert(stable_edge("nop"));
            }
            0x01 => {
                let Some((k, v)) = parse_kv(input, &mut i) else {
                    coverage.insert(stable_edge("parse:eof"));
                    break;
                };
                let existed = map.insert(k.clone(), v).is_some();
                coverage.insert(stable_edge(if existed { "set:overwrite" } else { "set:new" }));
            }
            0x02 => {
                let Some(key) = parse_bytes(input, &mut i) else {
                    coverage.insert(stable_edge("parse:eof"));
                    break;
                };
                let hit = map.contains_key(&key);
                coverage.insert(stable_edge(if hit { "get:hit" } else { "get:miss" }));
            }
            0x03 => {
                let Some((k, v)) = parse_kv(input, &mut i) else {
                    coverage.insert(stable_edge("parse:eof"));
                    break;
                };
                let got = map.get(&k).cloned();
                if got.as_deref() != Some(&v) {
                    findings.push(Finding {
                        kind: FindingKind::Assertion,
                        title: "kv_assert".to_string(),
                        message: "asserted key != expected value".to_string(),
                        location: None,
                    });
                    coverage.insert(stable_edge("assert:fail"));
                    return Ok(FuzzExec {
                        status: ExitStatus::Fail,
                        findings,
                        events,
                        coverage,
                    });
                }
                coverage.insert(stable_edge("assert:pass"));
            }
            0xFE => {
                findings.push(Finding {
                    kind: FindingKind::Panic,
                    title: "panic".to_string(),
                    message: "panic opcode reached".to_string(),
                    location: None,
                });
                return Ok(FuzzExec {
                    status: ExitStatus::Crash,
                    findings,
                    events,
                    coverage,
                });
            }
            0xFF => {
                findings.push(Finding {
                    kind: FindingKind::Hang,
                    title: "hang".to_string(),
                    message: "hang opcode reached".to_string(),
                    location: None,
                });
                return Ok(FuzzExec {
                    status: ExitStatus::Timeout,
                    findings,
                    events,
                    coverage,
                });
            }
            _ => {
                // Unknown opcode: ignore, but count towards coverage.
                coverage.insert(stable_edge("op:unknown"));
            }
        }
    }

    Ok(FuzzExec {
        status: ExitStatus::Pass,
        findings,
        events,
        coverage,
    })
}

fn parse_kv(input: &[u8], i: &mut usize) -> Option<(Vec<u8>, Vec<u8>)> {
    let k = parse_bytes(input, i)?;
    let v = parse_bytes(input, i)?;
    Some((k, v))
}

fn parse_bytes(input: &[u8], i: &mut usize) -> Option<Vec<u8>> {
    if *i >= input.len() {
        return None;
    }
    let len = input[*i] as usize;
    *i += 1;
    if *i + len > input.len() {
        return None;
    }
    let out = input[*i..*i + len].to_vec();
    *i += len;
    Some(out)
}

fn mutate_bytes(buf: &mut Vec<u8>, rng: &mut rand_chacha::ChaCha20Rng, max_len: usize) {
    let choice = (rng.next_u64() % 4) as u8;
    match choice {
        0 => bitflip(buf, rng),
        1 => insert_byte(buf, rng, max_len),
        2 => delete_byte(buf, rng),
        _ => overwrite_byte(buf, rng),
    }
}

fn bitflip(buf: &mut Vec<u8>, rng: &mut rand_chacha::ChaCha20Rng) {
    if buf.is_empty() {
        return;
    }
    let idx = (rng.next_u64() as usize) % buf.len();
    let bit = 1u8 << ((rng.next_u64() as usize) % 8);
    buf[idx] ^= bit;
}

fn insert_byte(buf: &mut Vec<u8>, rng: &mut rand_chacha::ChaCha20Rng, max_len: usize) {
    if buf.len() >= max_len {
        return;
    }
    let idx = if buf.is_empty() { 0 } else { (rng.next_u64() as usize) % (buf.len() + 1) };
    let val = (rng.next_u64() & 0xFF) as u8;
    buf.insert(idx, val);
}

fn delete_byte(buf: &mut Vec<u8>, rng: &mut rand_chacha::ChaCha20Rng) {
    if buf.is_empty() {
        return;
    }
    let idx = (rng.next_u64() as usize) % buf.len();
    buf.remove(idx);
}

fn overwrite_byte(buf: &mut Vec<u8>, rng: &mut rand_chacha::ChaCha20Rng) {
    if buf.is_empty() {
        buf.push((rng.next_u64() & 0xFF) as u8);
        return;
    }
    let idx = (rng.next_u64() as usize) % buf.len();
    buf[idx] = (rng.next_u64() & 0xFF) as u8;
}

fn load_corpus(dir: &Path) -> FozzyResult<Vec<Vec<u8>>> {
    let mut out = Vec::new();
    if !dir.exists() {
        return Ok(out);
    }
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            continue;
        }
        let p = entry.path();
        if p.extension().and_then(|s| s.to_str()) != Some("bin") {
            continue;
        }
        out.push(std::fs::read(p)?);
    }
    Ok(out)
}

fn persist_corpus_input(dir: &Path, bytes: &[u8]) -> FozzyResult<PathBuf> {
    let name = format!("input-{}.bin", blake3::hash(bytes).to_hex());
    let out = dir.join(name);
    if !out.exists() {
        std::fs::write(&out, bytes)?;
    }
    Ok(out)
}

fn persist_crash_input(dir: &Path, bytes: &[u8]) -> FozzyResult<PathBuf> {
    let name = format!("crash-{}.bin", blake3::hash(bytes).to_hex());
    let out = dir.join("crashes").join(name);
    if !out.exists() {
        std::fs::write(&out, bytes)?;
    }
    Ok(out)
}

fn persist_crash_min_input(dir: &Path, bytes: &[u8]) -> FozzyResult<PathBuf> {
    let name = format!("crash-{}.min.bin", blake3::hash(bytes).to_hex());
    let out = dir.join("crashes").join(name);
    if !out.exists() {
        std::fs::write(&out, bytes)?;
    }
    Ok(out)
}

fn minimize_input(target: &FuzzTarget, input: &[u8], max_len: usize) -> FozzyResult<Vec<u8>> {
    let mut best = input.to_vec();
    let mut chunk = (best.len().max(1) + 1) / 2;
    while chunk > 0 && best.len() > 1 {
        let mut improved = false;
        let mut i = 0usize;
        while i < best.len() {
            let mut trial = best.clone();
            let end = (i + chunk).min(trial.len());
            trial.drain(i..end);
            if trial.is_empty() {
                i += chunk;
                continue;
            }
            if trial.len() > max_len {
                i += chunk;
                continue;
            }
            let exec = execute_target(target, &trial)?;
            if exec.status != ExitStatus::Pass {
                best = trial;
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
    Ok(best)
}

fn stable_edge(label: &str) -> u64 {
    let h = blake3::hash(label.as_bytes());
    let mut b = [0u8; 8];
    b.copy_from_slice(&h.as_bytes()[..8]);
    u64::from_le_bytes(b)
}

fn gen_seed() -> u64 {
    let mut seed = [0u8; 8];
    rand_core::OsRng.fill_bytes(&mut seed);
    u64::from_le_bytes(seed)
}

fn rng_from_seed(seed: u64) -> ChaCha20Rng {
    let seed_bytes = blake3::hash(&seed.to_le_bytes()).as_bytes().to_owned();
    let mut seed32 = [0u8; 32];
    seed32.copy_from_slice(&seed_bytes[..32]);
    ChaCha20Rng::from_seed(seed32)
}

fn hex_decode(s: &str) -> FozzyResult<Vec<u8>> {
    let s = s.trim();
    if s.len() % 2 != 0 {
        return Err(FozzyError::Trace("invalid hex length".to_string()));
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    for i in (0..bytes.len()).step_by(2) {
        let hi = hex_val(bytes[i])?;
        let lo = hex_val(bytes[i + 1])?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

fn hex_val(b: u8) -> FozzyResult<u8> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(FozzyError::Trace("invalid hex character".to_string())),
    }
}
