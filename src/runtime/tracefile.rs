//! Trace file format (.fozzy) read/write.

use serde::{Deserialize, Serialize};

use std::path::{Path, PathBuf};

use crate::{
    Decision, ExploreTrace, FozzyError, FozzyResult, FuzzTrace, RecordCollisionPolicy, RunMode, RunSummary,
    ScenarioV1Steps, VersionInfo,
};

pub const CURRENT_TRACE_VERSION: u32 = 2;

#[derive(Debug, Clone)]
pub struct TracePath {
    path: PathBuf,
}

impl TracePath {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    pub fn as_path(&self) -> &Path {
        &self.path
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceFile {
    pub format: String,
    pub version: u32,
    pub engine: VersionInfo,
    pub mode: RunMode,
    pub scenario_path: Option<String>,
    pub scenario: Option<ScenarioV1Steps>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fuzz: Option<FuzzTrace>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub explore: Option<ExploreTrace>,
    pub decisions: Vec<Decision>,
    pub events: Vec<TraceEvent>,
    pub summary: RunSummary,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checksum: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceEvent {
    pub time_ms: u64,
    pub name: String,
    #[serde(default)]
    pub fields: serde_json::Map<String, serde_json::Value>,
}

impl TraceFile {
    pub fn new(
        mode: RunMode,
        scenario_path: Option<String>,
        scenario: Option<ScenarioV1Steps>,
        decisions: Vec<Decision>,
        events: Vec<TraceEvent>,
        summary: RunSummary,
    ) -> Self {
        Self {
            format: "fozzy-trace".to_string(),
            version: CURRENT_TRACE_VERSION,
            engine: crate::version_info(),
            mode,
            scenario_path,
            scenario,
            fuzz: None,
            explore: None,
            decisions,
            events,
            summary,
            checksum: None,
        }
    }

    pub fn new_fuzz(target: String, input: &[u8], events: Vec<TraceEvent>, summary: RunSummary) -> Self {
        Self {
            format: "fozzy-trace".to_string(),
            version: CURRENT_TRACE_VERSION,
            engine: crate::version_info(),
            mode: RunMode::Fuzz,
            scenario_path: None,
            scenario: None,
            fuzz: Some(FuzzTrace {
                target,
                input_hex: bytes_to_hex(input),
            }),
            explore: None,
            decisions: Vec::new(),
            events,
            summary,
            checksum: None,
        }
    }

    pub fn new_explore(
        explore: ExploreTrace,
        decisions: Vec<Decision>,
        events: Vec<TraceEvent>,
        summary: RunSummary,
    ) -> Self {
        Self {
            format: "fozzy-trace".to_string(),
            version: CURRENT_TRACE_VERSION,
            engine: crate::version_info(),
            mode: RunMode::Explore,
            scenario_path: None,
            scenario: None,
            fuzz: None,
            explore: Some(explore),
            decisions,
            events,
            summary,
            checksum: None,
        }
    }

    pub fn write_json(&self, path: &Path) -> FozzyResult<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut with_checksum = self.clone();
        with_checksum.checksum = None;
        let canonical = serde_json::to_vec(&with_checksum)?;
        with_checksum.checksum = Some(blake3::hash(&canonical).to_hex().to_string());

        let pretty = std::env::var("FOZZY_TRACE_PRETTY")
            .ok()
            .is_some_and(|v| v == "1" || v.eq_ignore_ascii_case("true"));
        let bytes = if pretty {
            serde_json::to_vec_pretty(&with_checksum)?
        } else {
            serde_json::to_vec(&with_checksum)?
        };
        // Atomic replace to avoid concurrent writer corruption on shared paths.
        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        let file_name = path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("trace.fozzy");
        let tmp_name = format!(
            ".{file_name}.{}.{}.tmp",
            std::process::id(),
            uuid::Uuid::new_v4()
        );
        let tmp_path = parent.join(tmp_name);
        std::fs::write(&tmp_path, bytes)?;
        std::fs::rename(&tmp_path, path)?;
        Ok(())
    }

    pub fn read_json(path: &Path) -> FozzyResult<Self> {
        let bytes = std::fs::read(path)?;
        let t: TraceFile = serde_json::from_slice(&bytes).map_err(|e| {
            FozzyError::Trace(format!(
                "failed to parse trace {}: {e}",
                path.display()
            ))
        })?;
        verify_checksum(&t, path)?;
        Ok(t)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceVerifyReport {
    pub ok: bool,
    pub path: String,
    pub version: u32,
    #[serde(rename = "checksumPresent")]
    pub checksum_present: bool,
    #[serde(rename = "checksumValid")]
    pub checksum_valid: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

pub fn trace_schema_warnings(version: u32) -> Vec<String> {
    if version < CURRENT_TRACE_VERSION {
        vec![format!(
            "trace schema v{version} is stale; current schema is v{CURRENT_TRACE_VERSION}"
        )]
    } else {
        Vec::new()
    }
}

pub fn verify_trace_file(path: &Path) -> FozzyResult<TraceVerifyReport> {
    let t = TraceFile::read_json(path)?;
    let warnings = trace_schema_warnings(t.version);
    Ok(TraceVerifyReport {
        ok: true,
        path: path.display().to_string(),
        version: t.version,
        checksum_present: t.checksum.is_some(),
        checksum_valid: t.checksum.is_some(),
        warnings,
    })
}

pub fn write_trace_with_policy(
    trace: &TraceFile,
    requested: &Path,
    policy: RecordCollisionPolicy,
) -> FozzyResult<PathBuf> {
    let target = resolve_record_target(requested, policy)?;
    let _lock = acquire_record_lock(&target)?;
    trace.write_json(&target)?;
    Ok(target)
}

fn resolve_record_target(path: &Path, policy: RecordCollisionPolicy) -> FozzyResult<PathBuf> {
    match policy {
        RecordCollisionPolicy::Overwrite => Ok(path.to_path_buf()),
        RecordCollisionPolicy::Error => {
            if path.exists() {
                Err(FozzyError::Trace(format!(
                    "record collision: {} already exists (--record-collision=error)",
                    path.display()
                )))
            } else {
                Ok(path.to_path_buf())
            }
        }
        RecordCollisionPolicy::Append => {
            if !path.exists() {
                return Ok(path.to_path_buf());
            }
            let parent = path.parent().unwrap_or_else(|| Path::new("."));
            let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("trace");
            let ext = path.extension().and_then(|s| s.to_str()).unwrap_or("fozzy");
            for i in 1..=100_000 {
                let candidate = parent.join(format!("{stem}.{i}.{ext}"));
                if !candidate.exists() {
                    return Ok(candidate);
                }
            }
            Err(FozzyError::Trace(format!(
                "unable to find append target for {}",
                path.display()
            )))
        }
    }
}

struct RecordLockGuard {
    lock_path: PathBuf,
}

impl Drop for RecordLockGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.lock_path);
    }
}

fn acquire_record_lock(target: &Path) -> FozzyResult<RecordLockGuard> {
    let lock_path = PathBuf::from(format!("{}.lock", target.to_string_lossy()));
    match std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&lock_path)
    {
        Ok(_) => Ok(RecordLockGuard { lock_path }),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Err(FozzyError::Trace(format!(
            "record collision: active writer holds lock for {}",
            target.display()
        ))),
        Err(e) => Err(e.into()),
    }
}

fn verify_checksum(trace: &TraceFile, path: &Path) -> FozzyResult<()> {
    let Some(expected) = trace.checksum.as_ref() else {
        return Ok(());
    };
    let mut canonical = trace.clone();
    canonical.checksum = None;
    let bytes = serde_json::to_vec(&canonical)?;
    let got = blake3::hash(&bytes).to_hex().to_string();
    if &got != expected {
        return Err(FozzyError::Trace(format!(
            "trace checksum mismatch for {} (expected {}, got {})",
            path.display(),
            expected,
            got
        )));
    }
    Ok(())
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    const TABLE: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    for b in bytes {
        out.push(TABLE[(b >> 4) as usize] as char);
        out.push(TABLE[(b & 0x0F) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ExitStatus, RunIdentity, RunSummary};
    use uuid::Uuid;

    fn temp_file(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("fozzy-trace-tests-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        dir.join(name)
    }

    fn sample_summary(trace_path: Option<String>) -> RunSummary {
        RunSummary {
            status: ExitStatus::Pass,
            mode: RunMode::Run,
            identity: RunIdentity {
                run_id: "run-1".to_string(),
                seed: 1,
                trace_path,
                report_path: None,
                artifacts_dir: None,
            },
            started_at: "2026-01-01T00:00:00Z".to_string(),
            finished_at: "2026-01-01T00:00:00Z".to_string(),
            duration_ms: 0,
            tests: None,
            findings: Vec::new(),
        }
    }

    #[test]
    fn trace_parses_legacy_scheduler_and_step_decisions() {
        let raw = r#"{
          "format":"fozzy-trace",
          "version":1,
          "engine":{"version":"0.1.0"},
          "mode":"run",
          "scenario_path":"tests/example.fozzy.json",
          "scenario":{"version":1,"name":"example","steps":[]},
          "decisions":[
            {"kind":"scheduler_pick","task_id":1,"label":"step0"},
            {"kind":"step","index":0,"name":"legacy-step"}
          ],
          "events":[],
          "summary":{
            "status":"pass",
            "mode":"run",
            "identity":{"runId":"r1","seed":1},
            "startedAt":"2026-01-01T00:00:00Z",
            "finishedAt":"2026-01-01T00:00:00Z",
            "durationMs":0
          }
        }"#;

        let trace: TraceFile = serde_json::from_str(raw).expect("legacy trace parses");
        assert_eq!(trace.version, 1);
        assert_eq!(trace.decisions.len(), 2);
    }

    #[test]
    fn trace_parses_network_replay_decisions() {
        let raw = r#"{
          "format":"fozzy-trace",
          "version":1,
          "engine":{"version":"0.1.0"},
          "mode":"run",
          "scenario_path":"tests/net.fozzy.json",
          "scenario":{"version":1,"name":"net","steps":[]},
          "decisions":[
            {"kind":"scheduler_pick","task_id":1,"label":"NetDeliverOne"},
            {"kind":"net_deliver_pick","message_id":42},
            {"kind":"net_drop","message_id":42,"dropped":false}
          ],
          "events":[],
          "summary":{
            "status":"pass",
            "mode":"run",
            "identity":{"runId":"r2","seed":2},
            "startedAt":"2026-01-01T00:00:00Z",
            "finishedAt":"2026-01-01T00:00:00Z",
            "durationMs":0
          }
        }"#;

        let trace: TraceFile = serde_json::from_str(raw).expect("network trace parses");
        assert_eq!(trace.decisions.len(), 3);
        let out = serde_json::to_string(&trace).expect("trace serializes");
        assert!(out.contains("net_deliver_pick"));
        assert!(out.contains("net_drop"));
    }

    #[test]
    fn checksum_mismatch_is_rejected() {
        let path = temp_file("bad.fozzy");
        let raw = r#"{
          "format":"fozzy-trace",
          "version":2,
          "engine":{"version":"0.1.0"},
          "mode":"run",
          "scenario_path":null,
          "scenario":{"version":1,"name":"x","steps":[]},
          "decisions":[],
          "events":[],
          "summary":{
            "status":"pass",
            "mode":"run",
            "identity":{"runId":"r1","seed":1},
            "startedAt":"2026-01-01T00:00:00Z",
            "finishedAt":"2026-01-01T00:00:00Z",
            "durationMs":0
          },
          "checksum":"deadbeef"
        }"#;
        std::fs::write(&path, raw).expect("write");
        let err = TraceFile::read_json(&path).expect_err("must reject checksum mismatch");
        assert!(err.to_string().contains("checksum mismatch"));
    }

    #[test]
    fn record_collision_error_policy_rejects_existing_target() {
        let path = temp_file("exists.fozzy");
        std::fs::write(&path, b"old").expect("write existing");
        let trace = TraceFile::new(
            RunMode::Run,
            None,
            Some(ScenarioV1Steps {
                version: 1,
                name: "x".to_string(),
                steps: Vec::new(),
            }),
            Vec::new(),
            Vec::new(),
            sample_summary(Some(path.to_string_lossy().to_string())),
        );
        let err = write_trace_with_policy(&trace, &path, RecordCollisionPolicy::Error).expect_err("must fail");
        assert!(err.to_string().contains("record collision"));
    }

    #[test]
    fn record_collision_append_policy_picks_numbered_path() {
        let path = temp_file("trace.fozzy");
        std::fs::write(&path, b"old").expect("write existing");
        let trace = TraceFile::new(
            RunMode::Run,
            None,
            Some(ScenarioV1Steps {
                version: 1,
                name: "x".to_string(),
                steps: Vec::new(),
            }),
            Vec::new(),
            Vec::new(),
            sample_summary(None),
        );
        let out = write_trace_with_policy(&trace, &path, RecordCollisionPolicy::Append).expect("append");
        assert_ne!(out, path);
        assert!(out.to_string_lossy().contains(".1.fozzy"));
        let loaded = TraceFile::read_json(&out).expect("trace exists");
        assert_eq!(loaded.format, "fozzy-trace");
    }

    #[test]
    fn truncated_trace_is_rejected() {
        let path = temp_file("truncated.fozzy");
        std::fs::write(&path, br#"{"format":"fozzy-trace""#).expect("write");
        let err = TraceFile::read_json(&path).expect_err("must fail");
        assert!(err.to_string().contains("failed to parse trace"));
    }

    #[test]
    fn random_bytes_trace_is_rejected() {
        let path = temp_file("random.fozzy");
        std::fs::write(&path, [0_u8, 159, 146, 150, 255, 0, 1, 2]).expect("write");
        let err = TraceFile::read_json(&path).expect_err("must fail");
        assert!(err.to_string().contains("failed to parse trace"));
    }
}
