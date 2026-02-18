//! Trace file format (.fozzy) read/write.

use serde::{Deserialize, Serialize};

use std::path::{Path, PathBuf};

use crate::{Decision, ExploreTrace, FuzzTrace, RunMode, RunSummary, ScenarioV1Steps, VersionInfo};

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
            version: 1,
            engine: crate::version_info(),
            mode,
            scenario_path,
            scenario,
            fuzz: None,
            explore: None,
            decisions,
            events,
            summary,
        }
    }

    pub fn new_fuzz(target: String, input: &[u8], events: Vec<TraceEvent>, summary: RunSummary) -> Self {
        Self {
            format: "fozzy-trace".to_string(),
            version: 1,
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
            version: 1,
            engine: crate::version_info(),
            mode: RunMode::Explore,
            scenario_path: None,
            scenario: None,
            fuzz: None,
            explore: Some(explore),
            decisions,
            events,
            summary,
        }
    }

    pub fn write_json(&self, path: &Path) -> crate::FozzyResult<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let pretty = std::env::var("FOZZY_TRACE_PRETTY")
            .ok()
            .is_some_and(|v| v == "1" || v.eq_ignore_ascii_case("true"));
        let bytes = if pretty {
            serde_json::to_vec_pretty(self)?
        } else {
            serde_json::to_vec(self)?
        };
        std::fs::write(path, bytes)?;
        Ok(())
    }

    pub fn read_json(path: &Path) -> crate::FozzyResult<Self> {
        let bytes = std::fs::read(path)?;
        let t: TraceFile = serde_json::from_slice(&bytes)?;
        Ok(t)
    }
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
}
