//! Trace file format (.fozzy) read/write.

use serde::{Deserialize, Serialize};

use std::path::{Path, PathBuf};

use crate::{Decision, FuzzTrace, RunMode, RunSummary, ScenarioV1Steps, VersionInfo};

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
            decisions: Vec::new(),
            events,
            summary,
        }
    }

    pub fn write_json(&self, path: &Path) -> crate::FozzyResult<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let bytes = serde_json::to_vec_pretty(self)?;
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
