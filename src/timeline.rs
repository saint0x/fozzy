//! Timeline artifact generation from trace events.

use serde::{Deserialize, Serialize};

use std::path::Path;

use crate::{FozzyResult, TraceEvent};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineEntry {
    pub index: usize,
    pub time_ms: u64,
    pub name: String,
    #[serde(default)]
    pub fields: serde_json::Map<String, serde_json::Value>,
}

pub fn write_timeline(events: &[TraceEvent], out_path: &Path) -> FozzyResult<()> {
    if let Some(parent) = out_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let timeline: Vec<TimelineEntry> = events
        .iter()
        .enumerate()
        .map(|(idx, e)| TimelineEntry {
            index: idx,
            time_ms: e.time_ms,
            name: e.name.clone(),
            fields: e.fields.clone(),
        })
        .collect();
    std::fs::write(out_path, serde_json::to_vec_pretty(&timeline)?)?;
    Ok(())
}

