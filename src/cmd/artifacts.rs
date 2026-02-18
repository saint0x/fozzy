//! Artifact management (`fozzy artifacts ...`).

use clap::Subcommand;
use serde::{Deserialize, Serialize};

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use crate::{Config, FozzyResult, RunSummary, TraceFile};

#[derive(Debug, Subcommand)]
pub enum ArtifactCommand {
    Ls { run: String },
    Diff { left: String, right: String },
    Export { run: String, #[arg(long)] out: PathBuf },
    Pack { run: String, #[arg(long)] out: PathBuf },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactKind {
    Trace,
    Timeline,
    Events,
    Report,
    Manifest,
    Coverage,
    MinRepro,
    Logs,
    Corpus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactEntry {
    pub kind: ArtifactKind,
    pub path: String,
    #[serde(rename = "sizeBytes", skip_serializing_if = "Option::is_none")]
    pub size_bytes: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ArtifactOutput {
    List { entries: Vec<ArtifactEntry> },
    Diff { diff: ArtifactDiff },
    Exported,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactDiff {
    pub left: String,
    pub right: String,
    pub files: Vec<ArtifactFileDelta>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub report: Option<ReportDelta>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trace: Option<TraceDelta>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactFileDelta {
    pub key: String,
    #[serde(rename = "leftPath", skip_serializing_if = "Option::is_none")]
    pub left_path: Option<String>,
    #[serde(rename = "rightPath", skip_serializing_if = "Option::is_none")]
    pub right_path: Option<String>,
    #[serde(rename = "leftSizeBytes", skip_serializing_if = "Option::is_none")]
    pub left_size_bytes: Option<u64>,
    #[serde(rename = "rightSizeBytes", skip_serializing_if = "Option::is_none")]
    pub right_size_bytes: Option<u64>,
    pub changed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportDelta {
    #[serde(rename = "leftStatus")]
    pub left_status: String,
    #[serde(rename = "rightStatus")]
    pub right_status: String,
    #[serde(rename = "leftMode")]
    pub left_mode: String,
    #[serde(rename = "rightMode")]
    pub right_mode: String,
    #[serde(rename = "leftFindings")]
    pub left_findings: usize,
    #[serde(rename = "rightFindings")]
    pub right_findings: usize,
    #[serde(rename = "leftDurationMs")]
    pub left_duration_ms: u64,
    #[serde(rename = "rightDurationMs")]
    pub right_duration_ms: u64,
    #[serde(rename = "findingTitlesChanged")]
    pub finding_titles_changed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceDelta {
    #[serde(rename = "leftMode")]
    pub left_mode: String,
    #[serde(rename = "rightMode")]
    pub right_mode: String,
    #[serde(rename = "leftDecisions")]
    pub left_decisions: usize,
    #[serde(rename = "rightDecisions")]
    pub right_decisions: usize,
    #[serde(rename = "leftEvents")]
    pub left_events: usize,
    #[serde(rename = "rightEvents")]
    pub right_events: usize,
    #[serde(rename = "firstDecisionDiffIndex", skip_serializing_if = "Option::is_none")]
    pub first_decision_diff_index: Option<usize>,
    #[serde(rename = "firstEventDiffIndex", skip_serializing_if = "Option::is_none")]
    pub first_event_diff_index: Option<usize>,
}

pub fn artifacts_command(config: &Config, command: &ArtifactCommand) -> FozzyResult<ArtifactOutput> {
    match command {
        ArtifactCommand::Ls { run } => Ok(ArtifactOutput::List {
            entries: artifacts_list(config, run)?,
        }),
        ArtifactCommand::Diff { left, right } => Ok(ArtifactOutput::Diff {
            diff: artifacts_diff(config, left, right)?,
        }),
        ArtifactCommand::Export { run, out } => {
            export_artifacts(config, run, out)?;
            Ok(ArtifactOutput::Exported)
        }
        ArtifactCommand::Pack { run, out } => {
            export_reproducer_pack(config, run, out)?;
            Ok(ArtifactOutput::Exported)
        }
    }
}

fn artifacts_list(config: &Config, run: &str) -> FozzyResult<Vec<ArtifactEntry>> {
    let run_path = PathBuf::from(run);
    if run_path.exists()
        && run_path.is_file()
        && run_path
            .extension()
            .and_then(|s| s.to_str())
            .is_some_and(|s| s.eq_ignore_ascii_case("fozzy"))
    {
        let mut out = Vec::new();
        push_if_exists(&mut out, ArtifactKind::Trace, run_path.clone())?;
        if let Some(parent) = run_path.parent() {
            push_if_exists(&mut out, ArtifactKind::Timeline, parent.join("timeline.json"))?;
            push_if_exists(&mut out, ArtifactKind::Report, parent.join("report.json"))?;
            push_if_exists(&mut out, ArtifactKind::Events, parent.join("events.json"))?;
            push_if_exists(&mut out, ArtifactKind::Coverage, parent.join("coverage.json"))?;
            push_if_exists(&mut out, ArtifactKind::Manifest, parent.join("manifest.json"))?;
            push_if_exists(&mut out, ArtifactKind::Report, parent.join("report.html"))?;
            push_if_exists(&mut out, ArtifactKind::Report, parent.join("junit.xml"))?;
        }
        return Ok(out);
    }

    if run_path
        .extension()
        .and_then(|s| s.to_str())
        .is_some_and(|s| s.eq_ignore_ascii_case("fozzy"))
        && !run_path.exists()
    {
        return Err(crate::FozzyError::InvalidArgument(format!(
            "trace path not found: {}",
            run_path.display()
        )));
    }

    let artifacts_dir = resolve_artifacts_dir(config, run)?;
    if !artifacts_dir.exists() {
        return Err(crate::FozzyError::InvalidArgument(format!(
            "run artifacts not found: {}",
            artifacts_dir.display()
        )));
    }
    let mut out = Vec::new();

    push_if_exists(&mut out, ArtifactKind::Trace, artifacts_dir.join("trace.fozzy"))?;
    push_if_exists(&mut out, ArtifactKind::Timeline, artifacts_dir.join("timeline.json"))?;
    push_if_exists(&mut out, ArtifactKind::Report, artifacts_dir.join("report.json"))?;
    push_if_exists(&mut out, ArtifactKind::Events, artifacts_dir.join("events.json"))?;
    push_if_exists(&mut out, ArtifactKind::Coverage, artifacts_dir.join("coverage.json"))?;
    push_if_exists(&mut out, ArtifactKind::Manifest, artifacts_dir.join("manifest.json"))?;
    push_if_exists(&mut out, ArtifactKind::Report, artifacts_dir.join("report.html"))?;
    push_if_exists(&mut out, ArtifactKind::Report, artifacts_dir.join("junit.xml"))?;

    Ok(out)
}

fn export_reproducer_pack(config: &Config, run: &str, out: &Path) -> FozzyResult<()> {
    let entries = artifacts_list(config, run)?;
    let mut files: Vec<PathBuf> = entries
        .into_iter()
        .map(|e| PathBuf::from(e.path))
        .filter(|p| p.exists() && p.is_file())
        .collect();
    files.sort();
    files.dedup();

    if files.is_empty() {
        return Err(crate::FozzyError::InvalidArgument(format!(
            "no artifacts found for {run:?}"
        )));
    }

    let meta_dir = std::env::temp_dir().join(format!("fozzy-pack-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&meta_dir)?;
    let meta_files = vec![
        ("env.json", serde_json::to_vec_pretty(&crate::env_info(config))?),
        ("version.json", serde_json::to_vec_pretty(&crate::version_info())?),
        (
            "commandline.json",
            serde_json::to_vec_pretty(&serde_json::json!({
                "argv": std::env::args().collect::<Vec<String>>(),
            }))?,
        ),
    ];
    for (name, bytes) in meta_files {
        std::fs::write(meta_dir.join(name), bytes)?;
    }
    files.push(meta_dir.join("env.json"));
    files.push(meta_dir.join("version.json"));
    files.push(meta_dir.join("commandline.json"));

    let res = if out
        .extension()
        .and_then(|s| s.to_str())
        .is_some_and(|s| s.eq_ignore_ascii_case("zip"))
    {
        export_artifacts_zip(&files, out)
    } else {
        std::fs::create_dir_all(out)?;
        validate_copy_targets_secure(&files, out)?;
        for src in files {
            copy_file_into_dir_secure(&src, out)?;
        }
        Ok(())
    };
    let _ = std::fs::remove_dir_all(meta_dir);
    res
}

fn export_artifacts(config: &Config, run: &str, out: &Path) -> FozzyResult<()> {
    let entries = artifacts_list(config, run)?;
    let mut files: Vec<PathBuf> = entries
        .into_iter()
        .map(|e| PathBuf::from(e.path))
        .filter(|p| p.exists() && p.is_file())
        .collect();
    files.sort();
    files.dedup();

    if files.is_empty() {
        return Err(crate::FozzyError::InvalidArgument(format!(
            "no artifacts found for {run:?}"
        )));
    }

    if out
        .extension()
        .and_then(|s| s.to_str())
        .is_some_and(|s| s.eq_ignore_ascii_case("zip"))
    {
        export_artifacts_zip(&files, out)?;
        return Ok(());
    }

    std::fs::create_dir_all(out)?;
    validate_copy_targets_secure(&files, out)?;

    for src in files {
        copy_file_into_dir_secure(&src, out)?;
    }

    Ok(())
}

fn artifacts_diff(config: &Config, left: &str, right: &str) -> FozzyResult<ArtifactDiff> {
    let left_entries = artifacts_list(config, left)?;
    let right_entries = artifacts_list(config, right)?;

    let mut left_map = BTreeMap::new();
    for entry in left_entries {
        let file = PathBuf::from(&entry.path)
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or(&entry.path)
            .to_string();
        let key = format!("{:?}:{file}", entry.kind);
        left_map.insert(key, entry);
    }
    let mut right_map = BTreeMap::new();
    for entry in right_entries {
        let file = PathBuf::from(&entry.path)
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or(&entry.path)
            .to_string();
        let key = format!("{:?}:{file}", entry.kind);
        right_map.insert(key, entry);
    }

    let mut keys: Vec<String> = left_map
        .keys()
        .chain(right_map.keys())
        .cloned()
        .collect();
    keys.sort();
    keys.dedup();

    let mut files = Vec::new();
    for key in keys {
        let l = left_map.get(&key);
        let r = right_map.get(&key);
        let left_path = l.map(|e| e.path.clone());
        let right_path = r.map(|e| e.path.clone());
        let left_size = l.and_then(|e| e.size_bytes);
        let right_size = r.and_then(|e| e.size_bytes);
        files.push(ArtifactFileDelta {
            key,
            left_path,
            right_path,
            left_size_bytes: left_size,
            right_size_bytes: right_size,
            changed: left_size != right_size || l.is_none() || r.is_none(),
        });
    }

    let report = match (load_summary(config, left)?, load_summary(config, right)?) {
        (Some(l), Some(r)) => Some(report_delta(&l, &r)),
        _ => None,
    };
    let trace = match (load_trace(config, left)?, load_trace(config, right)?) {
        (Some(l), Some(r)) => Some(trace_delta(&l, &r)),
        _ => None,
    };

    Ok(ArtifactDiff {
        left: left.to_string(),
        right: right.to_string(),
        files,
        report,
        trace,
    })
}

fn report_delta(left: &RunSummary, right: &RunSummary) -> ReportDelta {
    let left_titles: Vec<&str> = left.findings.iter().map(|f| f.title.as_str()).collect();
    let right_titles: Vec<&str> = right.findings.iter().map(|f| f.title.as_str()).collect();
    ReportDelta {
        left_status: format!("{:?}", left.status).to_lowercase(),
        right_status: format!("{:?}", right.status).to_lowercase(),
        left_mode: format!("{:?}", left.mode).to_lowercase(),
        right_mode: format!("{:?}", right.mode).to_lowercase(),
        left_findings: left.findings.len(),
        right_findings: right.findings.len(),
        left_duration_ms: left.duration_ms,
        right_duration_ms: right.duration_ms,
        finding_titles_changed: left_titles != right_titles,
    }
}

fn trace_delta(left: &TraceFile, right: &TraceFile) -> TraceDelta {
    let first_decision_diff_index = left
        .decisions
        .iter()
        .zip(right.decisions.iter())
        .position(|(a, b)| a != b)
        .or_else(|| {
            if left.decisions.len() != right.decisions.len() {
                Some(left.decisions.len().min(right.decisions.len()))
            } else {
                None
            }
        });

    let first_event_diff_index = left
        .events
        .iter()
        .zip(right.events.iter())
        .position(|(a, b)| a.time_ms != b.time_ms || a.name != b.name || a.fields != b.fields)
        .or_else(|| {
            if left.events.len() != right.events.len() {
                Some(left.events.len().min(right.events.len()))
            } else {
                None
            }
        });

    TraceDelta {
        left_mode: format!("{:?}", left.mode).to_lowercase(),
        right_mode: format!("{:?}", right.mode).to_lowercase(),
        left_decisions: left.decisions.len(),
        right_decisions: right.decisions.len(),
        left_events: left.events.len(),
        right_events: right.events.len(),
        first_decision_diff_index,
        first_event_diff_index,
    }
}

fn load_summary(config: &Config, run: &str) -> FozzyResult<Option<RunSummary>> {
    let artifacts_dir = resolve_artifacts_dir(config, run)?;
    let report_json = artifacts_dir.join("report.json");
    if report_json.exists() {
        let bytes = std::fs::read(report_json)?;
        let summary: RunSummary = serde_json::from_slice(&bytes)?;
        return Ok(Some(summary));
    }

    let trace = load_trace(config, run)?;
    Ok(trace.map(|t| t.summary))
}

fn load_trace(config: &Config, run: &str) -> FozzyResult<Option<TraceFile>> {
    let input = PathBuf::from(run);
    let trace_path = if input.exists()
        && input.is_file()
        && input
            .extension()
            .and_then(|s| s.to_str())
            .is_some_and(|s| s.eq_ignore_ascii_case("fozzy"))
    {
        input
    } else {
        resolve_artifacts_dir(config, run)?.join("trace.fozzy")
    };

    if !trace_path.exists() {
        return Ok(None);
    }
    Ok(Some(TraceFile::read_json(&trace_path)?))
}

pub(crate) fn resolve_artifacts_dir(config: &Config, run: &str) -> FozzyResult<PathBuf> {
    // `run` can be:
    // - a run id (directory `.fozzy/runs/<runId>`)
    // - a trace path (`*.fozzy`) that either is `.../trace.fozzy` or points to a trace file.
    let path = PathBuf::from(run);
    if path.exists() {
        if path.is_dir() {
            return Ok(path);
        }

        // A direct trace file, or any file within the artifacts dir.
        if let Some(parent) = path.parent() {
            return Ok(parent.to_path_buf());
        }
    }

    Ok(config.runs_dir().join(run))
}

fn push_if_exists(out: &mut Vec<ArtifactEntry>, kind: ArtifactKind, path: PathBuf) -> FozzyResult<()> {
    if !path.exists() {
        return Ok(());
    }
    let md = std::fs::metadata(&path)?;
    out.push(ArtifactEntry {
        kind,
        path: path.to_string_lossy().to_string(),
        size_bytes: Some(md.len()),
    });
    Ok(())
}

fn export_artifacts_zip(files: &[PathBuf], out_zip: &Path) -> FozzyResult<()> {
    use std::fs::File;
    use std::io::Write as _;

    if let Some(parent) = out_zip.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let file_name = out_zip
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("artifacts.zip");
    let tmp_name = format!(".{file_name}.{}.{}.tmp", std::process::id(), uuid::Uuid::new_v4());
    let tmp_path = out_zip
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(tmp_name);

    let write_result = (|| -> FozzyResult<()> {
        let file = File::create(&tmp_path)?;
        let mut zip = zip::ZipWriter::new(file);
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated)
            .unix_permissions(0o644);
        let mut used_names: BTreeSet<String> = BTreeSet::new();

        for src in files {
            let name = zip_entry_name_for_path(src, &mut used_names);
            zip.start_file(name, options)?;
            let bytes = std::fs::read(src)?;
            zip.write_all(&bytes)?;
        }

        zip.finish()?;
        Ok(())
    })();

    match write_result {
        Ok(()) => {
            std::fs::rename(&tmp_path, out_zip)?;
            Ok(())
        }
        Err(err) => {
            let _ = std::fs::remove_file(&tmp_path);
            Err(err)
        }
    }
}

fn zip_entry_name_for_path(path: &Path, used: &mut BTreeSet<String>) -> String {
    let base = path
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "artifact".to_string());

    let mut safe: String = base
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_') {
                c
            } else {
                '_'
            }
        })
        .collect();
    while safe.contains("__") {
        safe = safe.replace("__", "_");
    }
    safe = safe.trim_matches('_').to_string();
    if safe.is_empty() {
        safe = "artifact".to_string();
    }

    let (stem, ext) = match safe.rsplit_once('.') {
        Some((s, e)) if !s.is_empty() && !e.is_empty() => (s.to_string(), Some(e.to_string())),
        _ => (safe.clone(), None),
    };

    if used.insert(safe.clone()) {
        return safe;
    }

    for i in 2..=10_000usize {
        let candidate = match &ext {
            Some(ext) => format!("{stem}.{i}.{ext}"),
            None => format!("{stem}.{i}"),
        };
        if used.insert(candidate.clone()) {
            return candidate;
        }
    }
    "artifact.overflow".to_string()
}

fn copy_file_into_dir_secure(src: &Path, out_dir: &Path) -> FozzyResult<()> {
    if out_dir.exists() {
        let out_md = std::fs::symlink_metadata(out_dir)?;
        if out_md.file_type().is_symlink() {
            return Err(crate::FozzyError::InvalidArgument(format!(
                "refusing to write into symlinked output directory: {}",
                out_dir.display()
            )));
        }
    }

    let name = src
        .file_name()
        .ok_or_else(|| crate::FozzyError::InvalidArgument(format!("invalid artifact path: {}", src.display())))?;
    let dst = out_dir.join(name);
    if dst.exists() {
        let dst_md = std::fs::symlink_metadata(&dst)?;
        if dst_md.file_type().is_symlink() {
            return Err(crate::FozzyError::InvalidArgument(format!(
                "refusing to overwrite symlinked output file: {}",
                dst.display()
            )));
        }
        if !dst_md.is_file() {
            return Err(crate::FozzyError::InvalidArgument(format!(
                "refusing to overwrite non-file output path: {}",
                dst.display()
            )));
        }
        std::fs::remove_file(&dst)?;
    }

    let tmp_name = format!(
        ".{}.{}.{}.tmp",
        dst.file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("artifact"),
        std::process::id(),
        uuid::Uuid::new_v4()
    );
    let tmp = out_dir.join(tmp_name);
    std::fs::copy(src, &tmp)?;
    std::fs::rename(&tmp, &dst)?;
    Ok(())
}

fn validate_copy_targets_secure(files: &[PathBuf], out_dir: &Path) -> FozzyResult<()> {
    if out_dir.exists() {
        let out_md = std::fs::symlink_metadata(out_dir)?;
        if out_md.file_type().is_symlink() {
            return Err(crate::FozzyError::InvalidArgument(format!(
                "refusing to write into symlinked output directory: {}",
                out_dir.display()
            )));
        }
    }

    let mut seen = std::collections::BTreeSet::<String>::new();
    for src in files {
        let name = src
            .file_name()
            .and_then(|s| s.to_str())
            .ok_or_else(|| crate::FozzyError::InvalidArgument(format!("invalid artifact path: {}", src.display())))?
            .to_string();
        if !seen.insert(name.clone()) {
            return Err(crate::FozzyError::InvalidArgument(format!(
                "duplicate output file target detected: {name}"
            )));
        }
        let dst = out_dir.join(&name);
        if dst.exists() {
            let dst_md = std::fs::symlink_metadata(&dst)?;
            if dst_md.file_type().is_symlink() {
                return Err(crate::FozzyError::InvalidArgument(format!(
                    "refusing to overwrite symlinked output file: {}",
                    dst.display()
                )));
            }
            if !dst_md.is_file() {
                return Err(crate::FozzyError::InvalidArgument(format!(
                    "refusing to overwrite non-file output path: {}",
                    dst.display()
                )));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn export_zip_normalizes_unicode_filenames_to_ascii() {
        let root = std::env::temp_dir().join(format!("fozzy-artifacts-unicode-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&root).expect("create temp root");
        let src_a = root.join("résumé-😀.json");
        let src_b = root.join("résumé 👀.json");
        std::fs::write(&src_a, b"{}").expect("write source a");
        std::fs::write(&src_b, b"{}").expect("write source b");
        let out = root.join("out.zip");

        export_artifacts_zip(&[src_a, src_b], &out).expect("zip export");

        let file = std::fs::File::open(&out).expect("open zip");
        let mut archive = zip::ZipArchive::new(file).expect("parse zip");
        let a = archive.by_index(0).expect("entry 0").name().to_string();
        let b = archive.by_index(1).expect("entry 1").name().to_string();

        assert!(a.is_ascii());
        assert!(b.is_ascii());
        assert_ne!(a, b);
        assert!(a.ends_with(".json"));
        assert!(b.ends_with(".json"));
    }

    #[test]
    fn export_missing_input_returns_error_and_does_not_create_zip() {
        let root = std::env::temp_dir().join(format!("fozzy-artifacts-missing-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&root).expect("create temp root");
        let out = root.join("missing-input.zip");

        let cfg = crate::Config {
            base_dir: root.join(".fozzy"),
            reporter: crate::Reporter::Pretty,
        };
        let err = export_artifacts(&cfg, "does-not-exist-input.fozzy", &out).expect_err("must fail");
        assert!(err.to_string().contains("not found"));
        assert!(!out.exists(), "zip should not exist on failure");
    }

    #[test]
    fn export_empty_run_errors() {
        let root = std::env::temp_dir().join(format!("fozzy-artifacts-empty-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&root).expect("create temp root");
        let run_id = "empty-run";
        std::fs::create_dir_all(root.join(".fozzy").join("runs").join(run_id)).expect("create run dir");
        let out = root.join("empty.zip");

        let cfg = crate::Config {
            base_dir: root.join(".fozzy"),
            reporter: crate::Reporter::Pretty,
        };
        let err = export_artifacts(&cfg, run_id, &out).expect_err("must fail");
        assert!(err.to_string().contains("no artifacts found"));
        assert!(!out.exists(), "zip should not exist on failure");
    }

    #[test]
    fn pack_includes_runtime_metadata_files() {
        let root = std::env::temp_dir().join(format!("fozzy-pack-test-{}", uuid::Uuid::new_v4()));
        let run_dir = root.join(".fozzy").join("runs").join("r1");
        std::fs::create_dir_all(&run_dir).expect("mkdir");
        std::fs::write(run_dir.join("report.json"), b"{}").expect("report");
        std::fs::write(run_dir.join("events.json"), b"[]").expect("events");
        std::fs::write(run_dir.join("trace.fozzy"), b"{}").expect("trace");
        let out = root.join("pack.zip");
        let cfg = crate::Config {
            base_dir: root.join(".fozzy"),
            reporter: crate::Reporter::Pretty,
        };
        export_reproducer_pack(&cfg, "r1", &out).expect("pack");
        let file = std::fs::File::open(&out).expect("zip");
        let mut z = zip::ZipArchive::new(file).expect("zip parse");
        let mut names = Vec::new();
        for i in 0..z.len() {
            names.push(z.by_index(i).expect("entry").name().to_string());
        }
        assert!(names.iter().any(|n| n == "env.json"));
        assert!(names.iter().any(|n| n == "version.json"));
        assert!(names.iter().any(|n| n == "commandline.json"));
    }

    #[cfg(unix)]
    #[test]
    fn pack_dir_rejects_symlink_target_overwrite() {
        use std::os::unix::fs::symlink;

        let root = std::env::temp_dir().join(format!("fozzy-pack-symlink-{}", uuid::Uuid::new_v4()));
        let run_dir = root.join(".fozzy").join("runs").join("r1");
        std::fs::create_dir_all(&run_dir).expect("mkdir");
        std::fs::write(run_dir.join("report.json"), br#"{"ok":true}"#).expect("report");
        let cfg = crate::Config {
            base_dir: root.join(".fozzy"),
            reporter: crate::Reporter::Pretty,
        };

        let outside = root.join("outside.json");
        std::fs::write(&outside, br#"{"victim":true}"#).expect("outside");
        let out_dir = root.join("out");
        std::fs::create_dir_all(&out_dir).expect("out");
        symlink(&outside, out_dir.join("report.json")).expect("symlink");

        let err = export_reproducer_pack(&cfg, "r1", &out_dir).expect_err("must reject symlink overwrite");
        assert!(err.to_string().contains("symlinked output file"));
        let victim = std::fs::read_to_string(&outside).expect("read victim");
        assert!(victim.contains("victim"));
    }

    #[cfg(unix)]
    #[test]
    fn pack_dir_failure_atomic_on_symlink_error() {
        use std::os::unix::fs::symlink;

        let root = std::env::temp_dir().join(format!("fozzy-pack-atomic-{}", uuid::Uuid::new_v4()));
        let run_dir = root.join(".fozzy").join("runs").join("r1");
        std::fs::create_dir_all(&run_dir).expect("mkdir");
        std::fs::write(run_dir.join("report.json"), br#"{"report":true}"#).expect("report");
        std::fs::write(run_dir.join("events.json"), br#"[]"#).expect("events");
        std::fs::write(run_dir.join("manifest.json"), br#"{"schemaVersion":"fozzy.run_manifest.v1"}"#).expect("manifest");
        let cfg = crate::Config {
            base_dir: root.join(".fozzy"),
            reporter: crate::Reporter::Pretty,
        };

        let outside = root.join("outside.json");
        std::fs::write(&outside, br#"{"victim":true}"#).expect("outside");
        let out_dir = root.join("out");
        std::fs::create_dir_all(&out_dir).expect("out");
        symlink(&outside, out_dir.join("manifest.json")).expect("symlink");

        let err = export_reproducer_pack(&cfg, "r1", &out_dir).expect_err("must reject symlink overwrite");
        assert!(err.to_string().contains("symlinked output file"));
        assert_eq!(std::fs::read(&outside).expect("victim read"), br#"{"victim":true}"#);
        assert!(!out_dir.join("report.json").exists(), "partial file should not be written");
        assert!(!out_dir.join("events.json").exists(), "partial file should not be written");
    }
}
