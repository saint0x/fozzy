//! Artifact management (`fozzy artifacts ...`).

use clap::Subcommand;
use serde::{Deserialize, Serialize};

use std::path::{Path, PathBuf};

use crate::{Config, FozzyResult};

#[derive(Debug, Subcommand)]
pub enum ArtifactCommand {
    Ls { run: String },
    Export { run: String, #[arg(long)] out: PathBuf },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactKind {
    Trace,
    Timeline,
    Events,
    Report,
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

pub fn artifacts_command(config: &Config, command: &ArtifactCommand) -> FozzyResult<Vec<ArtifactEntry>> {
    match command {
        ArtifactCommand::Ls { run } => artifacts_list(config, run),
        ArtifactCommand::Export { run, out } => {
            export_artifacts(config, run, out)?;
            Ok(Vec::new())
        }
    }
}

fn artifacts_list(config: &Config, run: &str) -> FozzyResult<Vec<ArtifactEntry>> {
    let artifacts_dir = resolve_artifacts_dir(config, run)?;
    let mut out = Vec::new();

    push_if_exists(&mut out, ArtifactKind::Trace, artifacts_dir.join("trace.fozzy"))?;
    push_if_exists(&mut out, ArtifactKind::Timeline, artifacts_dir.join("timeline.json"))?;
    push_if_exists(&mut out, ArtifactKind::Report, artifacts_dir.join("report.json"))?;
    push_if_exists(&mut out, ArtifactKind::Events, artifacts_dir.join("events.json"))?;
    push_if_exists(&mut out, ArtifactKind::Report, artifacts_dir.join("report.html"))?;
    push_if_exists(&mut out, ArtifactKind::Report, artifacts_dir.join("junit.xml"))?;

    Ok(out)
}

fn export_artifacts(config: &Config, run: &str, out: &Path) -> FozzyResult<()> {
    let artifacts_dir = resolve_artifacts_dir(config, run)?;
    if out
        .extension()
        .and_then(|s| s.to_str())
        .is_some_and(|s| s.eq_ignore_ascii_case("zip"))
    {
        export_artifacts_zip(&artifacts_dir, out)?;
        return Ok(());
    }

    std::fs::create_dir_all(out)?;

    for entry in std::fs::read_dir(&artifacts_dir)? {
        let entry = entry?;
        let ty = entry.file_type()?;
        if !ty.is_file() {
            continue;
        }
        let src = entry.path();
        let dst = out.join(entry.file_name());
        std::fs::copy(src, dst)?;
    }

    Ok(())
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

fn export_artifacts_zip(artifacts_dir: &Path, out_zip: &Path) -> FozzyResult<()> {
    use std::fs::File;
    use std::io::Write as _;

    if let Some(parent) = out_zip.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let file = File::create(out_zip)?;
    let mut zip = zip::ZipWriter::new(file);
    let options = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated)
        .unix_permissions(0o644);

    for entry in std::fs::read_dir(artifacts_dir)? {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().to_string();
        zip.start_file(name, options)?;
        let bytes = std::fs::read(entry.path())?;
        zip.write_all(&bytes)?;
    }

    zip.finish()?;
    Ok(())
}
