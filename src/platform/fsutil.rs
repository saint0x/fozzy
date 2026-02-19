//! Small filesystem utilities.

use globset::{Glob, GlobSet, GlobSetBuilder};

use std::path::PathBuf;

use walkdir::WalkDir;

use crate::{FozzyError, FozzyResult};

pub fn find_matching_files(patterns: &[String]) -> FozzyResult<Vec<PathBuf>> {
    let set = compile_globset(patterns)?;
    let mut out = Vec::new();
    for entry in WalkDir::new(".").follow_links(false) {
        let entry = entry.map_err(|e| {
            let msg = e.to_string();
            FozzyError::Io(
                e.into_io_error()
                    .unwrap_or_else(|| std::io::Error::other(msg)),
            )
        })?;
        if !entry.file_type().is_file() {
            continue;
        }
        let p = entry.path();
        let rel = p.strip_prefix(".").unwrap_or(p);
        if set.is_match(rel) {
            out.push(rel.to_path_buf());
        }
    }
    out.sort();
    Ok(out)
}

fn compile_globset(patterns: &[String]) -> FozzyResult<GlobSet> {
    let mut b = GlobSetBuilder::new();
    for p in patterns {
        let g = Glob::new(p).map_err(|e| FozzyError::InvalidArgument(format!("invalid glob {p:?}: {e}")))?;
        b.add(g);
    }
    b.build()
        .map_err(|e| FozzyError::InvalidArgument(format!("invalid globset: {e}")))
}

pub fn default_min_trace_path(input: &std::path::Path) -> PathBuf {
    let parent = input.parent().map(|p| p.to_path_buf()).unwrap_or_else(|| PathBuf::from("."));
    let file_name = input
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("trace.fozzy");

    let out_name = if let Some(stem) = file_name.strip_suffix(".fozzy") {
        format!("{stem}.min.fozzy")
    } else {
        format!("{file_name}.min.fozzy")
    };

    parent.join(out_name)
}
