//! Small filesystem utilities.

use globset::{Glob, GlobSet, GlobSetBuilder};

use std::collections::BTreeSet;
use std::path::PathBuf;

use walkdir::WalkDir;

use crate::{FozzyError, FozzyResult};

pub fn find_matching_files(patterns: &[String]) -> FozzyResult<Vec<PathBuf>> {
    let set = compile_globset(patterns)?;
    let cwd = std::env::current_dir()?;
    let mut out = BTreeSet::new();

    // Accept direct file paths (absolute or relative) even when they are outside cwd.
    for pattern in patterns {
        if has_glob_meta(pattern) {
            continue;
        }
        let candidate = PathBuf::from(pattern);
        if candidate.is_file() {
            out.insert(candidate);
        }
    }

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
        let abs = cwd.join(rel);
        if set.is_match(rel) || set.is_match(&abs) {
            out.insert(rel.to_path_buf());
        }
    }
    Ok(out.into_iter().collect())
}

fn compile_globset(patterns: &[String]) -> FozzyResult<GlobSet> {
    let mut b = GlobSetBuilder::new();
    for p in patterns {
        let g = Glob::new(p)
            .map_err(|e| FozzyError::InvalidArgument(format!("invalid glob {p:?}: {e}")))?;
        b.add(g);
    }
    b.build()
        .map_err(|e| FozzyError::InvalidArgument(format!("invalid globset: {e}")))
}

fn has_glob_meta(pattern: &str) -> bool {
    pattern.contains('*')
        || pattern.contains('?')
        || pattern.contains('[')
        || pattern.contains(']')
        || pattern.contains('{')
        || pattern.contains('}')
}

pub fn default_min_trace_path(input: &std::path::Path) -> PathBuf {
    let parent = input
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("."));
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

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("fozzy-fsutil-{name}-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        dir
    }

    #[test]
    fn find_matching_files_accepts_absolute_file_path() {
        let root = temp_dir("abs-file");
        let scenario = root.join("abs.fozzy.json");
        std::fs::write(&scenario, br#"{"version":1,"name":"x","steps":[]}"#)
            .expect("write scenario");
        let matches =
            find_matching_files(&[scenario.to_string_lossy().to_string()]).expect("match files");
        assert!(matches.iter().any(|p| p == &scenario));
    }
}
