//! Fuzz corpus management.

use clap::Subcommand;
use std::collections::HashSet;
use std::fs::File;
use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};

use walkdir::WalkDir;

use crate::{Config, FozzyError, FozzyResult};

#[derive(Debug, Subcommand)]
pub enum CorpusCommand {
    List { dir: PathBuf },
    Add { dir: PathBuf, file: PathBuf },
    Minimize {
        dir: PathBuf,
        #[arg(long)]
        budget: Option<crate::FozzyDuration>,
    },
    Export { dir: PathBuf, #[arg(long)] out: PathBuf },
    Import { zip: PathBuf, #[arg(long)] out: PathBuf },
}

pub fn corpus_command(_config: &Config, command: &CorpusCommand) -> FozzyResult<serde_json::Value> {
    match command {
        CorpusCommand::List { dir } => {
            let mut files = Vec::new();
            if dir.exists() {
                for entry in WalkDir::new(dir).min_depth(1).max_depth(1) {
                    let entry = entry.map_err(|e| {
                        let msg = e.to_string();
                        FozzyError::Io(
                            e.into_io_error()
                                .unwrap_or_else(|| std::io::Error::new(std::io::ErrorKind::Other, msg)),
                        )
                    })?;
                    if entry.file_type().is_file() {
                        files.push(entry.path().to_string_lossy().to_string());
                    }
                }
            }
            files.sort();
            Ok(serde_json::to_value(files)?)
        }

        CorpusCommand::Add { dir, file } => {
            std::fs::create_dir_all(dir)?;
            let bytes = std::fs::read(file)?;
            let name = format!("input-{}.bin", blake3::hash(&bytes).to_hex());
            let out_path = dir.join(name);
            std::fs::write(&out_path, bytes)?;
            Ok(serde_json::json!({"added": out_path.to_string_lossy().to_string()}))
        }

        CorpusCommand::Minimize { dir, budget: _ } => {
            // Placeholder: true corpus minimization depends on the target + coverage signals.
            Ok(serde_json::json!({"ok": true, "dir": dir.to_string_lossy().to_string()}))
        }

        CorpusCommand::Export { dir, out } => {
            export_zip(dir, out)?;
            Ok(serde_json::json!({"ok": true, "zip": out.to_string_lossy().to_string()}))
        }

        CorpusCommand::Import { zip, out } => {
            import_zip(zip, out)?;
            Ok(serde_json::json!({"ok": true, "dir": out.to_string_lossy().to_string()}))
        }
    }
}

fn export_zip(dir: &Path, out_zip: &Path) -> FozzyResult<()> {
    if let Some(parent) = out_zip.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let file = File::create(out_zip)?;
    let mut zip = zip::ZipWriter::new(file);
    let options = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated)
        .unix_permissions(0o644);

    if dir.exists() {
        for entry in WalkDir::new(dir).min_depth(1) {
            let entry = entry.map_err(|e| {
                let msg = e.to_string();
                FozzyError::Io(
                    e.into_io_error()
                        .unwrap_or_else(|| std::io::Error::new(std::io::ErrorKind::Other, msg)),
                )
            })?;
            if !entry.file_type().is_file() {
                continue;
            }

            let rel = entry.path().strip_prefix(dir).unwrap_or(entry.path());
            let name = rel.to_string_lossy().replace('\\', "/");
            zip.start_file(name, options)?;
            let bytes = std::fs::read(entry.path())?;
            zip.write_all(&bytes)?;
        }
    }

    zip.finish()?;
    Ok(())
}

fn import_zip(zip_path: &Path, out_dir: &Path) -> FozzyResult<()> {
    std::fs::create_dir_all(out_dir)?;
    if std::fs::symlink_metadata(out_dir)?.file_type().is_symlink() {
        return Err(FozzyError::InvalidArgument(format!(
            "refusing to import into symlinked output directory: {}",
            out_dir.display()
        )));
    }

    let file = File::open(zip_path)?;
    let mut zip = zip::ZipArchive::new(file).map_err(|e| FozzyError::InvalidArgument(format!("invalid zip: {e}")))?;
    let mut seen_targets = HashSet::new();
    for i in 0..zip.len() {
        let f = zip.by_index(i).map_err(|e| FozzyError::InvalidArgument(format!("zip read error: {e}")))?;
        if f.is_dir() {
            continue;
        }
        validate_zip_entry_name_raw(f.name_raw(), f.name())?;
        let rel = normalize_zip_entry_rel_path(f.name())?;
        validate_zip_target_secure(out_dir, &rel, &mut seen_targets)?;
    }

    let file = File::open(zip_path)?;
    let mut zip = zip::ZipArchive::new(file).map_err(|e| FozzyError::InvalidArgument(format!("invalid zip: {e}")))?;
    for i in 0..zip.len() {
        let mut f = zip.by_index(i).map_err(|e| FozzyError::InvalidArgument(format!("zip read error: {e}")))?;
        if f.is_dir() {
            continue;
        }
        validate_zip_entry_name_raw(f.name_raw(), f.name())?;
        let mut bytes = Vec::new();
        f.read_to_end(&mut bytes)?;
        write_zip_entry_secure(out_dir, f.name(), &bytes)?;
    }
    Ok(())
}

fn write_zip_entry_secure(out_dir: &Path, entry_name: &str, bytes: &[u8]) -> FozzyResult<()> {
    let rel = normalize_zip_entry_rel_path(entry_name)?;
    let out_path = out_dir.join(&rel);

    // Reject symlinked parent components before creating/writing.
    let mut cur = out_dir.to_path_buf();
    if let Some(parent) = rel.parent() {
        for comp in parent.components() {
            use std::path::Component;
            let Component::Normal(seg) = comp else {
                continue;
            };
            cur.push(seg);
            if cur.exists() {
                let md = std::fs::symlink_metadata(&cur)?;
                if md.file_type().is_symlink() {
                    return Err(FozzyError::InvalidArgument(format!(
                        "refusing to write through symlinked output path: {}",
                        cur.display()
                    )));
                }
            } else {
                std::fs::create_dir(&cur)?;
            }
        }
    }

    if out_path.exists() {
        let md = std::fs::symlink_metadata(&out_path)?;
        if md.file_type().is_symlink() {
            return Err(FozzyError::InvalidArgument(format!(
                "refusing to overwrite symlinked output file: {}",
                out_path.display()
            )));
        }
        if !md.is_file() {
            return Err(FozzyError::InvalidArgument(format!(
                "refusing to overwrite non-file output path: {}",
                out_path.display()
            )));
        }
        return Err(FozzyError::InvalidArgument(format!(
            "refusing to overwrite existing output file: {}",
            out_path.display()
        )));
    }

    let parent = out_path.parent().unwrap_or(out_dir);
    let tmp_name = format!(
        ".{}.{}.{}.tmp",
        out_path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("corpus"),
        std::process::id(),
        uuid::Uuid::new_v4()
    );
    let tmp = parent.join(tmp_name);
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(&tmp, &out_path)?;
    Ok(())
}

fn validate_zip_target_secure(out_dir: &Path, rel: &Path, seen_targets: &mut HashSet<String>) -> FozzyResult<()> {
    let key = portable_rel_key(rel);
    if !seen_targets.insert(key) {
        return Err(FozzyError::InvalidArgument(format!(
            "duplicate output file in archive is not allowed: {}",
            rel.display()
        )));
    }

    // Reject symlinked parent components before creating/writing.
    let mut cur = out_dir.to_path_buf();
    if let Some(parent) = rel.parent() {
        for comp in parent.components() {
            use std::path::Component;
            let Component::Normal(seg) = comp else {
                continue;
            };
            cur.push(seg);
            if cur.exists() {
                let md = std::fs::symlink_metadata(&cur)?;
                if md.file_type().is_symlink() {
                    return Err(FozzyError::InvalidArgument(format!(
                        "refusing to write through symlinked output path: {}",
                        cur.display()
                    )));
                }
            }
        }
    }

    let out_path = out_dir.join(rel);
    if out_path.exists() {
        let md = std::fs::symlink_metadata(&out_path)?;
        if md.file_type().is_symlink() {
            return Err(FozzyError::InvalidArgument(format!(
                "refusing to overwrite symlinked output file: {}",
                out_path.display()
            )));
        }
        if !md.is_file() {
            return Err(FozzyError::InvalidArgument(format!(
                "refusing to overwrite non-file output path: {}",
                out_path.display()
            )));
        }
        return Err(FozzyError::InvalidArgument(format!(
            "refusing to overwrite existing output file: {}",
            out_path.display()
        )));
    }

    Ok(())
}

fn portable_rel_key(rel: &Path) -> String {
    let mut out = String::new();
    for (idx, comp) in rel.components().enumerate() {
        use std::path::Component;
        if let Component::Normal(seg) = comp {
            if idx > 0 {
                out.push('/');
            }
            out.push_str(&seg.to_string_lossy().to_lowercase());
        }
    }
    out
}

fn normalize_zip_entry_rel_path(name: &str) -> FozzyResult<PathBuf> {
    // Archive entry names must be portable relative POSIX-style paths.
    // Reject Windows-style separators/prefixes/UNC roots on every host.
    if name.starts_with("//")
        || name.starts_with("\\\\")
        || name.contains('\\')
        || is_windows_drive_prefixed(name)
    {
        return Err(FozzyError::InvalidArgument(format!(
            "unsafe archive entry path rejected: {name}"
        )));
    }

    let path = Path::new(name);
    let mut rel = PathBuf::new();
    for comp in path.components() {
        use std::path::Component;
        match comp {
            Component::Normal(seg) => {
                let seg = seg.to_str().ok_or_else(|| {
                    FozzyError::InvalidArgument(format!("unsafe archive entry path rejected: {name}"))
                })?;
                validate_archive_path_segment(seg, name)?;
                rel.push(seg);
            }
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(FozzyError::InvalidArgument(format!(
                    "unsafe archive entry path rejected: {name}"
                )));
            }
        }
    }
    if rel.as_os_str().is_empty() {
        return Err(FozzyError::InvalidArgument(format!(
            "unsafe archive entry path rejected: {name}"
        )));
    }
    Ok(rel)
}

fn validate_zip_entry_name_raw(raw_name: &[u8], display_name: &str) -> FozzyResult<()> {
    if raw_name.contains(&0) {
        return Err(FozzyError::InvalidArgument(format!(
            "unsafe archive entry path rejected: {display_name}"
        )));
    }
    Ok(())
}

fn is_windows_drive_prefixed(name: &str) -> bool {
    let b = name.as_bytes();
    b.len() >= 2 && b[0].is_ascii_alphabetic() && b[1] == b':'
}

fn validate_archive_path_segment(seg: &str, original_name: &str) -> FozzyResult<()> {
    if seg.is_empty() {
        return Err(FozzyError::InvalidArgument(format!(
            "unsafe archive entry path rejected: {original_name}"
        )));
    }

    // Keep entry names portable and safe across platforms/tools.
    if seg.ends_with('.') || seg.ends_with(' ') {
        return Err(FozzyError::InvalidArgument(format!(
            "unsafe archive entry path rejected: {original_name}"
        )));
    }

    if seg.chars().any(|c| c.is_control() || matches!(c, ':' | '*' | '?' | '"' | '<' | '>' | '|')) {
        return Err(FozzyError::InvalidArgument(format!(
            "unsafe archive entry path rejected: {original_name}"
        )));
    }

    if is_windows_reserved_name(seg) {
        return Err(FozzyError::InvalidArgument(format!(
            "unsafe archive entry path rejected: {original_name}"
        )));
    }

    Ok(())
}

fn is_windows_reserved_name(seg: &str) -> bool {
    let trimmed = seg.trim_end_matches(['.', ' ']);
    let stem = trimmed.split('.').next().unwrap_or(trimmed);
    let upper = stem.to_ascii_uppercase();
    matches!(
        upper.as_str(),
        "CON"
            | "PRN"
            | "AUX"
            | "NUL"
            | "COM1"
            | "COM2"
            | "COM3"
            | "COM4"
            | "COM5"
            | "COM6"
            | "COM7"
            | "COM8"
            | "COM9"
            | "LPT1"
            | "LPT2"
            | "LPT3"
            | "LPT4"
            | "LPT5"
            | "LPT6"
            | "LPT7"
            | "LPT8"
            | "LPT9"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn import_rejects_symlink_target_overwrite() {
        use std::os::unix::fs::symlink;

        let root = std::env::temp_dir().join(format!("fozzy-corpus-symlink-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&root).expect("root");
        let zip_path = root.join("in.zip");

        {
            let file = File::create(&zip_path).expect("zip create");
            let mut zip = zip::ZipWriter::new(file);
            let opts = zip::write::SimpleFileOptions::default();
            zip.start_file("payload.bin", opts).expect("start");
            zip.write_all(b"evil").expect("write");
            zip.finish().expect("finish");
        }

        let out = root.join("out");
        std::fs::create_dir_all(&out).expect("out");
        let victim = root.join("victim.bin");
        std::fs::write(&victim, b"safe").expect("victim");
        symlink(&victim, out.join("payload.bin")).expect("symlink");

        let err = import_zip(&zip_path, &out).expect_err("must fail");
        assert!(err.to_string().contains("symlinked output file"));
        assert_eq!(std::fs::read(&victim).expect("victim read"), b"safe");
    }

    #[cfg(unix)]
    #[test]
    fn import_failure_atomic_on_symlink_error() {
        use std::os::unix::fs::symlink;

        let root = std::env::temp_dir().join(format!(
            "fozzy-corpus-atomic-symlink-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&root).expect("root");
        let zip_path = root.join("in.zip");

        {
            let file = File::create(&zip_path).expect("zip create");
            let mut zip = zip::ZipWriter::new(file);
            let opts = zip::write::SimpleFileOptions::default();
            zip.start_file("good-1.bin", opts).expect("start 1");
            zip.write_all(b"one").expect("write 1");
            zip.start_file("good-2.bin", opts).expect("start 2");
            zip.write_all(b"two").expect("write 2");
            zip.start_file("bad.bin", opts).expect("start bad");
            zip.write_all(b"bad").expect("write bad");
            zip.finish().expect("finish");
        }

        let out = root.join("out");
        std::fs::create_dir_all(&out).expect("out");
        let victim = root.join("victim.bin");
        std::fs::write(&victim, b"safe").expect("victim");
        symlink(&victim, out.join("bad.bin")).expect("symlink");

        let err = import_zip(&zip_path, &out).expect_err("must fail");
        assert!(err.to_string().contains("symlinked output file"));
        assert_eq!(std::fs::read(&victim).expect("victim read"), b"safe");
        assert!(!out.join("good-1.bin").exists(), "good-1 should not be written");
        assert!(!out.join("good-2.bin").exists(), "good-2 should not be written");
    }

    #[test]
    fn normalize_rejects_windows_style_unsafe_paths() {
        for bad in [
            r"..\\evil_win.bin",
            r"C:\evil_drive.bin",
            "C:evil_drive.bin",
            r"\\server\share\evil_unc.bin",
            "//server/share/evil_unc.bin",
        ] {
            let err = normalize_zip_entry_rel_path(bad).expect_err("must reject windows-style unsafe path");
            assert!(err.to_string().contains("unsafe archive entry path rejected"));
        }
    }

    #[test]
    fn normalize_rejects_special_unsafe_filenames() {
        for bad in [
            "\u{0001}.bin",
            "\u{0000}TRUNC.bin",
            "CON",
            "aux.txt",
            "name-with-trailing-dot.",
            "name-with-trailing-space ",
            "bad:name.bin",
            "bad*name.bin",
            "bad?name.bin",
        ] {
            let err = normalize_zip_entry_rel_path(bad).expect_err("must reject unsafe special filename");
            assert!(err.to_string().contains("unsafe archive entry path rejected"));
        }
    }

    #[test]
    fn import_rejects_duplicate_entry_aliases() {
        let root = std::env::temp_dir().join(format!("fozzy-corpus-dup-alias-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&root).expect("root");
        let zip_path = root.join("in.zip");

        {
            let file = File::create(&zip_path).expect("zip create");
            let mut zip = zip::ZipWriter::new(file);
            let opts = zip::write::SimpleFileOptions::default();
            zip.start_file("dup.bin", opts).expect("start 1");
            zip.write_all(b"first").expect("write 1");
            zip.start_file("./dup.bin", opts).expect("start 2");
            zip.write_all(b"second").expect("write 2");
            zip.finish().expect("finish");
        }

        let out = root.join("out");
        std::fs::create_dir_all(&out).expect("out");

        let err = import_zip(&zip_path, &out).expect_err("must reject alias duplicates");
        assert!(err.to_string().contains("duplicate output file in archive is not allowed"));
        assert!(!out.join("dup.bin").exists(), "duplicate rejection should be failure-atomic");
    }

    #[test]
    fn import_rejects_case_insensitive_duplicate_entry_names() {
        let root = std::env::temp_dir().join(format!("fozzy-corpus-dup-case-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&root).expect("root");
        let zip_path = root.join("in.zip");

        {
            let file = File::create(&zip_path).expect("zip create");
            let mut zip = zip::ZipWriter::new(file);
            let opts = zip::write::SimpleFileOptions::default();
            zip.start_file("dup.bin", opts).expect("start 1");
            zip.write_all(b"first").expect("write 1");
            zip.start_file("DUP.BIN", opts).expect("start 2");
            zip.write_all(b"second").expect("write 2");
            zip.finish().expect("finish");
        }

        let out = root.join("out");
        std::fs::create_dir_all(&out).expect("out");

        let err = import_zip(&zip_path, &out).expect_err("must reject case-insensitive duplicates");
        assert!(err.to_string().contains("duplicate output file in archive is not allowed"));
        assert!(!out.join("dup.bin").exists(), "duplicate rejection should be failure-atomic");
        assert!(!out.join("DUP.BIN").exists(), "duplicate rejection should be failure-atomic");
    }

    #[test]
    fn import_rejects_overwrite_of_existing_file() {
        let root = std::env::temp_dir().join(format!("fozzy-corpus-overwrite-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&root).expect("root");
        let zip_path = root.join("in.zip");

        {
            let file = File::create(&zip_path).expect("zip create");
            let mut zip = zip::ZipWriter::new(file);
            let opts = zip::write::SimpleFileOptions::default();
            zip.start_file("dup.bin", opts).expect("start");
            zip.write_all(b"new").expect("write");
            zip.finish().expect("finish");
        }

        let out = root.join("out");
        std::fs::create_dir_all(&out).expect("out");
        std::fs::write(out.join("dup.bin"), b"old").expect("seed existing");

        let err = import_zip(&zip_path, &out).expect_err("must reject overwrite");
        assert!(err.to_string().contains("refusing to overwrite existing output file"));
        assert_eq!(std::fs::read(out.join("dup.bin")).expect("read"), b"old");
    }

    #[test]
    fn import_rejects_nul_in_raw_entry_name() {
        let root = std::env::temp_dir().join(format!("fozzy-corpus-nul-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&root).expect("root");
        let zip_path = root.join("in.zip");

        {
            let file = File::create(&zip_path).expect("zip create");
            let mut zip = zip::ZipWriter::new(file);
            let opts = zip::write::SimpleFileOptions::default();
            zip.start_file("bad\0name.bin", opts).expect("start");
            zip.write_all(b"payload").expect("write");
            zip.finish().expect("finish");
        }

        let out = root.join("out");
        std::fs::create_dir_all(&out).expect("out");

        let err = import_zip(&zip_path, &out).expect_err("must reject nul entry names");
        assert!(err.to_string().contains("unsafe archive entry path rejected"));
        assert!(!out.join("bad").exists(), "must not write truncated output");
    }
}
