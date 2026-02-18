use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use crate::{
    artifacts_command, report_command, replay_trace, verify_trace_file, ArtifactCommand, Config, FlakeBudget,
    FozzyError, FozzyResult, ReportCommand, ReplayOptions, Reporter, TraceFile, TracePath,
};

#[derive(Debug, Clone)]
pub struct CiOptions {
    pub trace: PathBuf,
    pub flake_runs: Vec<String>,
    pub flake_budget_pct: Option<FlakeBudget>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CiCheck {
    pub name: String,
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CiReport {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    pub ok: bool,
    pub checks: Vec<CiCheck>,
}

pub fn ci_command(config: &Config, opt: &CiOptions) -> FozzyResult<CiReport> {
    let mut checks = Vec::new();

    let verify = verify_trace_file(&opt.trace)?;
    checks.push(CiCheck {
        name: "trace_verify".to_string(),
        ok: verify.ok,
        detail: if verify.warnings.is_empty() {
            None
        } else {
            Some(verify.warnings.join("; "))
        },
    });

    let trace = TraceFile::read_json(&opt.trace)?;
    let replay = replay_trace(
        config,
        TracePath::new(opt.trace.clone()),
        &ReplayOptions {
            step: false,
            until: None,
            dump_events: false,
            reporter: Reporter::Json,
        },
    )?;
    let expected = if trace.summary.status == crate::ExitStatus::Pass {
        "pass"
    } else {
        "non_pass"
    };
    let got = if replay.summary.status == crate::ExitStatus::Pass {
        "pass"
    } else {
        "non_pass"
    };
    checks.push(CiCheck {
        name: "replay_outcome_class".to_string(),
        ok: expected == got,
        detail: Some(format!("expected={expected} got={got}")),
    });

    let zip_path = std::env::temp_dir().join(format!("fozzy-ci-export-{}.zip", uuid::Uuid::new_v4()));
    artifacts_command(
        config,
        &ArtifactCommand::Export {
            run: opt.trace.display().to_string(),
            out: zip_path.clone(),
        },
    )?;
    let zip_ok = if zip_path.exists() {
        let file = std::fs::File::open(&zip_path)?;
        let mut zip = zip::ZipArchive::new(file).map_err(|e| FozzyError::Zip(e.to_string()))?;
        for i in 0..zip.len() {
            let mut entry = zip.by_index(i).map_err(|e| FozzyError::Zip(e.to_string()))?;
            if entry.is_dir() {
                continue;
            }
            let mut sink = std::io::sink();
            std::io::copy(&mut entry, &mut sink)?;
        }
        true
    } else {
        false
    };
    checks.push(CiCheck {
        name: "artifacts_zip_integrity".to_string(),
        ok: zip_ok,
        detail: Some(zip_path.display().to_string()),
    });
    let _ = std::fs::remove_file(zip_path);

    if !opt.flake_runs.is_empty() {
        if opt.flake_runs.len() < 2 {
            return Err(FozzyError::InvalidArgument(
                "--flake-run requires at least two runs when provided".to_string(),
            ));
        }
        let out = report_command(
            config,
            &ReportCommand::Flaky {
                runs: opt.flake_runs.clone(),
                flake_budget: opt.flake_budget_pct,
            },
        )?;
        let rate = out
            .get("flakeRatePct")
            .and_then(|v| v.as_f64())
            .unwrap_or(100.0);
        checks.push(CiCheck {
            name: "flake_budget".to_string(),
            ok: true,
            detail: Some(format!("flake_rate_pct={rate:.2}")),
        });
    }

    let ok = checks.iter().all(|c| c.ok);
    if !ok {
        return Err(FozzyError::InvalidArgument(
            "ci gate failed (one or more checks failed)".to_string(),
        ));
    }
    Ok(CiReport {
        schema_version: "fozzy.ci_report.v1".to_string(),
        ok,
        checks,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ci_command_runs_core_checks() {
        let root = std::env::temp_dir().join(format!("fozzy-ci-cmd-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&root).expect("mkdir");
        let trace = root.join("trace.fozzy");
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
          }
        }"#;
        std::fs::write(&trace, raw).expect("write trace");
        let cfg = Config {
            base_dir: root.join(".fozzy"),
            reporter: Reporter::Json,
        };

        let out = ci_command(
            &cfg,
            &CiOptions {
                trace,
                flake_runs: Vec::new(),
                flake_budget_pct: None,
            },
        )
        .expect("ci command");
        assert!(out.ok);
        assert!(out.checks.iter().any(|c| c.name == "trace_verify"));
        assert!(out.checks.iter().any(|c| c.name == "replay_outcome_class"));
        assert!(out.checks.iter().any(|c| c.name == "artifacts_zip_integrity"));
    }
}
