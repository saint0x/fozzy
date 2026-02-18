use std::path::PathBuf;
use std::process::Command;

fn temp_workspace(name: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!("fozzy-cli-{name}-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&root).expect("create temp workspace");
    root
}

fn fixture(name: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests").join(name);
    std::fs::read_to_string(path).expect("read fixture")
}

fn run_cli(args: &[String]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_fozzy"))
        .args(args)
        .output()
        .expect("run cli")
}

#[test]
fn common_global_and_mode_flags_parse_across_run_like_commands() {
    let ws = temp_workspace("parity");
    std::fs::write(ws.join("fozzy.toml"), "base_dir = \".fozzy\"\n").expect("write config");
    std::fs::write(ws.join("example.fozzy.json"), fixture("example.fozzy.json")).expect("write example");
    std::fs::write(ws.join("kv.explore.fozzy.json"), fixture("kv.explore.fozzy.json")).expect("write explore");

    let cfg = ws.join("fozzy.toml").to_string_lossy().to_string();
    let cwd = ws.to_string_lossy().to_string();
    let run_scenario = ws.join("example.fozzy.json").to_string_lossy().to_string();
    let explore_scenario = ws.join("kv.explore.fozzy.json").to_string_lossy().to_string();

    let run = run_cli(&[
        "run".into(),
        run_scenario.clone(),
        "--det".into(),
        "--seed".into(),
        "7".into(),
        "--reporter".into(),
        "json".into(),
        "--json".into(),
        "--cwd".into(),
        cwd.clone(),
        "--config".into(),
        cfg.clone(),
    ]);
    assert_eq!(
        run.status.code(),
        Some(0),
        "run stderr={}",
        String::from_utf8_lossy(&run.stderr)
    );

    let test = run_cli(&[
        "test".into(),
        "example.fozzy.json".into(),
        "--det".into(),
        "--seed".into(),
        "7".into(),
        "--reporter".into(),
        "json".into(),
        "--json".into(),
        "--cwd".into(),
        cwd.clone(),
        "--config".into(),
        cfg.clone(),
    ]);
    assert_eq!(
        test.status.code(),
        Some(0),
        "test stderr={}",
        String::from_utf8_lossy(&test.stderr)
    );

    let fuzz = run_cli(&[
        "fuzz".into(),
        "fn:utf8".into(),
        "--seed".into(),
        "7".into(),
        "--runs".into(),
        "1".into(),
        "--reporter".into(),
        "json".into(),
        "--json".into(),
        "--cwd".into(),
        cwd.clone(),
        "--config".into(),
        cfg.clone(),
    ]);
    assert_ne!(
        fuzz.status.code(),
        Some(2),
        "fuzz should parse/execute; stderr={}",
        String::from_utf8_lossy(&fuzz.stderr)
    );

    let explore = run_cli(&[
        "explore".into(),
        explore_scenario,
        "--seed".into(),
        "7".into(),
        "--steps".into(),
        "10".into(),
        "--reporter".into(),
        "json".into(),
        "--json".into(),
        "--cwd".into(),
        cwd,
        "--config".into(),
        cfg,
    ]);
    assert_eq!(
        explore.status.code(),
        Some(0),
        "explore stderr={}",
        String::from_utf8_lossy(&explore.stderr)
    );
}

#[test]
fn strict_mode_fails_on_stale_trace_verify_warnings() {
    let ws = temp_workspace("strict");
    let trace = ws.join("stale.fozzy");
    let raw = r#"{
      "format":"fozzy-trace",
      "version":1,
      "engine":{"version":"0.1.0"},
      "mode":"run",
      "scenario_path":"tests/example.fozzy.json",
      "scenario":{"version":1,"name":"example","steps":[]},
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
    let trace_arg = trace.to_string_lossy().to_string();

    let ok = run_cli(&["trace".into(), "verify".into(), trace_arg.clone(), "--json".into()]);
    assert_eq!(ok.status.code(), Some(0), "non-strict should pass");

    let strict = run_cli(&[
        "trace".into(),
        "verify".into(),
        trace_arg,
        "--json".into(),
        "--strict".into(),
    ]);
    assert_eq!(strict.status.code(), Some(2), "strict should fail");
}

#[test]
fn non_finite_flake_budget_is_rejected() {
    let ws = temp_workspace("flake-budget");
    std::fs::write(ws.join("fozzy.toml"), "base_dir = \".fozzy\"\n").expect("write config");
    let cfg = ws.join("fozzy.toml").to_string_lossy().to_string();
    let cwd = ws.to_string_lossy().to_string();

    let report_nan = run_cli(&[
        "report".into(),
        "flaky".into(),
        "r1".into(),
        "r2".into(),
        "--flake-budget".into(),
        "NaN".into(),
        "--cwd".into(),
        cwd.clone(),
        "--config".into(),
        cfg.clone(),
    ]);
    assert_eq!(report_nan.status.code(), Some(2), "NaN should be rejected");

    let report_inf = run_cli(&[
        "report".into(),
        "flaky".into(),
        "r1".into(),
        "r2".into(),
        "--flake-budget".into(),
        "inf".into(),
        "--cwd".into(),
        cwd.clone(),
        "--config".into(),
        cfg.clone(),
    ]);
    assert_eq!(report_inf.status.code(), Some(2), "inf should be rejected");

    let ci_nan = run_cli(&[
        "ci".into(),
        "trace.fozzy".into(),
        "--flake-budget".into(),
        "NaN".into(),
        "--cwd".into(),
        cwd,
        "--config".into(),
        cfg,
    ]);
    assert_eq!(ci_nan.status.code(), Some(2), "ci NaN should be rejected");
}

#[test]
fn strict_rejects_checksumless_trace_in_verify_and_ci() {
    let ws = temp_workspace("strict-checksum");
    let trace = ws.join("no-checksum.fozzy");
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
    let trace_arg = trace.to_string_lossy().to_string();

    let strict_verify = run_cli(&[
        "--strict".into(),
        "trace".into(),
        "verify".into(),
        trace_arg.clone(),
        "--json".into(),
    ]);
    assert_eq!(strict_verify.status.code(), Some(2), "strict trace verify should fail");

    let strict_ci = run_cli(&[
        "--strict".into(),
        "ci".into(),
        trace_arg,
        "--json".into(),
    ]);
    assert_eq!(strict_ci.status.code(), Some(2), "strict ci should fail");
}

#[test]
fn strict_trace_verify_json_emits_single_error_document() {
    let ws = temp_workspace("strict-json-contract");
    let trace = ws.join("stale.fozzy");
    let raw = r#"{
      "format":"fozzy-trace",
      "version":1,
      "engine":{"version":"0.1.0"},
      "mode":"run",
      "scenario_path":"tests/example.fozzy.json",
      "scenario":{"version":1,"name":"example","steps":[]},
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
    let trace_arg = trace.to_string_lossy().to_string();

    let strict = run_cli(&[
        "--strict".into(),
        "trace".into(),
        "verify".into(),
        trace_arg,
        "--json".into(),
    ]);
    assert_eq!(strict.status.code(), Some(2), "strict should fail");

    let stdout = String::from_utf8_lossy(&strict.stdout);
    let lines: Vec<&str> = stdout.lines().filter(|l| !l.trim().is_empty()).collect();
    assert_eq!(lines.len(), 1, "must emit a single JSON document on stdout, got: {stdout}");

    let doc: serde_json::Value = serde_json::from_str(lines[0]).expect("stdout json");
    assert_eq!(doc.get("code").and_then(|v| v.as_str()), Some("error"));
}

#[test]
fn invalid_trace_header_is_rejected_in_non_strict_verify_replay_and_ci() {
    let ws = temp_workspace("trace-header");
    let bad_format = ws.join("bad-format.fozzy");
    let bad_version = ws.join("bad-version.fozzy");

    let base = |format: &str, version: u32| -> String {
        format!(
            r#"{{
      "format":"{format}",
      "version":{version},
      "engine":{{"version":"0.1.0"}},
      "mode":"run",
      "scenario_path":null,
      "scenario":{{"version":1,"name":"x","steps":[]}},
      "decisions":[],
      "events":[],
      "summary":{{
        "status":"pass",
        "mode":"run",
        "identity":{{"runId":"r1","seed":1}},
        "startedAt":"2026-01-01T00:00:00Z",
        "finishedAt":"2026-01-01T00:00:00Z",
        "durationMs":0
      }}
    }}"#
        )
    };

    std::fs::write(&bad_format, base("fozzy-trace-vX", 2)).expect("write bad format");
    std::fs::write(&bad_version, base("fozzy-trace", 999)).expect("write bad version");

    let bad_format_arg = bad_format.to_string_lossy().to_string();
    let bad_version_arg = bad_version.to_string_lossy().to_string();

    let verify_bad_format = run_cli(&[
        "trace".into(),
        "verify".into(),
        bad_format_arg.clone(),
        "--json".into(),
    ]);
    assert_eq!(
        verify_bad_format.status.code(),
        Some(2),
        "trace verify must reject bad format in non-strict mode"
    );

    let replay_bad_version = run_cli(&[
        "replay".into(),
        bad_version_arg.clone(),
        "--json".into(),
    ]);
    assert_eq!(
        replay_bad_version.status.code(),
        Some(2),
        "replay must reject bad version in non-strict mode"
    );

    let ci_bad_version = run_cli(&[
        "ci".into(),
        bad_version_arg,
        "--json".into(),
    ]);
    assert_eq!(
        ci_bad_version.status.code(),
        Some(2),
        "ci must reject bad version in non-strict mode"
    );
}

#[test]
fn ci_rejects_flake_budget_without_flake_runs() {
    let ws = temp_workspace("ci-budget");
    let trace = ws.join("trace.fozzy");
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
    let trace_arg = trace.to_string_lossy().to_string();

    let normal = run_cli(&[
        "ci".into(),
        trace_arg.clone(),
        "--flake-budget".into(),
        "5".into(),
        "--json".into(),
    ]);
    assert_eq!(normal.status.code(), Some(2), "normal mode should reject misconfig");

    let strict = run_cli(&[
        "--strict".into(),
        "ci".into(),
        trace_arg,
        "--flake-budget".into(),
        "5".into(),
        "--json".into(),
    ]);
    assert_eq!(strict.status.code(), Some(2), "strict mode should reject misconfig");
}

#[test]
fn report_flaky_rejects_duplicate_inputs() {
    let ws = temp_workspace("flake-dup");
    let runs = ws.join(".fozzy").join("runs");
    std::fs::create_dir_all(&runs).expect("mkdir");

    let mk_report = |id: &str, status: &str| {
        let dir = runs.join(id);
        std::fs::create_dir_all(&dir).expect("run dir");
        let body = format!(
            r#"{{
  "status":"{status}",
  "mode":"run",
  "identity":{{"runId":"{id}","seed":1}},
  "startedAt":"2026-01-01T00:00:00Z",
  "finishedAt":"2026-01-01T00:00:00Z",
  "durationMs":0
}}"#
        );
        std::fs::write(dir.join("report.json"), body).expect("write report");
    };
    mk_report("r1", "pass");
    mk_report("r2", "fail");

    std::fs::write(ws.join("fozzy.toml"), "base_dir = \".fozzy\"\n").expect("write config");
    let cfg = ws.join("fozzy.toml").to_string_lossy().to_string();
    let cwd = ws.to_string_lossy().to_string();

    let out = run_cli(&[
        "report".into(),
        "flaky".into(),
        "r1".into(),
        "r1".into(),
        "r2".into(),
        "--flake-budget".into(),
        "10".into(),
        "--cwd".into(),
        cwd,
        "--config".into(),
        cfg,
    ]);
    assert_eq!(out.status.code(), Some(2), "duplicate runs should be rejected");
}
