use std::path::PathBuf;
use std::process::Command;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

fn temp_workspace(name: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!("fozzy-cli-{name}-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&root).expect("create temp workspace");
    root
}

fn fixture(name: &str) -> String {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let tests_path = root.join("tests").join(name);
    if tests_path.exists() {
        return std::fs::read_to_string(tests_path).expect("read fixture");
    }
    let fixtures_path = root.join("fixtures").join(name);
    std::fs::read_to_string(fixtures_path).expect("read fixture")
}

fn run_cli(args: &[String]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_fozzy"))
        .args(args)
        .output()
        .expect("run cli")
}

fn spawn_one_shot_http_server() -> (String, mpsc::Sender<()>) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind http listener");
    listener
        .set_nonblocking(true)
        .expect("set nonblocking listener");
    let addr = listener.local_addr().expect("local addr");
    let (stop_tx, stop_rx) = mpsc::channel::<()>();
    thread::spawn(move || {
        let start = std::time::Instant::now();
        loop {
            if stop_rx.try_recv().is_ok() || start.elapsed() > Duration::from_secs(10) {
                break;
            }
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let mut buf = [0u8; 1024];
                    let _ = std::io::Read::read(&mut stream, &mut buf);
                    let response =
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";
                    let _ = std::io::Write::write_all(&mut stream, response);
                    break;
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(_) => break,
            }
        }
    });
    (format!("http://{addr}/ping"), stop_tx)
}

fn spawn_header_http_server() -> (String, mpsc::Sender<()>) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind http listener");
    listener
        .set_nonblocking(true)
        .expect("set nonblocking listener");
    let addr = listener.local_addr().expect("local addr");
    let (stop_tx, stop_rx) = mpsc::channel::<()>();
    thread::spawn(move || {
        let start = std::time::Instant::now();
        loop {
            if stop_rx.try_recv().is_ok() || start.elapsed() > Duration::from_secs(10) {
                break;
            }
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let mut buf = [0u8; 4096];
                    let n = std::io::Read::read(&mut stream, &mut buf).unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]).to_string();
                    let has_auth = req
                        .lines()
                        .any(|line| line.eq_ignore_ascii_case("authorization: bearer demo-token"));
                    let (status, body) = if has_auth {
                        ("200 OK", "ok")
                    } else {
                        ("401 Unauthorized", "missing-auth")
                    };
                    let response = format!(
                        "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\nX-Trace-Id: abc-123\r\nX-Service: fozzy-test\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = std::io::Write::write_all(&mut stream, response.as_bytes());
                    break;
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(_) => break,
            }
        }
    });
    (format!("http://{addr}/headers"), stop_tx)
}

fn parse_json_stdout(output: &std::process::Output) -> serde_json::Value {
    let s = String::from_utf8_lossy(&output.stdout);
    serde_json::from_str(s.trim()).expect("stdout json")
}

fn full_step_status(doc: &serde_json::Value, name: &str) -> Option<String> {
    doc.get("steps")
        .and_then(|v| v.as_array())
        .and_then(|steps| {
            steps.iter().find_map(|step| {
                if step.get("name").and_then(|v| v.as_str()) == Some(name) {
                    step.get("status")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string())
                } else {
                    None
                }
            })
        })
}

fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &b in bytes {
        crc ^= b as u32;
        for _ in 0..8 {
            let lsb = crc & 1;
            crc >>= 1;
            if lsb != 0 {
                crc ^= 0xEDB8_8320;
            }
        }
    }
    !crc
}

fn build_zip_with_raw_entries(entries: &[(&[u8], &[u8])]) -> Vec<u8> {
    let mut out = Vec::<u8>::new();
    let mut central = Vec::<u8>::new();
    let mut offsets = Vec::<u32>::new();

    for (name, payload) in entries {
        let offset = out.len() as u32;
        offsets.push(offset);
        let crc = crc32(payload);
        let name_len = name.len() as u16;
        let size = payload.len() as u32;

        out.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
        out.extend_from_slice(&20u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&crc.to_le_bytes());
        out.extend_from_slice(&size.to_le_bytes());
        out.extend_from_slice(&size.to_le_bytes());
        out.extend_from_slice(&name_len.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(name);
        out.extend_from_slice(payload);
    }

    let cd_offset = out.len() as u32;
    for ((name, payload), offset) in entries.iter().zip(offsets.iter().copied()) {
        let crc = crc32(payload);
        let name_len = name.len() as u16;
        let size = payload.len() as u32;
        central.extend_from_slice(&0x0201_4b50u32.to_le_bytes());
        central.extend_from_slice(&20u16.to_le_bytes());
        central.extend_from_slice(&20u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&crc.to_le_bytes());
        central.extend_from_slice(&size.to_le_bytes());
        central.extend_from_slice(&size.to_le_bytes());
        central.extend_from_slice(&name_len.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u32.to_le_bytes());
        central.extend_from_slice(&offset.to_le_bytes());
        central.extend_from_slice(name);
    }
    let cd_size = central.len() as u32;
    out.extend_from_slice(&central);

    out.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
    out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
    out.extend_from_slice(&cd_size.to_le_bytes());
    out.extend_from_slice(&cd_offset.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out
}

#[test]
fn common_global_and_mode_flags_parse_across_run_like_commands() {
    let ws = temp_workspace("parity");
    std::fs::write(ws.join("fozzy.toml"), "base_dir = \".fozzy\"\n").expect("write config");
    std::fs::write(ws.join("example.fozzy.json"), fixture("example.fozzy.json"))
        .expect("write example");
    std::fs::write(
        ws.join("kv.explore.fozzy.json"),
        fixture("kv.explore.fozzy.json"),
    )
    .expect("write explore");

    let cfg = ws.join("fozzy.toml").to_string_lossy().to_string();
    let cwd = ws.to_string_lossy().to_string();
    let run_scenario = ws.join("example.fozzy.json").to_string_lossy().to_string();
    let explore_scenario = ws
        .join("kv.explore.fozzy.json")
        .to_string_lossy()
        .to_string();

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

    let ok = run_cli(&[
        "trace".into(),
        "verify".into(),
        trace_arg.clone(),
        "--json".into(),
        "--unsafe".into(),
    ]);
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
    assert_eq!(
        strict_verify.status.code(),
        Some(2),
        "strict trace verify should fail"
    );

    let strict_ci = run_cli(&["--strict".into(), "ci".into(), trace_arg, "--json".into()]);
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
    let doc: serde_json::Value = serde_json::from_str(stdout.trim()).expect("stdout json");
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

    let replay_bad_version = run_cli(&["replay".into(), bad_version_arg.clone(), "--json".into()]);
    assert_eq!(
        replay_bad_version.status.code(),
        Some(2),
        "replay must reject bad version in non-strict mode"
    );

    let ci_bad_version = run_cli(&["ci".into(), bad_version_arg, "--json".into()]);
    assert_eq!(
        ci_bad_version.status.code(),
        Some(2),
        "ci must reject bad version in non-strict mode"
    );
}

#[test]
fn json_mode_argument_errors_emit_json_for_parse_failures() {
    for args in [
        vec!["artifacts".into(), "export".into(), "--json".into()],
        vec!["ci".into(), "--json".into()],
        vec!["replay".into(), "--json".into()],
    ] {
        let out = run_cli(&args);
        assert_eq!(out.status.code(), Some(2), "parse error should exit 2");
        let doc = parse_json_stdout(&out);
        assert_eq!(doc.get("code").and_then(|v| v.as_str()), Some("error"));
        assert!(
            !doc.get("message")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .is_empty(),
            "error message should be present"
        );
    }
}

#[test]
fn artifacts_help_uses_run_or_trace_value_name() {
    for sub in ["pack", "export"] {
        let out = run_cli(&["artifacts".into(), sub.to_string(), "--help".into()]);
        assert_eq!(out.status.code(), Some(0), "help should exit 0");
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            stdout.contains("RUN_OR_TRACE"),
            "help should show RUN_OR_TRACE for artifacts {sub}; got: {stdout}"
        );
    }
}

#[test]
fn corpus_import_rejects_raw_duplicate_entries_in_strict_and_non_strict() {
    let ws = temp_workspace("corpus-dup-raw");
    let zip = ws.join("dup.zip");
    let out = ws.join("out");
    std::fs::create_dir_all(&out).expect("out");
    std::fs::write(
        &zip,
        build_zip_with_raw_entries(&[(b"same.txt", b"A"), (b"same.txt", b"B")]),
    )
    .expect("zip");

    for strict in [false, true] {
        let mut args = vec![
            "corpus".into(),
            "import".into(),
            zip.to_string_lossy().to_string(),
            "--out".into(),
            out.to_string_lossy().to_string(),
            "--json".into(),
        ];
        if strict {
            args.insert(0, "--strict".into());
        }
        let outp = run_cli(&args);
        assert_eq!(outp.status.code(), Some(2), "duplicate import must fail");
        let doc = parse_json_stdout(&outp);
        assert_eq!(doc.get("code").and_then(|v| v.as_str()), Some("error"));
        assert!(
            doc.get("message")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .contains("duplicate output file in archive is not allowed")
        );
    }
}

#[test]
fn corpus_import_rejects_raw_nul_collision_in_strict_and_non_strict() {
    let ws = temp_workspace("corpus-nul-raw");
    let zip = ws.join("nuldup.zip");
    let out = ws.join("out");
    std::fs::create_dir_all(&out).expect("out");
    std::fs::write(
        &zip,
        build_zip_with_raw_entries(&[(b"bad\0a.txt", b"A"), (b"bad", b"B")]),
    )
    .expect("zip");

    for strict in [false, true] {
        let mut args = vec![
            "corpus".into(),
            "import".into(),
            zip.to_string_lossy().to_string(),
            "--out".into(),
            out.to_string_lossy().to_string(),
            "--json".into(),
        ];
        if strict {
            args.insert(0, "--strict".into());
        }
        let outp = run_cli(&args);
        assert_eq!(
            outp.status.code(),
            Some(2),
            "nul collision import must fail"
        );
        let doc = parse_json_stdout(&outp);
        assert_eq!(doc.get("code").and_then(|v| v.as_str()), Some("error"));
        assert!(
            doc.get("message")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .contains("unsafe archive entry path rejected")
        );
    }
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
    assert_eq!(
        normal.status.code(),
        Some(2),
        "normal mode should reject misconfig"
    );

    let strict = run_cli(&[
        "--strict".into(),
        "ci".into(),
        trace_arg,
        "--flake-budget".into(),
        "5".into(),
        "--json".into(),
    ]);
    assert_eq!(
        strict.status.code(),
        Some(2),
        "strict mode should reject misconfig"
    );
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
    assert_eq!(
        out.status.code(),
        Some(2),
        "duplicate runs should be rejected"
    );
}

#[cfg(unix)]
#[test]
fn host_proc_backend_executes_real_proc_spawn_for_run() {
    let ws = temp_workspace("host-proc-run");
    let scenario = ws.join("host-proc.fozzy.json");
    let raw = r#"{
      "version":1,
      "name":"host-proc",
      "steps":[
        {"type":"proc_spawn","cmd":"/usr/bin/true","expect_exit":0}
      ]
    }"#;
    std::fs::write(&scenario, raw).expect("write scenario");

    let out = run_cli(&[
        "--proc-backend".into(),
        "host".into(),
        "run".into(),
        scenario.to_string_lossy().to_string(),
        "--json".into(),
    ]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "host proc run should pass, stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let doc = parse_json_stdout(&out);
    assert_eq!(doc.get("status").and_then(|v| v.as_str()), Some("pass"));
}

#[cfg(unix)]
#[test]
fn host_proc_backend_is_rejected_in_deterministic_mode() {
    let ws = temp_workspace("host-proc-det");
    let scenario = ws.join("host-proc-det.fozzy.json");
    let raw = r#"{
      "version":1,
      "name":"host-proc-det",
      "steps":[
        {"type":"proc_spawn","cmd":"/usr/bin/true","expect_exit":0}
      ]
    }"#;
    std::fs::write(&scenario, raw).expect("write scenario");

    let out = run_cli(&[
        "--proc-backend".into(),
        "host".into(),
        "run".into(),
        scenario.to_string_lossy().to_string(),
        "--det".into(),
        "--json".into(),
    ]);
    assert_eq!(out.status.code(), Some(2), "det + host proc should fail");
    let doc = parse_json_stdout(&out);
    assert_eq!(doc.get("code").and_then(|v| v.as_str()), Some("error"));
    assert!(
        doc.get("message")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .contains("host proc backend is not supported in deterministic mode")
    );
}

#[cfg(unix)]
#[test]
fn replay_uses_recorded_proc_decisions_from_host_backend_trace() {
    let ws = temp_workspace("host-proc-replay");
    let scenario = ws.join("host-proc-replay.fozzy.json");
    let trace = ws.join("host-proc-replay.fozzy");
    let raw = r#"{
      "version":1,
      "name":"host-proc-replay",
      "steps":[
        {"type":"proc_spawn","cmd":"/bin/echo","args":["hi"],"expect_exit":0,"expect_stdout":"hi\n"}
      ]
    }"#;
    std::fs::write(&scenario, raw).expect("write scenario");

    let run = run_cli(&[
        "--proc-backend".into(),
        "host".into(),
        "run".into(),
        scenario.to_string_lossy().to_string(),
        "--record".into(),
        trace.to_string_lossy().to_string(),
        "--json".into(),
    ]);
    assert_eq!(run.status.code(), Some(0), "host run should pass");

    let replay = run_cli(&[
        "replay".into(),
        trace.to_string_lossy().to_string(),
        "--json".into(),
    ]);
    assert_eq!(
        replay.status.code(),
        Some(0),
        "replay should pass from recorded proc decisions, stderr={}",
        String::from_utf8_lossy(&replay.stderr)
    );
    let doc = parse_json_stdout(&replay);
    assert_eq!(doc.get("status").and_then(|v| v.as_str()), Some("pass"));
}

#[test]
fn exit_code_matrix_core_contract() {
    let ws = temp_workspace("exit-matrix");
    let pass = ws.join("pass.fozzy.json");
    let fail = ws.join("fail.fozzy.json");
    std::fs::write(&pass, fixture("example.fozzy.json")).expect("write pass");
    std::fs::write(&fail, fixture("fail.fozzy.json")).expect("write fail");

    let pass_out = run_cli(&[
        "run".into(),
        pass.to_string_lossy().to_string(),
        "--json".into(),
    ]);
    assert_eq!(pass_out.status.code(), Some(0), "pass run must exit 0");

    let fail_out = run_cli(&[
        "run".into(),
        fail.to_string_lossy().to_string(),
        "--json".into(),
    ]);
    assert_eq!(fail_out.status.code(), Some(1), "failing run must exit 1");

    let parse_err = run_cli(&["run".into(), "--json".into()]);
    assert_eq!(
        parse_err.status.code(),
        Some(2),
        "usage/parse errors must exit 2"
    );
}

#[test]
fn concurrent_same_root_runs_are_stable() {
    let ws = temp_workspace("concurrent-root");
    let scenario = ws.join("scenario.fozzy.json");
    std::fs::write(&scenario, fixture("example.fozzy.json")).expect("write scenario");
    std::fs::write(ws.join("fozzy.toml"), "base_dir = \".fozzy\"\n").expect("write config");

    let mut handles = Vec::new();
    for _ in 0..8 {
        let scenario = scenario.clone();
        let ws = ws.clone();
        handles.push(thread::spawn(move || {
            run_cli(&[
                "run".into(),
                scenario.to_string_lossy().to_string(),
                "--cwd".into(),
                ws.to_string_lossy().to_string(),
                "--json".into(),
            ])
        }));
    }

    for h in handles {
        let out = h.join().expect("thread join");
        assert_eq!(
            out.status.code(),
            Some(0),
            "concurrent run failed: stderr={}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

#[test]
fn host_fs_backend_executes_real_filesystem_steps() {
    let ws = temp_workspace("host-fs");
    let scenario = ws.join("host-fs.fozzy.json");
    let raw = r#"{
      "version":1,
      "name":"host-fs",
      "steps":[
        {"type":"fs_write","path":"tmp/host-fs.txt","data":"hello"},
        {"type":"fs_read_assert","path":"tmp/host-fs.txt","equals":"hello"}
      ]
    }"#;
    std::fs::write(&scenario, raw).expect("write scenario");
    let out = run_cli(&[
        "--fs-backend".into(),
        "host".into(),
        "run".into(),
        scenario.to_string_lossy().to_string(),
        "--cwd".into(),
        ws.to_string_lossy().to_string(),
        "--json".into(),
    ]);
    assert_eq!(out.status.code(), Some(0), "host fs run should pass");
    let written =
        std::fs::read_to_string(ws.join("tmp").join("host-fs.txt")).expect("read host fs output");
    assert_eq!(written, "hello");
}

#[test]
fn host_fs_backend_rejects_path_escape() {
    let ws = temp_workspace("host-fs-escape");
    let scenario = ws.join("host-fs-escape.fozzy.json");
    let raw = r#"{
      "version":1,
      "name":"host-fs-escape",
      "steps":[
        {"type":"fs_write","path":"../escape.txt","data":"bad"}
      ]
    }"#;
    std::fs::write(&scenario, raw).expect("write scenario");
    let out = run_cli(&[
        "--fs-backend".into(),
        "host".into(),
        "run".into(),
        scenario.to_string_lossy().to_string(),
        "--cwd".into(),
        ws.to_string_lossy().to_string(),
        "--json".into(),
    ]);
    assert_eq!(
        out.status.code(),
        Some(1),
        "path escape must fail as assertion"
    );
}

#[test]
fn host_fs_backend_is_rejected_in_deterministic_mode() {
    let ws = temp_workspace("host-fs-det");
    let scenario = ws.join("host-fs-det.fozzy.json");
    let raw = r#"{
      "version":1,
      "name":"host-fs-det",
      "steps":[{"type":"fs_write","path":"x.txt","data":"x"}]
    }"#;
    std::fs::write(&scenario, raw).expect("write scenario");
    let out = run_cli(&[
        "--fs-backend".into(),
        "host".into(),
        "run".into(),
        scenario.to_string_lossy().to_string(),
        "--det".into(),
        "--json".into(),
    ]);
    assert_eq!(out.status.code(), Some(2), "det + host fs should fail");
}

#[test]
fn host_http_backend_executes_and_replays_from_decisions() {
    let (url, stop_tx) = spawn_one_shot_http_server();
    let ws = temp_workspace("host-http");
    let scenario = ws.join("host-http.fozzy.json");
    let trace = ws.join("host-http.fozzy");
    let raw = format!(
        r#"{{
      "version":1,
      "name":"host-http",
      "steps":[
        {{"type":"http_request","method":"GET","path":"{url}","expect_status":200,"expect_body":"ok"}}
      ]
    }}"#
    );
    std::fs::write(&scenario, raw).expect("write scenario");
    let run = run_cli(&[
        "--http-backend".into(),
        "host".into(),
        "run".into(),
        scenario.to_string_lossy().to_string(),
        "--record".into(),
        trace.to_string_lossy().to_string(),
        "--json".into(),
    ]);
    let _ = stop_tx.send(());
    assert_eq!(
        run.status.code(),
        Some(0),
        "host http run should pass: {}",
        String::from_utf8_lossy(&run.stderr)
    );

    let replay = run_cli(&[
        "replay".into(),
        trace.to_string_lossy().to_string(),
        "--json".into(),
    ]);
    assert_eq!(replay.status.code(), Some(0), "replay must pass");
}

#[test]
fn http_request_supports_headers_and_response_header_assertions() {
    let (url, stop_tx) = spawn_header_http_server();
    let ws = temp_workspace("host-http-headers");
    let scenario = ws.join("host-http-headers.fozzy.json");
    let raw = format!(
        r#"{{
      "version":1,
      "name":"host-http-headers",
      "steps":[
        {{
          "type":"http_request",
          "method":"GET",
          "path":"{url}",
          "headers":{{"Authorization":"Bearer demo-token"}},
          "expect_status":200,
          "expect_headers":{{"x-trace-id":"abc-123","x-service":"fozzy-test"}},
          "expect_body":"ok"
        }}
      ]
    }}"#
    );
    std::fs::write(&scenario, raw).expect("write scenario");
    let run = run_cli(&[
        "--http-backend".into(),
        "host".into(),
        "run".into(),
        scenario.to_string_lossy().to_string(),
        "--json".into(),
    ]);
    let _ = stop_tx.send(());
    assert_eq!(
        run.status.code(),
        Some(0),
        "header request/assertions should pass: {}",
        String::from_utf8_lossy(&run.stderr)
    );
}

#[test]
fn host_http_backend_is_rejected_in_deterministic_mode() {
    let ws = temp_workspace("host-http-det");
    let scenario = ws.join("host-http-det.fozzy.json");
    let raw = r#"{
      "version":1,
      "name":"host-http-det",
      "steps":[{"type":"http_request","method":"GET","path":"http://127.0.0.1:1/x","expect_status":200}]
    }"#;
    std::fs::write(&scenario, raw).expect("write scenario");
    let out = run_cli(&[
        "--http-backend".into(),
        "host".into(),
        "run".into(),
        scenario.to_string_lossy().to_string(),
        "--det".into(),
        "--json".into(),
    ]);
    assert_eq!(out.status.code(), Some(2), "det + host http should fail");
}

#[test]
fn host_http_backend_accepts_https_scheme() {
    let ws = temp_workspace("host-http-https");
    let scenario = ws.join("host-http-https.fozzy.json");
    let raw = r#"{
      "version":1,
      "name":"host-http-https",
      "steps":[{"type":"http_request","method":"GET","path":"https://127.0.0.1:1/x","expect_status":200}]
    }"#;
    std::fs::write(&scenario, raw).expect("write scenario");
    let out = run_cli(&[
        "--http-backend".into(),
        "host".into(),
        "run".into(),
        scenario.to_string_lossy().to_string(),
        "--json".into(),
    ]);
    assert_eq!(
        out.status.code(),
        Some(1),
        "request should fail at network/tls layer"
    );
    let doc = parse_json_stdout(&out);
    let msg = doc
        .get("message")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    assert!(
        !msg.contains("https is not supported"),
        "https must be supported by host backend, got: {msg}"
    );
}

#[test]
fn scripted_http_when_supports_response_headers_assertions() {
    let ws = temp_workspace("scripted-http-headers");
    let scenario = ws.join("scripted-http-headers.fozzy.json");
    let raw = r#"{
      "version":1,
      "name":"scripted-http-headers",
      "steps":[
        {"type":"http_when","method":"GET","path":"/ping","status":200,"headers":{"x-test":"yes","content-type":"text/plain"},"body":"ok"},
        {"type":"http_request","method":"GET","path":"/ping","expect_status":200,"expect_headers":{"x-test":"yes","content-type":"text/plain"},"expect_body":"ok"}
      ]
    }"#;
    std::fs::write(&scenario, raw).expect("write scenario");
    let out = run_cli(&[
        "run".into(),
        scenario.to_string_lossy().to_string(),
        "--det".into(),
        "--json".into(),
    ]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "scripted response headers should assert: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn host_http_when_supports_absolute_url_rules() {
    let (url, stop_tx) = spawn_one_shot_http_server();
    let ws = temp_workspace("host-http-when-absolute");
    let scenario = ws.join("host-http-when-absolute.fozzy.json");
    let raw = format!(
        r#"{{
      "version":1,
      "name":"host-http-when-absolute",
      "steps":[
        {{"type":"http_when","method":"GET","path":"{url}","status":200,"body":"ok"}},
        {{"type":"http_request","method":"GET","path":"{url}"}}
      ]
    }}"#
    );
    std::fs::write(&scenario, raw).expect("write scenario");
    let run = run_cli(&[
        "--http-backend".into(),
        "host".into(),
        "run".into(),
        scenario.to_string_lossy().to_string(),
        "--json".into(),
    ]);
    let _ = stop_tx.send(());
    assert_eq!(
        run.status.code(),
        Some(0),
        "host http_when absolute rule should pass: {}",
        String::from_utf8_lossy(&run.stderr)
    );
}

#[test]
fn host_http_when_supports_relative_path_rules() {
    let (url, stop_tx) = spawn_one_shot_http_server();
    let ws = temp_workspace("host-http-when-relative");
    let scenario = ws.join("host-http-when-relative.fozzy.json");
    let raw = format!(
        r#"{{
      "version":1,
      "name":"host-http-when-relative",
      "steps":[
        {{"type":"http_when","method":"GET","path":"/ping","status":200,"body":"ok"}},
        {{"type":"http_request","method":"GET","path":"{url}"}}
      ]
    }}"#
    );
    std::fs::write(&scenario, raw).expect("write scenario");
    let run = run_cli(&[
        "--http-backend".into(),
        "host".into(),
        "run".into(),
        scenario.to_string_lossy().to_string(),
        "--json".into(),
    ]);
    let _ = stop_tx.send(());
    assert_eq!(
        run.status.code(),
        Some(0),
        "host http_when relative rule should pass: {}",
        String::from_utf8_lossy(&run.stderr)
    );
}

#[test]
fn host_http_when_unmatched_includes_remediation_guidance() {
    let (url, stop_tx) = spawn_one_shot_http_server();
    let ws = temp_workspace("host-http-when-unmatched");
    let scenario = ws.join("host-http-when-unmatched.fozzy.json");
    let raw = format!(
        r#"{{
      "version":1,
      "name":"host-http-when-unmatched",
      "steps":[
        {{"type":"http_when","method":"GET","path":"/wrong","status":200,"body":"ok"}},
        {{"type":"http_request","method":"GET","path":"{url}"}}
      ]
    }}"#
    );
    std::fs::write(&scenario, raw).expect("write scenario");
    let run = run_cli(&[
        "--http-backend".into(),
        "host".into(),
        "run".into(),
        scenario.to_string_lossy().to_string(),
        "--json".into(),
    ]);
    let _ = stop_tx.send(());
    assert_eq!(run.status.code(), Some(1), "host rule mismatch should fail");
    let doc = parse_json_stdout(&run);
    let msg = doc
        .get("findings")
        .and_then(|v| v.as_array())
        .and_then(|arr| arr.first())
        .and_then(|finding| finding.get("message"))
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    assert!(
        msg.contains("--http-backend scripted"),
        "expected remediation guidance in message, got: {msg}"
    );
}

#[test]
fn full_allow_expected_failures_controls_shrink_status_for_fail_class_runs() {
    let ws = temp_workspace("full-allow-expected-failures");
    let scenario_root = ws.join("tests");
    std::fs::create_dir_all(&scenario_root).expect("create tests dir");
    std::fs::write(
        scenario_root.join("intentional-fail.fozzy.json"),
        r#"{
          "version":1,
          "name":"intentional-fail",
          "steps":[
            {"type":"trace_event","name":"start"},
            {"type":"fail","message":"expected failure"}
          ]
        }"#,
    )
    .expect("write fail scenario");

    let mut common = vec![
        "full".to_string(),
        "--scenario-root".to_string(),
        scenario_root.to_string_lossy().to_string(),
        "--seed".to_string(),
        "7".to_string(),
        "--doctor-runs".to_string(),
        "2".to_string(),
        "--fuzz-time".to_string(),
        "10ms".to_string(),
        "--required-steps".to_string(),
        "run_record_trace,replay,ci,shrink".to_string(),
        "--json".to_string(),
    ];

    let no_allow = run_cli(&common);
    assert_eq!(
        no_allow.status.code(),
        Some(1),
        "full should fail without --allow-expected-failures: {}",
        String::from_utf8_lossy(&no_allow.stderr)
    );
    let no_allow_doc = parse_json_stdout(&no_allow);
    assert_eq!(
        full_step_status(&no_allow_doc, "run_record_trace"),
        Some("passed".to_string())
    );
    assert_eq!(
        full_step_status(&no_allow_doc, "replay"),
        Some("passed".to_string())
    );
    assert_eq!(
        full_step_status(&no_allow_doc, "ci"),
        Some("passed".to_string())
    );
    assert_eq!(
        full_step_status(&no_allow_doc, "shrink"),
        Some("failed".to_string())
    );
    assert_eq!(
        no_allow_doc
            .get("shrinkClassification")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        Some("policy_rejected_non_pass".to_string())
    );

    common.insert(1, "--allow-expected-failures".to_string());
    let allow = run_cli(&common);
    assert_eq!(
        allow.status.code(),
        Some(0),
        "full should pass with --allow-expected-failures: {}",
        String::from_utf8_lossy(&allow.stderr)
    );
    let allow_doc = parse_json_stdout(&allow);
    assert_eq!(
        full_step_status(&allow_doc, "run_record_trace"),
        Some("passed".to_string())
    );
    assert_eq!(
        full_step_status(&allow_doc, "replay"),
        Some("passed".to_string())
    );
    assert_eq!(
        full_step_status(&allow_doc, "ci"),
        Some("passed".to_string())
    );
    assert_eq!(
        full_step_status(&allow_doc, "shrink"),
        Some("passed".to_string())
    );
    assert_eq!(
        allow_doc
            .get("shrinkClassification")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        Some("expected_fail_class_preserved".to_string())
    );
}

#[test]
fn steps_alias_matches_schema_output() {
    let schema = run_cli(&["schema".into(), "--json".into()]);
    assert_eq!(
        schema.status.code(),
        Some(0),
        "schema stderr={}",
        String::from_utf8_lossy(&schema.stderr)
    );
    let steps = run_cli(&["steps".into(), "--json".into()]);
    assert_eq!(
        steps.status.code(),
        Some(0),
        "steps alias stderr={}",
        String::from_utf8_lossy(&steps.stderr)
    );
    assert_eq!(parse_json_stdout(&schema), parse_json_stdout(&steps));
}

#[test]
fn validate_returns_non_zero_with_actionable_parse_diagnostics() {
    let ws = temp_workspace("validate-parse-error");
    let scenario = ws.join("broken.fozzy.json");
    std::fs::write(
        &scenario,
        r#"{
          "version":1,
          "name":"broken",
          "steps":[
            {"type":"memory_alloc","bytes":"not-a-number"}
          ]
        }"#,
    )
    .expect("write broken scenario");

    let out = run_cli(&[
        "validate".into(),
        scenario.to_string_lossy().to_string(),
        "--json".into(),
    ]);
    assert_eq!(
        out.status.code(),
        Some(2),
        "validate should fail for malformed step payload: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let doc = parse_json_stdout(&out);
    assert_eq!(doc.get("ok").and_then(|v| v.as_bool()), Some(false));
    let msg = doc
        .get("error")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    assert!(
        msg.contains("failed to parse scenario"),
        "expected parse context in validate error, got: {msg}"
    );
    assert!(
        msg.contains("fozzy schema --json"),
        "expected schema guidance in validate error, got: {msg}"
    );
}

#[test]
fn validate_accepts_distributed_scenarios() {
    let ws = temp_workspace("validate-distributed");
    let scenario = ws.join("distributed.fozzy.json");
    std::fs::write(
        &scenario,
        r#"{
          "version":1,
          "name":"dist-ok",
          "distributed":{
            "node_count":3,
            "steps":[
              {"type":"client_put","node":"n0","key":"k","value":"v"},
              {"type":"tick","duration":"10ms"}
            ],
            "invariants":[{"type":"kv_present_on_all","key":"k"}]
          }
        }"#,
    )
    .expect("write distributed scenario");
    let out = run_cli(&[
        "validate".into(),
        scenario.to_string_lossy().to_string(),
        "--json".into(),
    ]);
    assert_eq!(out.status.code(), Some(0));
    let doc = parse_json_stdout(&out);
    assert_eq!(doc.get("ok").and_then(|v| v.as_bool()), Some(true));
    assert_eq!(
        doc.get("variant").and_then(|v| v.as_str()),
        Some("distributed")
    );
}

#[test]
fn run_record_collision_defaults_to_append_for_iterative_runs() {
    let ws = temp_workspace("run-record-append");
    let scenario = ws.join("pass.fozzy.json");
    std::fs::write(&scenario, fixture("example.fozzy.json")).expect("write scenario");
    let record = ws.join("trace.fozzy");
    let args = vec![
        "run".to_string(),
        scenario.to_string_lossy().to_string(),
        "--record".to_string(),
        record.to_string_lossy().to_string(),
        "--json".to_string(),
    ];
    let first = run_cli(&args);
    assert_eq!(first.status.code(), Some(0));
    let second = run_cli(&args);
    assert_eq!(
        second.status.code(),
        Some(0),
        "second run should append by default, stderr={}",
        String::from_utf8_lossy(&second.stderr)
    );
}

#[test]
fn fuzz_supports_scenario_target() {
    let ws = temp_workspace("fuzz-scenario-target");
    let scenario = ws.join("app.pass.fozzy.json");
    std::fs::write(&scenario, fixture("example.fozzy.json")).expect("write scenario");
    let out = run_cli(&[
        "fuzz".into(),
        format!("scenario:{}", scenario.display()),
        "--runs".into(),
        "1".into(),
        "--json".into(),
    ]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "fuzz scenario target should run, stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let doc = parse_json_stdout(&out);
    assert_eq!(doc.get("mode").and_then(|v| v.as_str()), Some("fuzz"));
}

#[test]
fn full_flags_conflict_with_required_steps_surfaces_policy_conflict() {
    let ws = temp_workspace("full-policy-conflict");
    let tests_dir = ws.join("tests");
    std::fs::create_dir_all(&tests_dir).expect("mkdir tests");
    std::fs::write(
        tests_dir.join("app.pass.fozzy.json"),
        fixture("example.fozzy.json"),
    )
    .expect("write scenario");
    let out = run_cli(&[
        "--cwd".into(),
        ws.to_string_lossy().to_string(),
        "full".into(),
        "--scenario-root".into(),
        "tests".into(),
        "--required-steps".into(),
        "usage,version,test_det".into(),
        "--require-topology-coverage".into(),
        ".".into(),
        "--json".into(),
    ]);
    assert_eq!(out.status.code(), Some(1));
    let doc = parse_json_stdout(&out);
    assert_eq!(
        full_step_status(&doc, "policy_conflict"),
        Some("failed".to_string())
    );
}

#[test]
fn map_hotspots_services_and_suites_emit_expected_schema() {
    let ws = temp_workspace("map-schema");
    let services_dir = ws.join("services").join("payments");
    let tests_dir = ws.join("tests");
    std::fs::create_dir_all(&services_dir).expect("services dir");
    std::fs::create_dir_all(&tests_dir).expect("tests dir");
    std::fs::write(
        services_dir.join("handler.rs"),
        r#"
        async fn handle_payment() {
            if retry { tokio::spawn(async move {}); }
            let _ = std::fs::read("config.toml");
            if timeout { panic!("failed"); }
        }
        "#,
    )
    .expect("write source");
    std::fs::write(
        tests_dir.join("handler.fozzy.json"),
        r#"{"version":1,"name":"handler","steps":[{"type":"trace_event","name":"x"}]}"#,
    )
    .expect("write scenario");

    let root = ws.to_string_lossy().to_string();
    let scenario_root = tests_dir.to_string_lossy().to_string();

    let hotspots = run_cli(&[
        "map".into(),
        "hotspots".into(),
        "--root".into(),
        root.clone(),
        "--min-risk".into(),
        "1".into(),
        "--limit".into(),
        "20".into(),
        "--json".into(),
    ]);
    assert_eq!(
        hotspots.status.code(),
        Some(0),
        "map hotspots stderr={}",
        String::from_utf8_lossy(&hotspots.stderr)
    );
    let hotspots_doc = parse_json_stdout(&hotspots);
    assert_eq!(
        hotspots_doc
            .get("schemaVersion")
            .and_then(|v| v.as_str())
            .unwrap_or_default(),
        "fozzy.map_hotspots.v2"
    );
    assert!(
        hotspots_doc
            .get("hotspots")
            .and_then(|v| v.as_array())
            .is_some_and(|v| !v.is_empty())
    );

    let services = run_cli(&[
        "map".into(),
        "services".into(),
        "--root".into(),
        root.clone(),
        "--json".into(),
    ]);
    assert_eq!(
        services.status.code(),
        Some(0),
        "map services stderr={}",
        String::from_utf8_lossy(&services.stderr)
    );
    let services_doc = parse_json_stdout(&services);
    assert_eq!(
        services_doc
            .get("schemaVersion")
            .and_then(|v| v.as_str())
            .unwrap_or_default(),
        "fozzy.map_services.v2"
    );

    let suites = run_cli(&[
        "map".into(),
        "suites".into(),
        "--root".into(),
        root,
        "--scenario-root".into(),
        scenario_root,
        "--min-risk".into(),
        "1".into(),
        "--json".into(),
    ]);
    assert_eq!(
        suites.status.code(),
        Some(0),
        "map suites stderr={}",
        String::from_utf8_lossy(&suites.stderr)
    );
    let suites_doc = parse_json_stdout(&suites);
    assert_eq!(
        suites_doc
            .get("schemaVersion")
            .and_then(|v| v.as_str())
            .unwrap_or_default(),
        "fozzy.map_suites.v4"
    );
    assert!(
        suites_doc
            .get("suites")
            .and_then(|v| v.as_array())
            .and_then(|arr| arr.first())
            .and_then(|s| s.get("coverageEvidence"))
            .is_some(),
        "map suites should emit explainable coverage evidence"
    );
    assert_eq!(
        suites_doc
            .get("profile")
            .and_then(|v| v.as_str())
            .unwrap_or_default(),
        "pedantic"
    );
    assert_eq!(
        suites_doc
            .get("shrinkPolicy")
            .and_then(|v| v.as_str())
            .unwrap_or_default(),
        "no_known_failures"
    );
    assert!(
        suites_doc
            .get("requiredHotspotCount")
            .and_then(|v| v.as_u64())
            .unwrap_or(0)
            >= suites_doc
                .get("coveredHotspotCount")
                .and_then(|v| v.as_u64())
                .unwrap_or(0)
    );
}

#[test]
fn gate_targeted_profile_runs_scoped_strict_bundle() {
    let ws = temp_workspace("gate-targeted");
    let tests_dir = ws.join("tests");
    std::fs::create_dir_all(&tests_dir).expect("mkdir tests");
    std::fs::write(
        tests_dir.join("gateway.pass.fozzy.json"),
        br#"{
  "version": 1,
  "name": "gateway-pass",
  "steps": [
    { "type": "assert_eq_int", "a": 1, "b": 1 }
  ]
}"#,
    )
    .expect("write gateway scenario");
    std::fs::write(
        tests_dir.join("other.pass.fozzy.json"),
        br#"{
  "version": 1,
  "name": "other-pass",
  "steps": [
    { "type": "assert_eq_int", "a": 2, "b": 2 }
  ]
}"#,
    )
    .expect("write other scenario");

    let out = Command::new(env!("CARGO_BIN_EXE_fozzy"))
        .args([
            "--cwd",
            ws.to_str().expect("ws str"),
            "gate",
            "--profile",
            "targeted",
            "--scenario-root",
            tests_dir.to_str().expect("tests str"),
            "--scope",
            "gateway",
            "--seed",
            "1337",
            "--doctor-runs",
            "2",
            "--json",
        ])
        .output()
        .expect("run gate");
    assert_eq!(
        out.status.code(),
        Some(0),
        "gate stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let doc = parse_json_stdout(&out);
    assert_eq!(
        doc.get("schemaVersion")
            .and_then(|v| v.as_str())
            .unwrap_or_default(),
        "fozzy.gate_report.v1"
    );
    assert_eq!(
        doc.get("profile")
            .and_then(|v| v.as_str())
            .unwrap_or_default(),
        "targeted"
    );
    assert_eq!(
        doc.get("matchedScenarios")
            .and_then(|v| v.as_array())
            .map(|v| v.len())
            .unwrap_or_default(),
        1
    );
}
