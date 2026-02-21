use std::path::PathBuf;

use fozzy::{
    Config, ExitStatus, ExploreOptions, FsBackend, FuzzMode, FuzzOptions, FuzzTarget, HttpBackend,
    InitTemplate, InitTestType, ProcBackend, RecordCollisionPolicy, ReplayOptions, Reporter,
    RunOptions, ScenarioPath, ScheduleStrategy, ShrinkMinimize, ShrinkOptions, TracePath, explore,
    fuzz, init_project, replay_trace, run_scenario, shrink_trace,
};

fn temp_workspace(name: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!("fozzy-golden-{name}-{}", uuid::Uuid::new_v4()));
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

fn outcome_class(s: ExitStatus) -> &'static str {
    if s == ExitStatus::Pass {
        "pass"
    } else {
        "non_pass"
    }
}

#[test]
fn golden_run_record_replay_shrink_replay_min() {
    let ws = temp_workspace("run");
    let scenario = ws.join("fail.fozzy.json");
    std::fs::write(&scenario, fixture("fail.fozzy.json")).expect("write scenario");

    let cfg = Config {
        base_dir: ws.join(".fozzy"),
        reporter: Reporter::Json,
        proc_backend: ProcBackend::Scripted,
        fs_backend: FsBackend::Virtual,
        http_backend: HttpBackend::Scripted,
        mem_track: false,
        mem_limit_mb: None,
        mem_fail_after: None,
        fail_on_leak: false,
        leak_budget: None,
        mem_artifacts: false,
        mem_fragmentation_seed: None,
        mem_pressure_wave: None,
    };
    let trace = ws.join("run.trace.fozzy");
    let run = run_scenario(
        &cfg,
        ScenarioPath::new(scenario),
        &RunOptions {
            det: true,
            seed: Some(7),
            timeout: None,
            reporter: Reporter::Json,
            record_trace_to: Some(trace.clone()),
            filter: None,
            jobs: None,
            fail_fast: false,
            record_collision: RecordCollisionPolicy::Overwrite,
            proc_backend: ProcBackend::Scripted,
            fs_backend: FsBackend::Virtual,
            http_backend: HttpBackend::Scripted,
            memory: fozzy::MemoryOptions::default(),
        },
    )
    .expect("run");
    assert!(trace.exists(), "recorded trace missing");

    let replay = replay_trace(
        &cfg,
        TracePath::new(trace.clone()),
        &ReplayOptions {
            step: false,
            until: None,
            dump_events: false,
            reporter: Reporter::Json,
        },
    )
    .expect("replay");
    assert_eq!(
        outcome_class(run.summary.status),
        outcome_class(replay.summary.status)
    );

    let min = ws.join("run.min.fozzy");
    let shrunk = shrink_trace(
        &cfg,
        TracePath::new(trace),
        &ShrinkOptions {
            out_trace_path: Some(min.clone()),
            budget: None,
            aggressive: false,
            minimize: ShrinkMinimize::All,
        },
    )
    .expect("shrink");
    assert!(min.exists(), "minimized trace missing");

    let replay_min = replay_trace(
        &cfg,
        TracePath::new(min),
        &ReplayOptions {
            step: false,
            until: None,
            dump_events: false,
            reporter: Reporter::Json,
        },
    )
    .expect("replay min");
    assert_eq!(
        outcome_class(shrunk.result.summary.status),
        outcome_class(replay_min.summary.status)
    );
}

#[test]
fn golden_fuzz_record_replay_shrink_replay_min() {
    let ws = temp_workspace("fuzz");
    let cfg = Config {
        base_dir: ws.join(".fozzy"),
        reporter: Reporter::Json,
        proc_backend: ProcBackend::Scripted,
        fs_backend: FsBackend::Virtual,
        http_backend: HttpBackend::Scripted,
        mem_track: false,
        mem_limit_mb: None,
        mem_fail_after: None,
        fail_on_leak: false,
        leak_budget: None,
        mem_artifacts: false,
        mem_fragmentation_seed: None,
        mem_pressure_wave: None,
    };
    let trace = ws.join("fuzz.trace.fozzy");
    let target: FuzzTarget = "fn:utf8".parse().expect("target parse");

    let run = fuzz(
        &cfg,
        &target,
        &FuzzOptions {
            mode: FuzzMode::Coverage,
            seed: Some(7),
            time: None,
            runs: Some(1),
            max_input_bytes: 64,
            corpus_dir: None,
            mutator: None,
            shrink: false,
            record_trace_to: Some(trace.clone()),
            reporter: Reporter::Json,
            crash_only: false,
            minimize: false,
            record_collision: RecordCollisionPolicy::Overwrite,
            memory: fozzy::MemoryOptions::default(),
        },
    )
    .expect("fuzz run");
    assert!(trace.exists(), "recorded fuzz trace missing");

    let replay = replay_trace(
        &cfg,
        TracePath::new(trace.clone()),
        &ReplayOptions {
            step: false,
            until: None,
            dump_events: false,
            reporter: Reporter::Json,
        },
    )
    .expect("fuzz replay");
    assert_eq!(
        outcome_class(run.summary.status),
        outcome_class(replay.summary.status)
    );

    let min = ws.join("fuzz.min.fozzy");
    let shrunk = shrink_trace(
        &cfg,
        TracePath::new(trace),
        &ShrinkOptions {
            out_trace_path: Some(min.clone()),
            budget: None,
            aggressive: false,
            minimize: ShrinkMinimize::Input,
        },
    )
    .expect("fuzz shrink");
    assert!(min.exists(), "minimized fuzz trace missing");

    let replay_min = replay_trace(
        &cfg,
        TracePath::new(min),
        &ReplayOptions {
            step: false,
            until: None,
            dump_events: false,
            reporter: Reporter::Json,
        },
    )
    .expect("fuzz replay min");
    assert_eq!(
        outcome_class(shrunk.result.summary.status),
        outcome_class(replay_min.summary.status)
    );
}

#[test]
fn golden_explore_record_replay_shrink_replay_min() {
    let ws = temp_workspace("explore");
    let scenario = ws.join("kv.explore.fozzy.json");
    std::fs::write(&scenario, fixture("kv.explore.fozzy.json")).expect("write explore scenario");

    let cfg = Config {
        base_dir: ws.join(".fozzy"),
        reporter: Reporter::Json,
        proc_backend: ProcBackend::Scripted,
        fs_backend: FsBackend::Virtual,
        http_backend: HttpBackend::Scripted,
        mem_track: false,
        mem_limit_mb: None,
        mem_fail_after: None,
        fail_on_leak: false,
        leak_budget: None,
        mem_artifacts: false,
        mem_fragmentation_seed: None,
        mem_pressure_wave: None,
    };
    let trace = ws.join("explore.trace.fozzy");
    let run = explore(
        &cfg,
        ScenarioPath::new(scenario),
        &ExploreOptions {
            seed: Some(7),
            time: None,
            steps: Some(12),
            nodes: None,
            faults: Some("none".to_string()),
            schedule: ScheduleStrategy::Fifo,
            checker: None,
            record_trace_to: Some(trace.clone()),
            shrink: false,
            minimize: false,
            reporter: Reporter::Json,
            record_collision: RecordCollisionPolicy::Overwrite,
            memory: fozzy::MemoryOptions::default(),
        },
    )
    .expect("explore run");
    assert!(trace.exists(), "recorded explore trace missing");

    let replay = replay_trace(
        &cfg,
        TracePath::new(trace.clone()),
        &ReplayOptions {
            step: false,
            until: None,
            dump_events: false,
            reporter: Reporter::Json,
        },
    )
    .expect("explore replay");
    assert_eq!(
        outcome_class(run.summary.status),
        outcome_class(replay.summary.status)
    );

    let min = ws.join("explore.min.fozzy");
    let shrunk = shrink_trace(
        &cfg,
        TracePath::new(trace),
        &ShrinkOptions {
            out_trace_path: Some(min.clone()),
            budget: None,
            aggressive: false,
            minimize: ShrinkMinimize::Schedule,
        },
    )
    .expect("explore shrink");
    assert!(min.exists(), "minimized explore trace missing");

    let replay_min = replay_trace(
        &cfg,
        TracePath::new(min),
        &ReplayOptions {
            step: false,
            until: None,
            dump_events: false,
            reporter: Reporter::Json,
        },
    )
    .expect("explore replay min");
    assert_eq!(
        outcome_class(shrunk.result.summary.status),
        outcome_class(replay_min.summary.status)
    );
}

#[test]
fn golden_init_scaffold_distributed_pass_succeeds_in_explore() {
    let ws = temp_workspace("init-explore");
    let prev = std::env::current_dir().expect("cwd");
    std::env::set_current_dir(&ws).expect("chdir");
    let cfg = Config::default();
    init_project(&cfg, &InitTemplate::Rust, true, &[InitTestType::Explore]).expect("init");
    let scenario = ws.join("tests/distributed.pass.fozzy.json");
    let run = explore(
        &cfg,
        ScenarioPath::new(scenario),
        &ExploreOptions {
            seed: Some(7),
            time: None,
            steps: Some(100),
            nodes: Some(3),
            faults: Some("none".to_string()),
            schedule: ScheduleStrategy::CoverageGuided,
            checker: None,
            record_trace_to: None,
            shrink: false,
            minimize: false,
            reporter: Reporter::Json,
            record_collision: RecordCollisionPolicy::Append,
            memory: fozzy::MemoryOptions::default(),
        },
    )
    .expect("explore run");
    std::env::set_current_dir(prev).expect("restore cwd");
    assert_eq!(run.summary.status, ExitStatus::Pass);
}
