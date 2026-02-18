use std::path::PathBuf;

use fozzy::{
    explore, fuzz, replay_trace, run_scenario, shrink_trace, Config, ExploreOptions, ExitStatus, FuzzMode,
    FuzzOptions, FuzzTarget, RecordCollisionPolicy, ReplayOptions, Reporter, RunOptions, ScenarioPath, ScheduleStrategy,
    ShrinkMinimize, ShrinkOptions, TracePath,
};

fn temp_workspace(name: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!("fozzy-golden-{name}-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&root).expect("create temp workspace");
    root
}

fn fixture(name: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests").join(name);
    std::fs::read_to_string(path).expect("read fixture")
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
    assert_eq!(outcome_class(run.summary.status), outcome_class(replay.summary.status));

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
    assert_eq!(outcome_class(run.summary.status), outcome_class(replay.summary.status));

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
    assert_eq!(outcome_class(run.summary.status), outcome_class(replay.summary.status));

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
