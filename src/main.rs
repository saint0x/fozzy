//! Fozzy CLI entrypoint.

mod cli_logger;

use clap::{Parser, Subcommand, error::ErrorKind};
use tracing_subscriber::EnvFilter;

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use walkdir::WalkDir;

use cli_logger::CliLogger;
use fozzy::{
    ArtifactCommand, CiOptions, Config, CorpusCommand, ExitStatus, ExploreOptions, FlakeBudget,
    FozzyDuration, FsBackend, FuzzMode, FuzzOptions, FuzzTarget, HttpBackend, InitTemplate,
    InitTestType, MapCommand, MapSuitesOptions, MemoryCommand, MemoryOptions, ProcBackend,
    RecordCollisionPolicy, ReportCommand, Reporter, RunOptions, RunSummary, ScenarioPath,
    ScheduleStrategy, ShrinkMinimize, TopologyProfile, TracePath,
};

#[derive(Debug, Parser)]
#[command(name = "fozzy")]
#[command(about = "deterministic full-stack testing + fuzzing + distributed exploration")]
#[command(
    after_help = "Start with `fozzy map suites --root . --scenario-root tests --profile pedantic --json` and follow suite gaps in full. Execution policy: use the full command surface by default (map/run/test/fuzz/explore/replay/shrink/trace verify/ci/report/artifacts/memory/doctor/corpus/env/version/usage). Use `fozzy full` to run the end-to-end gate automatically; use `--unsafe` only when intentionally relaxing checks."
)]
struct Cli {
    /// Path to config file. Missing configs are treated as "defaults".
    #[arg(long, global = true, default_value = "fozzy.toml")]
    config: PathBuf,

    /// Working directory for execution.
    #[arg(long, global = true)]
    cwd: Option<PathBuf>,

    /// Log level.
    #[arg(long, global = true, default_value = "info")]
    log: String,

    /// Machine-readable output to stdout (JSON).
    #[arg(long, global = true)]
    json: bool,

    /// Disable color output.
    #[arg(long, global = true)]
    no_color: bool,

    /// Treat warning-like conditions as errors (non-zero exit). Enabled by default.
    #[arg(long, global = true, default_value_t = true)]
    strict: bool,

    /// Opt out of strict mode and allow potentially unsafe relaxed checks.
    #[arg(long = "unsafe", global = true)]
    unsafe_mode: bool,

    /// Proc backend for proc_spawn steps.
    #[arg(long, global = true)]
    proc_backend: Option<ProcBackend>,

    /// Filesystem backend for fs_* steps.
    #[arg(long, global = true)]
    fs_backend: Option<FsBackend>,

    /// HTTP backend for http_* steps.
    #[arg(long, global = true)]
    http_backend: Option<HttpBackend>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Initialize a fozzy project (config + scaffolding)
    Init {
        #[arg(long)]
        force: bool,

        #[arg(long)]
        template: Option<InitTemplate>,

        /// Scaffold test types (`run`, `fuzz`, `explore`, `memory`, `host`, `all`).
        #[arg(long = "with", value_enum, value_delimiter = ',')]
        with: Vec<InitTestType>,

        /// Explicitly scaffold all available test types.
        #[arg(long)]
        all_tests: bool,
    },

    /// Run regular tests (optionally deterministic)
    Test {
        /// Glob patterns for scenario files.
        globs: Vec<String>,

        /// Enable deterministic runtime (seeded RNG + virtual time + decision logging).
        #[arg(long)]
        det: bool,

        /// Seed to use in deterministic mode (or to make nondet runs reproducible).
        #[arg(long)]
        seed: Option<u64>,

        /// Number of parallel jobs (best-effort; determinism is preserved within a run).
        #[arg(long)]
        jobs: Option<usize>,

        /// Per-test timeout.
        #[arg(long)]
        timeout: Option<FozzyDuration>,

        /// Name filter expression (substring match; v1).
        #[arg(long)]
        filter: Option<String>,

        /// Reporter format.
        #[arg(long, default_value = "pretty")]
        reporter: Reporter,

        /// Record trace (.fozzy) to path.
        #[arg(long)]
        record: Option<PathBuf>,

        /// Behavior when --record target exists: error, overwrite, or append with numeric suffix.
        #[arg(long, default_value = "append")]
        record_collision: RecordCollisionPolicy,

        /// Stop on first failure.
        #[arg(long)]
        fail_fast: bool,

        /// Enable deterministic memory tracking capability.
        #[arg(long)]
        mem_track: bool,

        /// Deterministic memory ceiling in MB.
        #[arg(long)]
        mem_limit_mb: Option<u64>,

        /// Deterministic allocation failure after N allocations.
        #[arg(long)]
        mem_fail_after: Option<u64>,

        /// Deterministic fragmentation overhead seed.
        #[arg(long)]
        mem_fragmentation_seed: Option<u64>,

        /// Deterministic pressure wave pattern (for example \"1,2,4\").
        #[arg(long)]
        mem_pressure_wave: Option<String>,

        /// Fail run on any detected leak.
        #[arg(long)]
        fail_on_leak: bool,

        /// Leak budget in bytes.
        #[arg(long)]
        leak_budget: Option<u64>,

        /// Emit dedicated memory artifacts.
        #[arg(long)]
        mem_artifacts: bool,
    },

    /// Run a single scenario file (one-off)
    Run {
        scenario: PathBuf,

        #[arg(long)]
        det: bool,

        #[arg(long)]
        seed: Option<u64>,

        #[arg(long)]
        timeout: Option<FozzyDuration>,

        #[arg(long, default_value = "pretty")]
        reporter: Reporter,

        #[arg(long)]
        record: Option<PathBuf>,

        /// Behavior when --record target exists: error, overwrite, or append with numeric suffix.
        #[arg(long, default_value = "append")]
        record_collision: RecordCollisionPolicy,

        #[arg(long)]
        mem_track: bool,
        #[arg(long)]
        mem_limit_mb: Option<u64>,
        #[arg(long)]
        mem_fail_after: Option<u64>,
        #[arg(long)]
        mem_fragmentation_seed: Option<u64>,
        #[arg(long)]
        mem_pressure_wave: Option<String>,
        #[arg(long)]
        fail_on_leak: bool,
        #[arg(long)]
        leak_budget: Option<u64>,
        #[arg(long)]
        mem_artifacts: bool,
    },

    /// Coverage-guided or property-based fuzzing
    Fuzz {
        target: String,

        #[arg(long, default_value = "coverage")]
        mode: FuzzMode,

        #[arg(long)]
        seed: Option<u64>,

        #[arg(long)]
        time: Option<FozzyDuration>,

        #[arg(long)]
        runs: Option<u64>,

        #[arg(long, default_value_t = 4096)]
        max_input: usize,

        #[arg(long)]
        corpus: Option<PathBuf>,

        #[arg(long)]
        mutator: Option<String>,

        #[arg(long)]
        shrink: bool,

        #[arg(long)]
        record: Option<PathBuf>,

        #[arg(long, default_value = "pretty")]
        reporter: Reporter,

        #[arg(long)]
        crash_only: bool,

        #[arg(long)]
        minimize: bool,

        /// Behavior when --record target exists: error, overwrite, or append with numeric suffix.
        #[arg(long, default_value = "append")]
        record_collision: RecordCollisionPolicy,

        #[arg(long)]
        mem_track: bool,
        #[arg(long)]
        mem_limit_mb: Option<u64>,
        #[arg(long)]
        mem_fail_after: Option<u64>,
        #[arg(long)]
        mem_fragmentation_seed: Option<u64>,
        #[arg(long)]
        mem_pressure_wave: Option<String>,
        #[arg(long)]
        fail_on_leak: bool,
        #[arg(long)]
        leak_budget: Option<u64>,
        #[arg(long)]
        mem_artifacts: bool,
    },

    /// Deterministic distributed schedule + fault exploration
    Explore {
        scenario: PathBuf,

        #[arg(long)]
        seed: Option<u64>,

        #[arg(long)]
        time: Option<FozzyDuration>,

        #[arg(long)]
        steps: Option<u64>,

        #[arg(long)]
        nodes: Option<usize>,

        #[arg(long)]
        faults: Option<String>,

        #[arg(long, default_value = "fifo")]
        schedule: ScheduleStrategy,

        #[arg(long)]
        checker: Option<String>,

        #[arg(long)]
        record: Option<PathBuf>,

        #[arg(long)]
        shrink: bool,

        #[arg(long)]
        minimize: bool,

        #[arg(long, default_value = "pretty")]
        reporter: Reporter,

        /// Behavior when --record target exists: error, overwrite, or append with numeric suffix.
        #[arg(long, default_value = "error")]
        record_collision: RecordCollisionPolicy,

        #[arg(long)]
        mem_track: bool,
        #[arg(long)]
        mem_limit_mb: Option<u64>,
        #[arg(long)]
        mem_fail_after: Option<u64>,
        #[arg(long)]
        mem_fragmentation_seed: Option<u64>,
        #[arg(long)]
        mem_pressure_wave: Option<String>,
        #[arg(long)]
        fail_on_leak: bool,
        #[arg(long)]
        leak_budget: Option<u64>,
        #[arg(long)]
        mem_artifacts: bool,
    },

    /// Replay a previously recorded run exactly
    Replay {
        trace: PathBuf,

        #[arg(long)]
        step: bool,

        #[arg(long)]
        until: Option<FozzyDuration>,

        #[arg(long)]
        dump_events: bool,

        #[arg(long, default_value = "pretty")]
        reporter: Reporter,
    },

    /// Inspect and verify trace-file integrity/versioning
    Trace {
        #[command(subcommand)]
        command: TraceCommand,
    },

    /// Minimize a failing run (input + schedule + fault trace)
    Shrink {
        trace: PathBuf,

        #[arg(long)]
        out: Option<PathBuf>,

        #[arg(long)]
        budget: Option<FozzyDuration>,

        #[arg(long)]
        aggressive: bool,

        #[arg(long, default_value = "all")]
        minimize: ShrinkMinimize,

        /// Accepted for CLI parity with run/test/fuzz/explore (summary output still follows global --json/pretty).
        #[arg(long, default_value = "pretty")]
        reporter: Reporter,
    },

    /// Manage fuzz corpora
    Corpus {
        #[command(subcommand)]
        command: CorpusCommand,
    },

    /// Inspect/export artifacts (traces, timelines, diffs)
    Artifacts {
        #[command(subcommand)]
        command: ArtifactCommand,
    },

    /// Render / query run reports (JSON, JUnit, HTML)
    Report {
        #[command(subcommand)]
        command: ReportCommand,
    },

    /// Inspect memory artifacts and summaries
    Memory {
        #[command(subcommand)]
        command: MemoryCommand,
    },

    /// Analyze repository topology and hotspot candidates for granular Fozzy suites
    Map {
        #[command(subcommand)]
        command: MapCommand,
    },

    /// Diagnose nondeterminism + environment issues
    Doctor {
        #[arg(long)]
        deep: bool,

        /// Scenario path for deterministic repeated-run audit (used with --deep).
        #[arg(long)]
        scenario: Option<PathBuf>,

        /// Number of repeated deterministic runs for audit (minimum 2).
        #[arg(long, default_value_t = 3)]
        runs: u32,

        /// Fixed seed used by deterministic audit runs.
        #[arg(long)]
        seed: Option<u64>,
    },

    /// Print environment + capability backend info
    Env,

    /// Run canonical CI gate checks for reproducibility/integrity
    Ci {
        /// Trace path used as the anchor artifact for verify/replay/export checks.
        trace: PathBuf,
        /// Optional run ids/trace paths used for flake-rate budget checks.
        #[arg(long = "flake-run")]
        flake_runs: Vec<String>,
        /// Maximum allowed flake rate percentage.
        #[arg(long = "flake-budget")]
        flake_budget: Option<FlakeBudget>,
    },

    /// Run strict deterministic gate checks with optional scoped targeting.
    Gate {
        /// Gate profile.
        #[arg(long, default_value = "targeted")]
        profile: GateProfile,
        /// Root directory scanned for `*.fozzy.json` scenarios.
        #[arg(long, default_value = "tests")]
        scenario_root: PathBuf,
        /// Substring scope matcher applied to scenario paths (comma-separated).
        #[arg(long, value_delimiter = ',')]
        scope: Vec<String>,
        /// Deterministic seed for reproducible runs.
        #[arg(long)]
        seed: Option<u64>,
        /// Number of repeated deterministic runs in doctor deep audit.
        #[arg(long, default_value_t = 5)]
        doctor_runs: u32,
    },

    /// Print version and build info
    Version,

    /// Show a compact "what to use when" guide for each command, with examples.
    Usage,

    /// Print scenario/schema surface (file variants + step kinds) for automation.
    #[command(alias = "steps")]
    Schema,

    /// Validate a scenario file and emit parser/step-shape diagnostics.
    Validate { scenario: PathBuf },

    /// Run an end-to-end full-surface Fozzy gate with setup guidance and graceful skips.
    Full {
        /// Root directory scanned for `*.fozzy.json` scenarios.
        #[arg(long, default_value = "tests")]
        scenario_root: PathBuf,

        /// Deterministic seed for reproducible full runs.
        #[arg(long)]
        seed: Option<u64>,

        /// Number of repeated deterministic runs in doctor deep audit.
        #[arg(long, default_value_t = 5)]
        doctor_runs: u32,

        /// Fuzz duration used by `fozzy full`.
        #[arg(long, default_value = "2s")]
        fuzz_time: FozzyDuration,

        /// Explore step budget used for distributed scenarios.
        #[arg(long, default_value_t = 200)]
        explore_steps: u64,

        /// Explore node count override used for distributed scenarios.
        #[arg(long, default_value_t = 3)]
        explore_nodes: usize,

        /// Treat fail-class scenario outcomes as valid if replay/ci preserve the outcome class.
        #[arg(long)]
        allow_expected_failures: bool,

        /// Run only scenarios whose path contains this substring.
        #[arg(long)]
        scenario_filter: Option<String>,

        /// Skip specific full steps (comma-separated list).
        #[arg(long, value_delimiter = ',')]
        skip_steps: Vec<String>,

        /// If set, only these full steps are considered required (others are marked skipped).
        #[arg(long, value_delimiter = ',')]
        required_steps: Vec<String>,

        /// Require coverage for high-risk topology hotspots (pass repo root path to analyze).
        #[arg(long)]
        require_topology_coverage: Option<PathBuf>,

        /// Minimum hotspot risk score (0-100) considered required for topology coverage.
        #[arg(long, default_value_t = 60)]
        topology_min_risk: u8,

        /// Topology strictness profile used when checking coverage.
        #[arg(long, default_value = "pedantic")]
        topology_profile: TopologyProfile,
    },
}

#[derive(Debug, Subcommand)]
enum TraceCommand {
    /// Verify checksum/integrity and schema warnings for a .fozzy trace
    Verify { path: PathBuf },
}

#[derive(Debug, Clone, Copy, serde::Serialize)]
#[serde(rename_all = "snake_case")]
enum GateProfile {
    Targeted,
}

impl clap::ValueEnum for GateProfile {
    fn value_variants<'a>() -> &'a [Self] {
        &[Self::Targeted]
    }

    fn to_possible_value(&self) -> Option<clap::builder::PossibleValue> {
        Some(clap::builder::PossibleValue::new("targeted"))
    }
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "snake_case")]
enum FullStepStatus {
    Passed,
    Failed,
    Skipped,
}

#[derive(Debug, Clone, serde::Serialize)]
struct FullStepResult {
    name: String,
    status: FullStepStatus,
    detail: String,
}

#[derive(Debug, Clone, serde::Serialize)]
struct FullReport {
    #[serde(rename = "schemaVersion")]
    schema_version: String,
    strict: bool,
    unsafe_mode: bool,
    #[serde(rename = "scenarioRoot")]
    scenario_root: String,
    guidance: Vec<String>,
    #[serde(
        rename = "shrinkClassification",
        skip_serializing_if = "Option::is_none"
    )]
    shrink_classification: Option<String>,
    steps: Vec<FullStepResult>,
}

#[derive(Debug, Clone)]
struct FullScenarioDiscovery {
    steps: Vec<PathBuf>,
    distributed: Vec<PathBuf>,
    parse_errors: Vec<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
struct GateReport {
    #[serde(rename = "schemaVersion")]
    schema_version: String,
    profile: GateProfile,
    strict: bool,
    #[serde(rename = "scenarioRoot")]
    scenario_root: String,
    scopes: Vec<String>,
    #[serde(rename = "matchedScenarios")]
    matched_scenarios: Vec<String>,
    steps: Vec<FullStepResult>,
}

fn main() -> ExitCode {
    let normalized_args = normalize_global_args(std::env::args());
    let json_requested = args_request_json(&normalized_args);
    let cli = match Cli::try_parse_from(normalized_args) {
        Ok(cli) => cli,
        Err(err) => return print_clap_error_and_exit(json_requested, err),
    };
    let logger = CliLogger::new(cli.json, cli.no_color);

    if let Err(err) = init_tracing(&cli.log) {
        // Tracing is best-effort; if it fails, we still continue.
        logger.print_warning(&format!("failed to init tracing: {err:#}"));
    }

    let cwd = cli
        .cwd
        .clone()
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
    if let Err(err) = std::env::set_current_dir(&cwd) {
        return print_error_and_exit(
            &logger,
            anyhow::anyhow!(err).context(format!("failed to set cwd to {}", cwd.display())),
        );
    }

    let config = Config::load_optional(&cli.config);

    match run_command(&cli, &config, &logger) {
        Ok(code) => code,
        Err(err) => print_error_and_exit(&logger, err),
    }
}

fn args_request_json(args: &[String]) -> bool {
    args.iter().any(|a| a == "--json" || a == "--json=true")
}

fn normalize_global_args(args: impl IntoIterator<Item = String>) -> Vec<String> {
    let all: Vec<String> = args.into_iter().collect();
    if all.is_empty() {
        return all;
    }

    let mut globals = Vec::new();
    let mut rest = Vec::new();

    let mut i = 1usize;
    while i < all.len() {
        let arg = &all[i];
        match arg.as_str() {
            "--json" | "--no-color" | "--strict" | "--unsafe" => {
                globals.push(arg.clone());
                i += 1;
            }
            "--config" | "--cwd" | "--log" | "--proc-backend" | "--fs-backend"
            | "--http-backend" => {
                globals.push(arg.clone());
                if i + 1 < all.len() {
                    globals.push(all[i + 1].clone());
                    i += 2;
                } else {
                    i += 1;
                }
            }
            _ if arg.starts_with("--config=")
                || arg.starts_with("--cwd=")
                || arg.starts_with("--log=")
                || arg.starts_with("--proc-backend=")
                || arg.starts_with("--fs-backend=")
                || arg.starts_with("--http-backend=")
                || arg.starts_with("--strict=")
                || arg.starts_with("--unsafe=") =>
            {
                globals.push(arg.clone());
                i += 1;
            }
            _ => {
                rest.push(arg.clone());
                i += 1;
            }
        }
    }

    let mut normalized = Vec::with_capacity(all.len());
    normalized.push(all[0].clone());
    normalized.extend(globals);
    normalized.extend(rest);
    normalized
}

fn init_tracing(level: &str) -> anyhow::Result<()> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(level));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .init();
    Ok(())
}

fn run_command(cli: &Cli, config: &Config, logger: &CliLogger) -> anyhow::Result<ExitCode> {
    let proc_backend = cli.proc_backend.unwrap_or(config.proc_backend);
    let fs_backend = cli.fs_backend.unwrap_or(config.fs_backend);
    let http_backend = cli.http_backend.unwrap_or(config.http_backend);
    match &cli.command {
        Command::Init {
            force,
            template,
            with,
            all_tests,
        } => {
            let init_types = selected_init_test_types(with, *all_tests);
            fozzy::init_project(
                config,
                &InitTemplate::from_option(template.as_ref()),
                *force,
                &init_types,
            )?;
            Ok(ExitCode::SUCCESS)
        }

        Command::Test {
            globs,
            det,
            seed,
            jobs,
            timeout,
            filter,
            reporter,
            record,
            fail_fast,
            record_collision,
            mem_track,
            mem_limit_mb,
            mem_fail_after,
            mem_fragmentation_seed,
            mem_pressure_wave,
            fail_on_leak,
            leak_budget,
            mem_artifacts,
        } => {
            let _ = (*mem_track, *mem_artifacts);
            let memory = MemoryOptions {
                track: true,
                limit_mb: mem_limit_mb.or(config.mem_limit_mb),
                fail_after_allocs: mem_fail_after.or(config.mem_fail_after),
                fragmentation_seed: mem_fragmentation_seed.or(config.mem_fragmentation_seed),
                pressure_wave: mem_pressure_wave
                    .clone()
                    .or_else(|| config.mem_pressure_wave.clone()),
                fail_on_leak: *fail_on_leak || config.fail_on_leak,
                leak_budget_bytes: leak_budget.or(config.leak_budget),
                artifacts: true,
            };
            let run = fozzy::run_tests(
                config,
                globs,
                &RunOptions {
                    det: *det,
                    seed: *seed,
                    timeout: timeout.map(|d| d.0),
                    reporter: *reporter,
                    record_trace_to: record.clone(),
                    filter: filter.clone(),
                    jobs: *jobs,
                    fail_fast: *fail_fast,
                    record_collision: *record_collision,
                    proc_backend,
                    fs_backend,
                    http_backend,
                    memory,
                },
            )?;
            logger.print_run_summary(&run.summary)?;
            enforce_strict_run(cli, &run.summary)?;
            Ok(exit_code_for_status(run.summary.status))
        }

        Command::Run {
            scenario,
            det,
            seed,
            timeout,
            reporter,
            record,
            record_collision,
            mem_track,
            mem_limit_mb,
            mem_fail_after,
            mem_fragmentation_seed,
            mem_pressure_wave,
            fail_on_leak,
            leak_budget,
            mem_artifacts,
        } => {
            let _ = (*mem_track, *mem_artifacts);
            let memory = MemoryOptions {
                track: true,
                limit_mb: mem_limit_mb.or(config.mem_limit_mb),
                fail_after_allocs: mem_fail_after.or(config.mem_fail_after),
                fragmentation_seed: mem_fragmentation_seed.or(config.mem_fragmentation_seed),
                pressure_wave: mem_pressure_wave
                    .clone()
                    .or_else(|| config.mem_pressure_wave.clone()),
                fail_on_leak: *fail_on_leak || config.fail_on_leak,
                leak_budget_bytes: leak_budget.or(config.leak_budget),
                artifacts: true,
            };
            let run = fozzy::run_scenario(
                config,
                ScenarioPath::new(scenario.clone()),
                &RunOptions {
                    det: *det,
                    seed: *seed,
                    timeout: timeout.map(|d| d.0),
                    reporter: *reporter,
                    record_trace_to: record.clone(),
                    filter: None,
                    jobs: None,
                    fail_fast: false,
                    record_collision: *record_collision,
                    proc_backend,
                    fs_backend,
                    http_backend,
                    memory,
                },
            )?;
            logger.print_run_summary(&run.summary)?;
            enforce_strict_run(cli, &run.summary)?;
            Ok(exit_code_for_status(run.summary.status))
        }

        Command::Fuzz {
            target,
            mode,
            seed,
            time,
            runs,
            max_input,
            corpus,
            mutator,
            shrink,
            record,
            reporter,
            crash_only,
            minimize,
            record_collision,
            mem_track,
            mem_limit_mb,
            mem_fail_after,
            mem_fragmentation_seed,
            mem_pressure_wave,
            fail_on_leak,
            leak_budget,
            mem_artifacts,
        } => {
            let _ = (*mem_track, *mem_artifacts);
            let memory = MemoryOptions {
                track: true,
                limit_mb: mem_limit_mb.or(config.mem_limit_mb),
                fail_after_allocs: mem_fail_after.or(config.mem_fail_after),
                fragmentation_seed: mem_fragmentation_seed.or(config.mem_fragmentation_seed),
                pressure_wave: mem_pressure_wave
                    .clone()
                    .or_else(|| config.mem_pressure_wave.clone()),
                fail_on_leak: *fail_on_leak || config.fail_on_leak,
                leak_budget_bytes: leak_budget.or(config.leak_budget),
                artifacts: true,
            };
            let target: FuzzTarget = target.parse()?;
            let run = fozzy::fuzz(
                config,
                &target,
                &FuzzOptions {
                    mode: *mode,
                    seed: *seed,
                    time: time.map(|d| d.0),
                    runs: *runs,
                    max_input_bytes: *max_input,
                    corpus_dir: corpus.clone(),
                    mutator: mutator.clone(),
                    shrink: *shrink,
                    record_trace_to: record.clone(),
                    reporter: *reporter,
                    crash_only: *crash_only,
                    minimize: *minimize,
                    record_collision: *record_collision,
                    memory,
                },
            )?;
            logger.print_run_summary(&run.summary)?;
            enforce_strict_run(cli, &run.summary)?;
            Ok(exit_code_for_status(run.summary.status))
        }

        Command::Explore {
            scenario,
            seed,
            time,
            steps,
            nodes,
            faults,
            schedule,
            checker,
            record,
            shrink,
            minimize,
            reporter,
            record_collision,
            mem_track,
            mem_limit_mb,
            mem_fail_after,
            mem_fragmentation_seed,
            mem_pressure_wave,
            fail_on_leak,
            leak_budget,
            mem_artifacts,
        } => {
            let _ = (*mem_track, *mem_artifacts);
            let memory = MemoryOptions {
                track: true,
                limit_mb: mem_limit_mb.or(config.mem_limit_mb),
                fail_after_allocs: mem_fail_after.or(config.mem_fail_after),
                fragmentation_seed: mem_fragmentation_seed.or(config.mem_fragmentation_seed),
                pressure_wave: mem_pressure_wave
                    .clone()
                    .or_else(|| config.mem_pressure_wave.clone()),
                fail_on_leak: *fail_on_leak || config.fail_on_leak,
                leak_budget_bytes: leak_budget.or(config.leak_budget),
                artifacts: true,
            };
            let run = fozzy::explore(
                config,
                ScenarioPath::new(scenario.clone()),
                &ExploreOptions {
                    seed: *seed,
                    time: time.map(|d| d.0),
                    steps: *steps,
                    nodes: *nodes,
                    faults: faults.clone(),
                    schedule: *schedule,
                    checker: checker.clone(),
                    record_trace_to: record.clone(),
                    shrink: *shrink,
                    minimize: *minimize,
                    reporter: *reporter,
                    record_collision: *record_collision,
                    memory,
                },
            )?;
            logger.print_run_summary(&run.summary)?;
            enforce_strict_run(cli, &run.summary)?;
            Ok(exit_code_for_status(run.summary.status))
        }

        Command::Replay {
            trace,
            step,
            until,
            dump_events,
            reporter,
        } => {
            let run = fozzy::replay_trace(
                config,
                TracePath::new(trace.clone()),
                &fozzy::ReplayOptions {
                    step: *step,
                    until: until.map(|d| d.0),
                    dump_events: *dump_events,
                    reporter: *reporter,
                },
            )?;
            logger.print_run_summary(&run.summary)?;
            enforce_strict_run(cli, &run.summary)?;
            Ok(exit_code_for_status(run.summary.status))
        }

        Command::Trace { command } => {
            match command {
                TraceCommand::Verify { path } => {
                    let out = fozzy::verify_trace_file(path)?;
                    if strict_enabled(cli)
                        && (!out.checksum_present
                            || !out.checksum_valid
                            || !out.warnings.is_empty())
                    {
                        let mut reasons = Vec::new();
                        if !out.checksum_present {
                            reasons.push("checksum missing".to_string());
                        }
                        if !out.checksum_valid {
                            reasons.push("checksum invalid".to_string());
                        }
                        if !out.warnings.is_empty() {
                            reasons.push(format!("warnings: {}", out.warnings.join("; ")));
                        }
                        return Err(anyhow::anyhow!(
                            "strict mode: trace verify failed integrity policy ({})",
                            reasons.join(", ")
                        ));
                    }
                    logger.print_serialized(&out)?;
                }
            }
            Ok(ExitCode::SUCCESS)
        }

        Command::Shrink {
            trace,
            out,
            budget,
            aggressive,
            minimize,
            reporter: _reporter,
        } => {
            let result = fozzy::shrink_trace(
                config,
                TracePath::new(trace.clone()),
                &fozzy::ShrinkOptions {
                    out_trace_path: out.clone(),
                    budget: budget.map(|d| d.0),
                    aggressive: *aggressive,
                    minimize: *minimize,
                },
            )?;
            logger.print_run_summary(&result.result.summary)?;
            enforce_strict_run(cli, &result.result.summary)?;
            Ok(exit_code_for_status(result.result.summary.status))
        }

        Command::Corpus { command } => {
            let out = fozzy::corpus_command(config, command)?;
            logger.print_serialized(&out)?;
            Ok(ExitCode::SUCCESS)
        }

        Command::Artifacts { command } => {
            let out = fozzy::artifacts_command(config, command)?;
            logger.print_serialized(&out)?;
            Ok(ExitCode::SUCCESS)
        }

        Command::Report { command } => {
            let out = fozzy::report_command(config, command)?;
            logger.print_serialized(&out)?;
            Ok(ExitCode::SUCCESS)
        }

        Command::Memory { command } => {
            let out = fozzy::memory_command(config, command)?;
            logger.print_serialized(&out)?;
            Ok(ExitCode::SUCCESS)
        }

        Command::Map { command } => {
            let out = fozzy::map_command(config, command)?;
            logger.print_serialized(&out)?;
            Ok(ExitCode::SUCCESS)
        }

        Command::Doctor {
            deep,
            scenario,
            runs,
            seed,
        } => {
            let report = fozzy::doctor(
                config,
                &fozzy::DoctorOptions {
                    deep: *deep,
                    scenario: scenario.clone().map(ScenarioPath::new),
                    runs: *runs,
                    seed: *seed,
                },
            )?;
            logger.print_serialized(&report)?;
            if strict_enabled(cli) {
                let mut reasons = Vec::new();
                if !report.issues.is_empty() {
                    reasons.push(format!("{} issue(s)", report.issues.len()));
                }
                if let Some(signals) = &report.nondeterminism_signals
                    && !signals.is_empty()
                {
                    reasons.push(format!("{} nondeterminism signal(s)", signals.len()));
                }
                if !reasons.is_empty() {
                    return Err(anyhow::anyhow!(
                        "strict mode: doctor reported {}",
                        reasons.join(" and ")
                    ));
                }
            }
            Ok(ExitCode::SUCCESS)
        }

        Command::Env => {
            let info = fozzy::env_info(config);
            logger.print_serialized(&info)?;
            Ok(ExitCode::SUCCESS)
        }

        Command::Ci {
            trace,
            flake_runs,
            flake_budget,
        } => {
            let out = fozzy::ci_command(
                config,
                &CiOptions {
                    trace: trace.clone(),
                    flake_runs: flake_runs.clone(),
                    flake_budget_pct: *flake_budget,
                    strict: strict_enabled(cli),
                },
            )?;
            logger.print_serialized(&out)?;
            Ok(ExitCode::SUCCESS)
        }

        Command::Gate {
            profile,
            scenario_root,
            scope,
            seed,
            doctor_runs,
        } => {
            let report = run_gate_command(
                config,
                *profile,
                scenario_root,
                scope,
                *seed,
                *doctor_runs,
                strict_enabled(cli),
            )?;
            let has_failed = report
                .steps
                .iter()
                .any(|s| matches!(s.status, FullStepStatus::Failed));
            logger.print_serialized(&report)?;
            Ok(if has_failed {
                ExitCode::from(1)
            } else {
                ExitCode::SUCCESS
            })
        }

        Command::Version => {
            let info = fozzy::version_info();
            logger.print_serialized(&info)?;
            Ok(ExitCode::SUCCESS)
        }

        Command::Usage => {
            let doc = fozzy::usage_doc();
            logger.print_usage(&doc)?;
            Ok(ExitCode::SUCCESS)
        }

        Command::Schema => {
            let doc = fozzy::schema_doc();
            logger.print_serialized(&doc)?;
            Ok(ExitCode::SUCCESS)
        }

        Command::Validate { scenario } => {
            let scenario_path = ScenarioPath::new(scenario.clone());
            let out = match fozzy::Scenario::load_file(&scenario_path) {
                Ok(fozzy::ScenarioFile::Steps(steps)) => {
                    let loaded = fozzy::Scenario {
                        name: steps.name.clone(),
                        steps: steps.steps.clone(),
                    };
                    match loaded.validate() {
                        Ok(()) => serde_json::json!({
                            "ok": true,
                            "scenario": scenario.display().to_string(),
                            "variant": "steps",
                            "name": loaded.name,
                            "steps": loaded.steps.len()
                        }),
                        Err(err) => serde_json::json!({
                            "ok": false,
                            "scenario": scenario.display().to_string(),
                            "variant": "steps",
                            "error": err.to_string()
                        }),
                    }
                }
                Ok(fozzy::ScenarioFile::Distributed(dist)) => match dist.validate() {
                    Ok(()) => serde_json::json!({
                        "ok": true,
                        "scenario": scenario.display().to_string(),
                        "variant": "distributed",
                        "name": dist.name,
                        "steps": dist.distributed.steps.len(),
                        "invariants": dist.distributed.invariants.len()
                    }),
                    Err(err) => serde_json::json!({
                        "ok": false,
                        "scenario": scenario.display().to_string(),
                        "variant": "distributed",
                        "error": err.to_string()
                    }),
                },
                Ok(fozzy::ScenarioFile::Suites(suites)) => serde_json::json!({
                    "ok": false,
                    "scenario": scenario.display().to_string(),
                    "variant": "suites",
                    "error": format!(
                        "scenario file {} uses `suites` without an executable step DSL (v0.1 only supports `steps` or `distributed` for execution)",
                        scenario.display()
                    ),
                    "name": suites.name
                }),
                Err(err) => serde_json::json!({
                    "ok": false,
                    "scenario": scenario.display().to_string(),
                    "error": err.to_string()
                }),
            };
            logger.print_serialized(&out)?;
            Ok(if out.get("ok").and_then(|v| v.as_bool()) == Some(true) {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(2)
            })
        }

        Command::Full {
            scenario_root,
            seed,
            doctor_runs,
            fuzz_time,
            explore_steps,
            explore_nodes,
            allow_expected_failures,
            scenario_filter,
            skip_steps,
            required_steps,
            require_topology_coverage,
            topology_min_risk,
            topology_profile,
        } => {
            let report = run_full_command(
                config,
                scenario_root,
                *seed,
                *doctor_runs,
                fuzz_time.0,
                *explore_steps,
                *explore_nodes,
                strict_enabled(cli),
                cli.unsafe_mode,
                *allow_expected_failures,
                scenario_filter.as_deref(),
                skip_steps,
                required_steps,
                require_topology_coverage.as_deref(),
                *topology_min_risk,
                *topology_profile,
            )?;
            let has_failed = report
                .steps
                .iter()
                .any(|s| matches!(s.status, FullStepStatus::Failed));
            logger.print_serialized(&report)?;
            Ok(if has_failed {
                ExitCode::from(1)
            } else {
                ExitCode::SUCCESS
            })
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn run_gate_command(
    config: &Config,
    profile: GateProfile,
    scenario_root: &Path,
    scopes: &[String],
    seed: Option<u64>,
    doctor_runs: u32,
    strict: bool,
) -> anyhow::Result<GateReport> {
    let mut steps = Vec::<FullStepResult>::new();
    let mut push = |name: &str, status: FullStepStatus, detail: String| {
        steps.push(FullStepResult {
            name: name.to_string(),
            status,
            detail,
        });
    };

    let discovered = discover_scenarios(scenario_root);
    if !discovered.parse_errors.is_empty() {
        push(
            "discover",
            FullStepStatus::Failed,
            format!("parse_errors={}", discovered.parse_errors.join(" | ")),
        );
    } else {
        push(
            "discover",
            FullStepStatus::Passed,
            format!(
                "step_scenarios={} distributed_scenarios={}",
                discovered.steps.len(),
                discovered.distributed.len()
            ),
        );
    }

    let scope_tokens: Vec<String> = scopes
        .iter()
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty())
        .collect();
    let mut targets: Vec<PathBuf> = discovered
        .steps
        .iter()
        .filter(|p| {
            if scope_tokens.is_empty() {
                return true;
            }
            let key = p.to_string_lossy().to_ascii_lowercase();
            scope_tokens.iter().any(|token| key.contains(token))
        })
        .cloned()
        .collect();
    targets.sort();
    let matched_scenarios: Vec<String> = targets
        .iter()
        .map(|p| p.to_string_lossy().to_string())
        .collect();

    if targets.is_empty() {
        push(
            "scope_match",
            FullStepStatus::Failed,
            "no step scenarios matched requested scope".to_string(),
        );
        return Ok(GateReport {
            schema_version: "fozzy.gate_report.v1".to_string(),
            profile,
            strict,
            scenario_root: scenario_root.display().to_string(),
            scopes: scope_tokens,
            matched_scenarios,
            steps,
        });
    }
    push(
        "scope_match",
        FullStepStatus::Passed,
        format!("matched={}", targets.len()),
    );

    let primary = targets
        .iter()
        .find(|p| is_preferred_step_scenario(p))
        .cloned()
        .unwrap_or_else(|| targets[0].clone());

    let memory = MemoryOptions {
        track: true,
        limit_mb: config.mem_limit_mb,
        fail_after_allocs: config.mem_fail_after,
        fail_on_leak: config.fail_on_leak,
        leak_budget_bytes: config.leak_budget,
        artifacts: true,
        fragmentation_seed: config.mem_fragmentation_seed,
        pressure_wave: config.mem_pressure_wave.clone(),
    };

    match fozzy::doctor(
        config,
        &fozzy::DoctorOptions {
            deep: true,
            scenario: Some(ScenarioPath::new(primary.clone())),
            runs: doctor_runs.max(2),
            seed,
        },
    ) {
        Ok(report) => {
            let policy_ok = !strict
                || (report.issues.is_empty()
                    && report
                        .nondeterminism_signals
                        .as_ref()
                        .map_or(true, |signals| signals.is_empty()));
            push(
                "doctor_deep",
                if report.ok && policy_ok {
                    FullStepStatus::Passed
                } else {
                    FullStepStatus::Failed
                },
                format!(
                    "ok={} policy_ok={} scenario={}",
                    report.ok,
                    policy_ok,
                    primary.display()
                ),
            );
        }
        Err(err) => push("doctor_deep", FullStepStatus::Failed, err.to_string()),
    }

    let test_globs: Vec<String> = targets
        .iter()
        .map(|p| p.to_string_lossy().to_string())
        .collect();
    match fozzy::run_tests(
        config,
        &test_globs,
        &RunOptions {
            det: true,
            seed,
            timeout: None,
            reporter: Reporter::Json,
            record_trace_to: None,
            filter: None,
            jobs: None,
            fail_fast: false,
            record_collision: RecordCollisionPolicy::Error,
            proc_backend: config.proc_backend,
            fs_backend: config.fs_backend,
            http_backend: config.http_backend,
            memory: memory.clone(),
        },
    ) {
        Ok(test) => {
            let strict_ok = enforce_strict_summary(strict, &test.summary).is_ok();
            push(
                "test_det_strict",
                if strict_ok {
                    FullStepStatus::Passed
                } else {
                    FullStepStatus::Failed
                },
                format!(
                    "status={:?} strict_ok={} run_id={}",
                    test.summary.status, strict_ok, test.summary.identity.run_id
                ),
            );
        }
        Err(err) => push("test_det_strict", FullStepStatus::Failed, err.to_string()),
    }

    let trace_path = std::env::temp_dir().join(format!(
        "fozzy-gate-{}-{}.trace.fozzy",
        profile_string(profile),
        uuid::Uuid::new_v4()
    ));
    let mut primary_status: Option<ExitStatus> = None;
    match fozzy::run_scenario(
        config,
        ScenarioPath::new(primary.clone()),
        &RunOptions {
            det: true,
            seed,
            timeout: None,
            reporter: Reporter::Json,
            record_trace_to: Some(trace_path.clone()),
            filter: None,
            jobs: None,
            fail_fast: false,
            record_collision: RecordCollisionPolicy::Overwrite,
            proc_backend: config.proc_backend,
            fs_backend: config.fs_backend,
            http_backend: config.http_backend,
            memory,
        },
    ) {
        Ok(run) => {
            primary_status = Some(run.summary.status);
            let strict_ok = enforce_strict_summary(strict, &run.summary).is_ok();
            push(
                "run_record_trace",
                if run.summary.identity.trace_path.is_some() && strict_ok {
                    FullStepStatus::Passed
                } else {
                    FullStepStatus::Failed
                },
                format!(
                    "status={:?} strict_ok={} trace={}",
                    run.summary.status,
                    strict_ok,
                    trace_path.display()
                ),
            );
        }
        Err(err) => push("run_record_trace", FullStepStatus::Failed, err.to_string()),
    }

    if trace_path.exists() {
        match fozzy::verify_trace_file(&trace_path) {
            Ok(verify) => {
                let strict_ok = !strict
                    || (verify.checksum_present
                        && verify.checksum_valid
                        && verify.warnings.is_empty());
                push(
                    "trace_verify",
                    if verify.ok && strict_ok {
                        FullStepStatus::Passed
                    } else {
                        FullStepStatus::Failed
                    },
                    format!(
                        "ok={} checksum_present={} checksum_valid={} warnings={}",
                        verify.ok,
                        verify.checksum_present,
                        verify.checksum_valid,
                        verify.warnings.len()
                    ),
                );
            }
            Err(err) => push("trace_verify", FullStepStatus::Failed, err.to_string()),
        }

        match fozzy::replay_trace(
            config,
            TracePath::new(trace_path.clone()),
            &fozzy::ReplayOptions {
                step: false,
                until: None,
                dump_events: false,
                reporter: Reporter::Json,
            },
        ) {
            Ok(replay) => {
                let class_ok = primary_status
                    .map(|s| (s == ExitStatus::Pass) == (replay.summary.status == ExitStatus::Pass))
                    .unwrap_or(false);
                let strict_ok = enforce_strict_summary(strict, &replay.summary).is_ok();
                push(
                    "replay",
                    if class_ok && strict_ok {
                        FullStepStatus::Passed
                    } else {
                        FullStepStatus::Failed
                    },
                    format!(
                        "status={:?} class_ok={} strict_ok={}",
                        replay.summary.status, class_ok, strict_ok
                    ),
                );
            }
            Err(err) => push("replay", FullStepStatus::Failed, err.to_string()),
        }

        let ci = fozzy::ci_evaluate(
            config,
            &CiOptions {
                trace: trace_path.clone(),
                flake_runs: Vec::new(),
                flake_budget_pct: None,
                strict,
            },
        );
        match ci {
            Ok(report) => push(
                "ci",
                if report.ok {
                    FullStepStatus::Passed
                } else {
                    FullStepStatus::Failed
                },
                format!("ok={} checks={}", report.ok, report.checks.len()),
            ),
            Err(err) => push("ci", FullStepStatus::Failed, err.to_string()),
        }
    } else {
        for name in ["trace_verify", "replay", "ci"] {
            push(
                name,
                FullStepStatus::Skipped,
                "trace was not recorded".to_string(),
            );
        }
    }

    Ok(GateReport {
        schema_version: "fozzy.gate_report.v1".to_string(),
        profile,
        strict,
        scenario_root: scenario_root.display().to_string(),
        scopes: scope_tokens,
        matched_scenarios,
        steps,
    })
}

fn profile_string(profile: GateProfile) -> &'static str {
    match profile {
        GateProfile::Targeted => "targeted",
    }
}

#[allow(clippy::too_many_arguments)]
fn run_full_command(
    config: &Config,
    scenario_root: &Path,
    seed: Option<u64>,
    doctor_runs: u32,
    fuzz_time: std::time::Duration,
    explore_steps: u64,
    explore_nodes: usize,
    strict: bool,
    unsafe_mode: bool,
    allow_expected_failures: bool,
    scenario_filter: Option<&str>,
    skip_steps: &[String],
    required_steps: &[String],
    require_topology_coverage: Option<&Path>,
    topology_min_risk: u8,
    topology_profile: TopologyProfile,
) -> anyhow::Result<FullReport> {
    let mut steps = Vec::<FullStepResult>::new();
    let mut push = |name: &str, status: FullStepStatus, detail: String| {
        steps.push(FullStepResult {
            name: name.to_string(),
            status,
            detail,
        });
    };
    let mut shrink_classification: Option<String> = None;

    let mut guidance = vec![
        "Use the entire command surface by default; skip only when required inputs for a command are genuinely missing."
            .to_string(),
        "Keep strict mode enabled (default) so warning-class signals fail fast; use --unsafe only for intentional relaxed passes."
            .to_string(),
        "Place executable scenarios under tests/**/*.fozzy.json; distributed scenarios should use the `distributed` schema."
            .to_string(),
    ];
    if let Some(conflict) = full_policy_conflict_details(
        skip_steps,
        required_steps,
        require_topology_coverage.is_some(),
    ) {
        push("policy_conflict", FullStepStatus::Failed, conflict);
    }

    let usage = fozzy::usage_doc();
    push(
        "usage",
        if usage.items.is_empty() {
            FullStepStatus::Failed
        } else {
            FullStepStatus::Passed
        },
        format!("items={}", usage.items.len()),
    );
    let version = fozzy::version_info();
    push(
        "version",
        FullStepStatus::Passed,
        format!("version={}", version.version),
    );

    let init_tmp = std::env::temp_dir().join(format!("fozzy-full-init-{}", uuid::Uuid::new_v4()));
    let init_status = (|| -> anyhow::Result<String> {
        std::fs::create_dir_all(&init_tmp)?;
        let prev = std::env::current_dir()?;
        std::env::set_current_dir(&init_tmp)?;
        let cfg = Config::load_optional(Path::new("fozzy.toml"));
        let init_res = fozzy::init_project(
            &cfg,
            &InitTemplate::Rust,
            true,
            &selected_init_test_types(&[], true),
        );
        let restore_res = std::env::set_current_dir(prev);
        if let Err(err) = restore_res {
            return Err(anyhow::anyhow!(
                "failed to restore cwd after init check: {err}"
            ));
        }
        init_res?;
        let example = init_tmp.join("tests/example.fozzy.json");
        if !example.exists() {
            return Err(anyhow::anyhow!(
                "expected init scaffold missing: {}",
                example.display()
            ));
        }
        Ok(format!("workspace={}", init_tmp.display()))
    })();
    match init_status {
        Ok(detail) => push("init", FullStepStatus::Passed, detail),
        Err(err) => push("init", FullStepStatus::Failed, err.to_string()),
    }

    let mut discovered = discover_scenarios(scenario_root);
    if let Some(filter) = scenario_filter
        && !filter.is_empty()
    {
        discovered
            .steps
            .retain(|p| p.to_string_lossy().contains(filter));
        discovered
            .distributed
            .retain(|p| p.to_string_lossy().contains(filter));
    }
    let parse_error_count = discovered.parse_errors.len();
    let parsed_summary = format!(
        "discovered step_scenarios={} distributed_scenarios={} parse_errors={}",
        discovered.steps.len(),
        discovered.distributed.len(),
        parse_error_count
    );
    push(
        "discover_scenarios",
        if parse_error_count > 0 {
            FullStepStatus::Failed
        } else {
            FullStepStatus::Passed
        },
        parsed_summary,
    );
    if parse_error_count > 0 {
        guidance.push(format!(
            "Fix malformed scenarios before trusting `fozzy full` coverage: {}",
            discovered.parse_errors.join(" | ")
        ));
    }

    if let Some(root) = require_topology_coverage {
        match fozzy::map_suites(&MapSuitesOptions {
            root: root.to_path_buf(),
            scenario_root: scenario_root.to_path_buf(),
            min_risk: topology_min_risk,
            profile: topology_profile,
            limit: 200,
        }) {
            Ok(report) => {
                let ok = report.uncovered_hotspot_count == 0;
                push(
                    "topology_coverage",
                    if ok {
                        FullStepStatus::Passed
                    } else {
                        FullStepStatus::Failed
                    },
                    format!(
                        "required_hotspots={} covered={} uncovered={} min_risk={} profile={} root={} scenario_root={}",
                        report.required_hotspot_count,
                        report.covered_hotspot_count,
                        report.uncovered_hotspot_count,
                        report.effective_min_risk,
                        format!("{:?}", report.profile).to_lowercase(),
                        root.display(),
                        scenario_root.display()
                    ),
                );
            }
            Err(err) => push("topology_coverage", FullStepStatus::Failed, err.to_string()),
        }
    } else {
        push(
            "topology_coverage",
            FullStepStatus::Skipped,
            "not requested (use --require-topology-coverage <repo_root>)".to_string(),
        );
    }

    let pick_step = discovered
        .steps
        .iter()
        .find(|p| is_preferred_step_scenario(p))
        .cloned()
        .or_else(|| discovered.steps.first().cloned());
    let pick_distributed = discovered
        .distributed
        .iter()
        .find(|p| is_preferred_distributed_scenario(p))
        .cloned()
        .or_else(|| discovered.distributed.first().cloned());

    let memory = MemoryOptions {
        track: true,
        limit_mb: config.mem_limit_mb,
        fail_after_allocs: config.mem_fail_after,
        fail_on_leak: config.fail_on_leak,
        leak_budget_bytes: config.leak_budget,
        artifacts: true,
        fragmentation_seed: config.mem_fragmentation_seed,
        pressure_wave: config.mem_pressure_wave.clone(),
    };

    let mut primary_trace: Option<PathBuf> = None;
    let mut shrunk_trace: Option<PathBuf> = None;
    let mut primary_status: Option<ExitStatus> = None;

    if pick_step.is_none() {
        push(
            "doctor_deep",
            FullStepStatus::Skipped,
            "no step scenario found; add tests/*.fozzy.json to run deterministic audits"
                .to_string(),
        );
        push(
            "test_det",
            FullStepStatus::Skipped,
            "no step scenario found".to_string(),
        );
        push(
            "run_record_trace",
            FullStepStatus::Skipped,
            "no step scenario found".to_string(),
        );
    } else {
        let primary = pick_step
            .clone()
            .expect("pick_step checked as Some in else branch");
        match fozzy::doctor(
            config,
            &fozzy::DoctorOptions {
                deep: true,
                scenario: Some(ScenarioPath::new(primary.clone())),
                runs: doctor_runs.max(2),
                seed,
            },
        ) {
            Ok(doctor) => {
                let doctor_failed_strict = strict
                    && (!doctor.issues.is_empty()
                        || doctor
                            .nondeterminism_signals
                            .as_ref()
                            .is_some_and(|s| !s.is_empty()));
                push(
                    "doctor_deep",
                    if doctor.ok && !doctor_failed_strict {
                        FullStepStatus::Passed
                    } else {
                        FullStepStatus::Failed
                    },
                    format!(
                        "ok={} strict_policy_ok={} runs={} scenario={}",
                        doctor.ok,
                        !doctor_failed_strict,
                        doctor_runs.max(2),
                        primary.display()
                    ),
                );
            }
            Err(err) => push("doctor_deep", FullStepStatus::Failed, err.to_string()),
        }

        let filtered_steps: Vec<PathBuf> = discovered
            .steps
            .iter()
            .filter(|p| !is_negative_fixture_scenario(p))
            .cloned()
            .collect();
        let test_targets = if filtered_steps.is_empty() {
            vec![primary.clone()]
        } else {
            filtered_steps
        };
        let test_globs: Vec<String> = test_targets
            .iter()
            .map(|p| p.to_string_lossy().to_string())
            .collect();
        match fozzy::run_tests(
            config,
            &test_globs,
            &RunOptions {
                det: true,
                seed,
                timeout: None,
                reporter: Reporter::Json,
                record_trace_to: None,
                filter: None,
                jobs: None,
                fail_fast: false,
                record_collision: RecordCollisionPolicy::Error,
                proc_backend: config.proc_backend,
                fs_backend: config.fs_backend,
                http_backend: config.http_backend,
                memory: memory.clone(),
            },
        ) {
            Ok(test) => push(
                "test_det",
                FullStepStatus::Passed,
                format!(
                    "status={:?} run_id={}",
                    test.summary.status, test.summary.identity.run_id
                ),
            ),
            Err(err) => push("test_det", FullStepStatus::Failed, err.to_string()),
        }

        let trace_path =
            std::env::temp_dir().join(format!("fozzy-full-{}.trace.fozzy", uuid::Uuid::new_v4()));
        match fozzy::run_scenario(
            config,
            ScenarioPath::new(primary.clone()),
            &RunOptions {
                det: true,
                seed,
                timeout: None,
                reporter: Reporter::Json,
                record_trace_to: Some(trace_path.clone()),
                filter: None,
                jobs: None,
                fail_fast: false,
                record_collision: RecordCollisionPolicy::Overwrite,
                proc_backend: config.proc_backend,
                fs_backend: config.fs_backend,
                http_backend: config.http_backend,
                memory: memory.clone(),
            },
        ) {
            Ok(run) => {
                primary_status = Some(run.summary.status);
                if run.summary.identity.trace_path.is_some() {
                    primary_trace = Some(trace_path.clone());
                }
                push(
                    "run_record_trace",
                    if run.summary.identity.trace_path.is_some() {
                        FullStepStatus::Passed
                    } else {
                        FullStepStatus::Failed
                    },
                    format!(
                        "status={:?} trace={}",
                        run.summary.status,
                        trace_path.display()
                    ),
                );
            }
            Err(err) => push("run_record_trace", FullStepStatus::Failed, err.to_string()),
        }
    }

    if let Some(trace) = primary_trace.as_ref() {
        match fozzy::verify_trace_file(trace) {
            Ok(verify) => {
                let strict_verify_ok = !strict
                    || (verify.checksum_present
                        && verify.checksum_valid
                        && verify.warnings.is_empty());
                push(
                    "trace_verify",
                    if verify.ok && strict_verify_ok {
                        FullStepStatus::Passed
                    } else {
                        FullStepStatus::Failed
                    },
                    format!(
                        "ok={} checksum_present={} checksum_valid={} warnings={}",
                        verify.ok,
                        verify.checksum_present,
                        verify.checksum_valid,
                        if verify.warnings.is_empty() {
                            "<none>".to_string()
                        } else {
                            verify.warnings.join("; ")
                        }
                    ),
                );
            }
            Err(err) => push("trace_verify", FullStepStatus::Failed, err.to_string()),
        }

        match fozzy::replay_trace(
            config,
            TracePath::new(trace.clone()),
            &fozzy::ReplayOptions {
                step: false,
                until: None,
                dump_events: false,
                reporter: Reporter::Json,
            },
        ) {
            Ok(replay) => {
                let replay_ok = primary_status
                    .map(|s| (s == ExitStatus::Pass) == (replay.summary.status == ExitStatus::Pass))
                    .unwrap_or(false);
                push(
                    "replay",
                    if replay_ok {
                        FullStepStatus::Passed
                    } else {
                        FullStepStatus::Failed
                    },
                    format!(
                        "status={:?} run_id={}",
                        replay.summary.status, replay.summary.identity.run_id
                    ),
                );
            }
            Err(err) => push("replay", FullStepStatus::Failed, err.to_string()),
        }

        match fozzy::ci_command(
            config,
            &CiOptions {
                trace: trace.clone(),
                flake_runs: Vec::new(),
                flake_budget_pct: None,
                strict,
            },
        ) {
            Ok(ci) => push(
                "ci",
                if ci.ok {
                    FullStepStatus::Passed
                } else {
                    FullStepStatus::Failed
                },
                format!("ok={} checks={}", ci.ok, ci.checks.len()),
            ),
            Err(err) => push("ci", FullStepStatus::Failed, err.to_string()),
        }

        let shrink_out =
            std::env::temp_dir().join(format!("fozzy-full-{}.min.fozzy", uuid::Uuid::new_v4()));
        match fozzy::shrink_trace(
            config,
            TracePath::new(trace.clone()),
            &fozzy::ShrinkOptions {
                out_trace_path: Some(shrink_out.clone()),
                budget: None,
                aggressive: false,
                minimize: ShrinkMinimize::All,
            },
        ) {
            Ok(shrink) => {
                shrunk_trace = Some(PathBuf::from(shrink.out_trace_path.clone()));
                let status = if allow_expected_failures {
                    if let Some(primary) = primary_status {
                        if shrink_status_matches(primary, shrink.result.summary.status) {
                            shrink_classification =
                                Some("expected_fail_class_preserved".to_string());
                            FullStepStatus::Passed
                        } else {
                            shrink_classification =
                                Some("expected_fail_class_mismatch".to_string());
                            FullStepStatus::Failed
                        }
                    } else {
                        shrink_classification = Some("primary_status_missing".to_string());
                        FullStepStatus::Passed
                    }
                } else if shrink.result.summary.status == ExitStatus::Pass {
                    shrink_classification = Some("pass_required_policy".to_string());
                    FullStepStatus::Passed
                } else {
                    shrink_classification = Some("policy_rejected_non_pass".to_string());
                    FullStepStatus::Failed
                };
                push(
                    "shrink",
                    status,
                    format!("out_trace={}", shrink.out_trace_path),
                );
            }
            Err(err) => {
                shrink_classification = Some("tooling_failure".to_string());
                push("shrink", FullStepStatus::Failed, err.to_string())
            }
        }

        if let Some(min_trace) = shrunk_trace.as_ref() {
            match fozzy::replay_trace(
                config,
                TracePath::new(min_trace.clone()),
                &fozzy::ReplayOptions {
                    step: false,
                    until: None,
                    dump_events: false,
                    reporter: Reporter::Json,
                },
            ) {
                Ok(replay) => push(
                    "replay_shrunk",
                    FullStepStatus::Passed,
                    format!("status={:?}", replay.summary.status),
                ),
                Err(err) => push("replay_shrunk", FullStepStatus::Failed, err.to_string()),
            }
        } else {
            push(
                "replay_shrunk",
                FullStepStatus::Skipped,
                "shrink output not available".to_string(),
            );
        }

        let _ = fozzy::artifacts_command(
            config,
            &ArtifactCommand::Ls {
                run: trace.display().to_string(),
            },
        )
        .map(|_| {
            push(
                "artifacts_ls",
                FullStepStatus::Passed,
                trace.display().to_string(),
            )
        })
        .map_err(|err| push("artifacts_ls", FullStepStatus::Failed, err.to_string()));

        let artifacts_export =
            std::env::temp_dir().join(format!("fozzy-full-artifacts-{}.zip", uuid::Uuid::new_v4()));
        match fozzy::artifacts_command(
            config,
            &ArtifactCommand::Export {
                run: trace.display().to_string(),
                out: artifacts_export.clone(),
            },
        ) {
            Ok(_) => push(
                "artifacts_export",
                FullStepStatus::Passed,
                artifacts_export.display().to_string(),
            ),
            Err(err) => push("artifacts_export", FullStepStatus::Failed, err.to_string()),
        }

        let artifacts_pack =
            std::env::temp_dir().join(format!("fozzy-full-pack-{}.zip", uuid::Uuid::new_v4()));
        match fozzy::artifacts_command(
            config,
            &ArtifactCommand::Pack {
                run: trace.display().to_string(),
                out: artifacts_pack.clone(),
            },
        ) {
            Ok(_) => push(
                "artifacts_pack",
                FullStepStatus::Passed,
                artifacts_pack.display().to_string(),
            ),
            Err(err) => push("artifacts_pack", FullStepStatus::Failed, err.to_string()),
        }

        if let Some(min_trace) = shrunk_trace.as_ref() {
            match fozzy::artifacts_command(
                config,
                &ArtifactCommand::Diff {
                    left: trace.display().to_string(),
                    right: min_trace.display().to_string(),
                },
            ) {
                Ok(_) => push(
                    "artifacts_diff",
                    FullStepStatus::Passed,
                    format!("left={} right={}", trace.display(), min_trace.display()),
                ),
                Err(err) => push("artifacts_diff", FullStepStatus::Failed, err.to_string()),
            }
        } else {
            push(
                "artifacts_diff",
                FullStepStatus::Skipped,
                "requires shrink output".to_string(),
            );
        }

        match fozzy::report_command(
            config,
            &ReportCommand::Show {
                run: trace.display().to_string(),
                format: Reporter::Pretty,
            },
        ) {
            Ok(_) => push(
                "report_show",
                FullStepStatus::Passed,
                "generated pretty report envelope".to_string(),
            ),
            Err(err) => push("report_show", FullStepStatus::Failed, err.to_string()),
        }

        match fozzy::report_command(
            config,
            &ReportCommand::Query {
                run: trace.display().to_string(),
                jq: Some(".status".to_string()),
                list_paths: false,
            },
        ) {
            Ok(_) => push(
                "report_query",
                FullStepStatus::Passed,
                "queried .status".to_string(),
            ),
            Err(err) => push("report_query", FullStepStatus::Failed, err.to_string()),
        }

        match fozzy::report_command(
            config,
            &ReportCommand::Query {
                run: trace.display().to_string(),
                jq: None,
                list_paths: true,
            },
        ) {
            Ok(_) => push(
                "report_query_paths",
                FullStepStatus::Passed,
                "listed report paths".to_string(),
            ),
            Err(err) => push(
                "report_query_paths",
                FullStepStatus::Failed,
                err.to_string(),
            ),
        }

        if let Some(min_trace) = shrunk_trace.as_ref() {
            match fozzy::report_command(
                config,
                &ReportCommand::Flaky {
                    runs: vec![trace.display().to_string(), min_trace.display().to_string()],
                    flake_budget: None,
                },
            ) {
                Ok(_) => push(
                    "report_flaky",
                    FullStepStatus::Passed,
                    "computed flaky report across primary/shrunk traces".to_string(),
                ),
                Err(err) => push("report_flaky", FullStepStatus::Failed, err.to_string()),
            }
        } else {
            push(
                "report_flaky",
                FullStepStatus::Skipped,
                "requires second trace input".to_string(),
            );
        }

        match fozzy::memory_command(
            config,
            &MemoryCommand::Top {
                run: trace.display().to_string(),
                limit: 10,
            },
        ) {
            Ok(_) => push(
                "memory_top",
                FullStepStatus::Passed,
                "memory diagnostics checked".to_string(),
            ),
            Err(err) => push("memory_top", FullStepStatus::Failed, err.to_string()),
        }

        match fozzy::memory_command(
            config,
            &MemoryCommand::Graph {
                run: trace.display().to_string(),
                out: None,
            },
        ) {
            Ok(_) => push(
                "memory_graph",
                FullStepStatus::Passed,
                "allocation graph extracted".to_string(),
            ),
            Err(err) => push("memory_graph", FullStepStatus::Failed, err.to_string()),
        }

        if let Some(min_trace) = shrunk_trace.as_ref() {
            match fozzy::memory_command(
                config,
                &MemoryCommand::Diff {
                    left: trace.display().to_string(),
                    right: min_trace.display().to_string(),
                },
            ) {
                Ok(_) => push(
                    "memory_diff",
                    FullStepStatus::Passed,
                    "memory delta computed".to_string(),
                ),
                Err(err) => push("memory_diff", FullStepStatus::Failed, err.to_string()),
            }
        } else {
            push(
                "memory_diff",
                FullStepStatus::Skipped,
                "requires second trace input".to_string(),
            );
        }
    } else {
        for name in [
            "trace_verify",
            "replay",
            "ci",
            "shrink",
            "replay_shrunk",
            "artifacts_ls",
            "artifacts_export",
            "artifacts_pack",
            "artifacts_diff",
            "report_show",
            "report_query",
            "report_query_paths",
            "report_flaky",
            "memory_top",
            "memory_graph",
            "memory_diff",
        ] {
            push(
                name,
                FullStepStatus::Skipped,
                "no recorded trace available".to_string(),
            );
        }
    }

    let full_fuzz_target: FuzzTarget = "fn:kv".parse().map_err(|e| anyhow::anyhow!("{e}"))?;
    let fuzz_trace = std::env::temp_dir().join(format!(
        "fozzy-full-fuzz-{}.trace.fozzy",
        uuid::Uuid::new_v4()
    ));
    match fozzy::fuzz(
        config,
        &full_fuzz_target,
        &FuzzOptions {
            mode: FuzzMode::Coverage,
            seed,
            time: Some(fuzz_time),
            runs: None,
            max_input_bytes: 4096,
            corpus_dir: None,
            mutator: None,
            shrink: true,
            record_trace_to: Some(fuzz_trace.clone()),
            reporter: Reporter::Json,
            crash_only: false,
            minimize: true,
            record_collision: RecordCollisionPolicy::Overwrite,
            memory: memory.clone(),
        },
    ) {
        Ok(fuzz_run) => push(
            "fuzz",
            FullStepStatus::Passed,
            format!(
                "status={:?} run_id={}",
                fuzz_run.summary.status, fuzz_run.summary.identity.run_id
            ),
        ),
        Err(err) => push("fuzz", FullStepStatus::Failed, err.to_string()),
    }

    if let Some(distributed) = pick_distributed.as_ref() {
        match fozzy::explore(
            config,
            ScenarioPath::new(distributed.clone()),
            &ExploreOptions {
                seed,
                time: None,
                steps: Some(explore_steps),
                nodes: Some(explore_nodes),
                faults: None,
                schedule: ScheduleStrategy::CoverageGuided,
                checker: None,
                record_trace_to: None,
                shrink: true,
                minimize: true,
                reporter: Reporter::Json,
                record_collision: RecordCollisionPolicy::Error,
                memory: memory.clone(),
            },
        ) {
            Ok(explore) => push(
                "explore",
                FullStepStatus::Passed,
                format!(
                    "status={:?} scenario={}",
                    explore.summary.status,
                    distributed.display()
                ),
            ),
            Err(err) => push("explore", FullStepStatus::Failed, err.to_string()),
        }
    } else {
        push(
            "explore",
            FullStepStatus::Skipped,
            "no distributed scenario found; add tests/*.fozzy.json with `distributed` schema"
                .to_string(),
        );
    }

    let corpus_dir =
        std::env::temp_dir().join(format!("fozzy-full-corpus-{}", uuid::Uuid::new_v4()));
    let seed_file = corpus_dir.join("seed.bin");
    let corpus_zip =
        std::env::temp_dir().join(format!("fozzy-full-corpus-{}.zip", uuid::Uuid::new_v4()));
    let corpus_import_dir =
        std::env::temp_dir().join(format!("fozzy-full-corpus-import-{}", uuid::Uuid::new_v4()));
    let corpus_setup = (|| -> anyhow::Result<()> {
        std::fs::create_dir_all(&corpus_dir)?;
        std::fs::write(&seed_file, b"fozzy-corpus-seed")?;
        Ok(())
    })();
    if let Err(err) = corpus_setup {
        for name in [
            "corpus_add",
            "corpus_list",
            "corpus_minimize",
            "corpus_export",
            "corpus_import",
        ] {
            push(name, FullStepStatus::Failed, err.to_string());
        }
    } else {
        match fozzy::corpus_command(
            config,
            &CorpusCommand::Add {
                dir: corpus_dir.clone(),
                file: seed_file.clone(),
            },
        ) {
            Ok(_) => push(
                "corpus_add",
                FullStepStatus::Passed,
                corpus_dir.display().to_string(),
            ),
            Err(err) => push("corpus_add", FullStepStatus::Failed, err.to_string()),
        }
        match fozzy::corpus_command(
            config,
            &CorpusCommand::List {
                dir: corpus_dir.clone(),
            },
        ) {
            Ok(_) => push(
                "corpus_list",
                FullStepStatus::Passed,
                corpus_dir.display().to_string(),
            ),
            Err(err) => push("corpus_list", FullStepStatus::Failed, err.to_string()),
        }
        match fozzy::corpus_command(
            config,
            &CorpusCommand::Minimize {
                dir: corpus_dir.clone(),
                budget: None,
            },
        ) {
            Ok(_) => push(
                "corpus_minimize",
                FullStepStatus::Passed,
                "placeholder minimization executed".to_string(),
            ),
            Err(err) => push("corpus_minimize", FullStepStatus::Failed, err.to_string()),
        }
        match fozzy::corpus_command(
            config,
            &CorpusCommand::Export {
                dir: corpus_dir.clone(),
                out: corpus_zip.clone(),
            },
        ) {
            Ok(_) => push(
                "corpus_export",
                FullStepStatus::Passed,
                corpus_zip.display().to_string(),
            ),
            Err(err) => push("corpus_export", FullStepStatus::Failed, err.to_string()),
        }
        match fozzy::corpus_command(
            config,
            &CorpusCommand::Import {
                zip: corpus_zip,
                out: corpus_import_dir,
            },
        ) {
            Ok(_) => push(
                "corpus_import",
                FullStepStatus::Passed,
                "imported zip into temp directory".to_string(),
            ),
            Err(err) => push("corpus_import", FullStepStatus::Failed, err.to_string()),
        }
    }

    if let Some(primary) = pick_step.as_ref() {
        match fozzy::run_scenario(
            config,
            ScenarioPath::new(primary.clone()),
            &RunOptions {
                det: false,
                seed,
                timeout: None,
                reporter: Reporter::Json,
                record_trace_to: None,
                filter: None,
                jobs: None,
                fail_fast: false,
                record_collision: RecordCollisionPolicy::Error,
                proc_backend: fozzy::ProcBackend::Host,
                fs_backend: fozzy::FsBackend::Host,
                http_backend: fozzy::HttpBackend::Host,
                memory,
            },
        ) {
            Ok(host_run) => push(
                "host_backends_run",
                FullStepStatus::Passed,
                format!("status={:?}", host_run.summary.status),
            ),
            Err(err) => push("host_backends_run", FullStepStatus::Failed, err.to_string()),
        }
    } else {
        push(
            "host_backends_run",
            FullStepStatus::Skipped,
            "no step scenario found".to_string(),
        );
    }

    let _env = fozzy::env_info(config);
    push(
        "env",
        FullStepStatus::Passed,
        "environment capability snapshot collected".to_string(),
    );

    apply_full_policy_filters(&mut steps, skip_steps, required_steps);

    Ok(FullReport {
        schema_version: "fozzy.full_report.v1".to_string(),
        strict,
        unsafe_mode,
        scenario_root: scenario_root.display().to_string(),
        guidance,
        shrink_classification,
        steps,
    })
}

fn discover_scenarios(root: &Path) -> FullScenarioDiscovery {
    let mut out = FullScenarioDiscovery {
        steps: Vec::new(),
        distributed: Vec::new(),
        parse_errors: Vec::new(),
    };
    if !root.exists() {
        return out;
    }
    for entry in WalkDir::new(root).into_iter().flatten() {
        let path = entry.path();
        if !entry.file_type().is_file() {
            continue;
        }
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if !name.ends_with(".fozzy.json") {
            continue;
        }
        let bytes = match std::fs::read(path) {
            Ok(v) => v,
            Err(err) => {
                out.parse_errors
                    .push(format!("{}: {}", path.display(), err));
                continue;
            }
        };
        match serde_json::from_slice::<fozzy::ScenarioFile>(&bytes) {
            Ok(fozzy::ScenarioFile::Steps(_)) => out.steps.push(path.to_path_buf()),
            Ok(fozzy::ScenarioFile::Distributed(_)) => out.distributed.push(path.to_path_buf()),
            Ok(fozzy::ScenarioFile::Suites(_)) => out.parse_errors.push(format!(
                "{}: suites format is not executable",
                path.display()
            )),
            Err(err) => out.parse_errors.push(format!("{}: {err}", path.display())),
        }
    }
    out.steps.sort();
    out.distributed.sort();
    out
}

fn selected_init_test_types(with: &[InitTestType], all_tests: bool) -> Vec<InitTestType> {
    if all_tests || with.is_empty() {
        return vec![InitTestType::All];
    }
    let mut out = with.to_vec();
    if out.contains(&InitTestType::All) {
        return vec![InitTestType::All];
    }
    out.sort_by_key(|v| match v {
        InitTestType::Run => 0,
        InitTestType::Fuzz => 1,
        InitTestType::Explore => 2,
        InitTestType::Memory => 3,
        InitTestType::Host => 4,
        InitTestType::All => 5,
    });
    out.dedup();
    out
}

fn apply_full_policy_filters(
    steps: &mut [FullStepResult],
    skip_steps: &[String],
    required_steps: &[String],
) {
    use std::collections::BTreeSet;
    let skip: BTreeSet<String> = skip_steps
        .iter()
        .map(|s| s.trim().to_ascii_lowercase())
        .collect();
    let required: BTreeSet<String> = required_steps
        .iter()
        .map(|s| s.trim().to_ascii_lowercase())
        .collect();

    for step in steps {
        let key = step.name.to_ascii_lowercase();
        if key == "policy_conflict" {
            continue;
        }
        if !required.is_empty() && !required.contains(&key) {
            step.status = FullStepStatus::Skipped;
            step.detail = format!("skipped by required-steps policy; {}", step.detail);
            continue;
        }
        if skip.contains(&key) {
            step.status = FullStepStatus::Skipped;
            step.detail = format!("skipped by skip-steps policy; {}", step.detail);
        }
    }
}

fn full_policy_conflict_details(
    skip_steps: &[String],
    required_steps: &[String],
    topology_required: bool,
) -> Option<String> {
    use std::collections::BTreeSet;
    if !topology_required {
        return None;
    }
    let req: BTreeSet<String> = required_steps
        .iter()
        .map(|s| s.trim().to_ascii_lowercase())
        .collect();
    if !req.is_empty() && !req.contains("topology_coverage") {
        return Some(
            "--require-topology-coverage was set, but --required-steps excludes topology_coverage; refusing implicit policy neutralization"
                .to_string(),
        );
    }
    let skip: BTreeSet<String> = skip_steps
        .iter()
        .map(|s| s.trim().to_ascii_lowercase())
        .collect();
    if skip.contains("topology_coverage") {
        return Some(
            "--require-topology-coverage conflicts with --skip-steps topology_coverage; remove one policy flag"
                .to_string(),
        );
    }
    None
}

fn shrink_status_matches(target: ExitStatus, candidate: ExitStatus) -> bool {
    if target == ExitStatus::Pass {
        candidate == ExitStatus::Pass
    } else {
        candidate != ExitStatus::Pass
    }
}

fn is_negative_fixture_scenario(path: &Path) -> bool {
    let name = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    ["fail", "leak", "panic", "timeout", "checkers", "assertions"]
        .iter()
        .any(|tok| name.contains(tok))
}

fn is_preferred_step_scenario(path: &Path) -> bool {
    let name = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    name.contains("pass") || name.contains("example")
}

fn is_preferred_distributed_scenario(path: &Path) -> bool {
    let name = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    !name.contains("checkers")
}

fn enforce_strict_run(cli: &Cli, summary: &RunSummary) -> anyhow::Result<()> {
    enforce_strict_summary(strict_enabled(cli), summary)
}

fn enforce_strict_summary(strict: bool, summary: &RunSummary) -> anyhow::Result<()> {
    if !strict {
        return Ok(());
    }

    let warnings: Vec<&str> = summary
        .findings
        .iter()
        .filter(|f| f.title == "stale_trace_schema")
        .map(|f| f.message.as_str())
        .collect();
    if warnings.is_empty() {
        return Ok(());
    }

    Err(anyhow::anyhow!(
        "strict mode: run contains warning findings: {}",
        warnings.join("; ")
    ))
}

fn strict_enabled(cli: &Cli) -> bool {
    cli.strict && !cli.unsafe_mode
}

fn print_error_and_exit(logger: &CliLogger, err: anyhow::Error) -> ExitCode {
    let msg = format!("{err:#}");
    logger.print_error(&msg);
    ExitCode::from(2)
}

fn print_clap_error_and_exit(json: bool, err: clap::Error) -> ExitCode {
    let kind = err.kind();
    let code = err.exit_code();
    if matches!(kind, ErrorKind::DisplayHelp | ErrorKind::DisplayVersion) {
        let _ = err.print();
        return ExitCode::from(code as u8);
    }
    if json {
        let out = serde_json::json!({
            "code": "error",
            "message": err.to_string().trim_end(),
        });
        match serde_json::to_string_pretty(&out) {
            Ok(s) => println!("{s}"),
            Err(_) => println!("{out}"),
        }
    } else {
        let _ = err.print();
    }
    ExitCode::from(code as u8)
}

fn exit_code_for_status(status: ExitStatus) -> ExitCode {
    match status {
        ExitStatus::Pass => ExitCode::SUCCESS,
        ExitStatus::Fail => ExitCode::from(1),
        ExitStatus::Timeout => ExitCode::from(3),
        ExitStatus::Crash => ExitCode::from(4),
        ExitStatus::Error => ExitCode::from(2),
    }
}
