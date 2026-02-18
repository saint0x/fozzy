//! Fozzy CLI entrypoint.

use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

use std::path::PathBuf;
use std::process::ExitCode;

use fozzy::{
    ArtifactCommand, Config, CorpusCommand, ExitStatus, FozzyDuration, InitTemplate, ReportCommand,
    ExploreOptions, FuzzMode, FuzzOptions, FuzzTarget, Reporter, RunOptions, RunSummary,
    ScenarioPath, ScheduleStrategy, ShrinkMinimize, TracePath,
};

#[derive(Debug, Parser)]
#[command(name = "fozzy")]
#[command(about = "deterministic full-stack testing + fuzzing + distributed exploration")]
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

        /// Stop on first failure.
        #[arg(long)]
        fail_fast: bool,
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

    /// Diagnose nondeterminism + environment issues
    Doctor {
        #[arg(long)]
        deep: bool,
    },

    /// Print environment + capability backend info
    Env,

    /// Print version and build info
    Version,

    /// Show a compact "what to use when" guide for each command, with examples.
    Usage,
}

fn main() -> ExitCode {
    let cli = Cli::parse_from(normalize_global_args(std::env::args()));

    if let Err(err) = init_tracing(&cli.log) {
        // Tracing is best-effort; if it fails, we still continue.
        eprintln!("warning: failed to init tracing: {err:#}");
    }

    let cwd = cli.cwd.clone().unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
    if let Err(err) = std::env::set_current_dir(&cwd) {
        return print_error_and_exit(&cli, anyhow::anyhow!(err).context(format!("failed to set cwd to {}", cwd.display())));
    }

    let config = Config::load_optional(&cli.config);

    match run_command(&cli, &config) {
        Ok(code) => code,
        Err(err) => print_error_and_exit(&cli, err),
    }
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
            "--json" | "--no-color" => {
                globals.push(arg.clone());
                i += 1;
            }
            "--config" | "--cwd" | "--log" => {
                globals.push(arg.clone());
                if i + 1 < all.len() {
                    globals.push(all[i + 1].clone());
                    i += 2;
                } else {
                    i += 1;
                }
            }
            _ if arg.starts_with("--config=") || arg.starts_with("--cwd=") || arg.starts_with("--log=") => {
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
    tracing_subscriber::fmt().with_env_filter(filter).with_target(false).init();
    Ok(())
}

fn run_command(cli: &Cli, config: &Config) -> anyhow::Result<ExitCode> {
    match &cli.command {
        Command::Init { force, template } => {
            fozzy::init_project(config, &InitTemplate::from_option(template.as_ref()), *force)?;
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
        } => {
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
                },
            )?;
            print_run_summary(cli, &run.summary)?;
            Ok(exit_code_for_status(run.summary.status))
        }

        Command::Run {
            scenario,
            det,
            seed,
            timeout,
            reporter,
            record,
        } => {
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
                },
            )?;
            print_run_summary(cli, &run.summary)?;
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
        } => {
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
                },
            )?;
            print_run_summary(cli, &run.summary)?;
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
        } => {
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
                },
            )?;
            print_run_summary(cli, &run.summary)?;
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
            print_run_summary(cli, &run.summary)?;
            Ok(exit_code_for_status(run.summary.status))
        }

        Command::Shrink {
            trace,
            out,
            budget,
            aggressive,
            minimize,
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
            print_run_summary(cli, &result.result.summary)?;
            Ok(exit_code_for_status(result.result.summary.status))
        }

        Command::Corpus { command } => {
            let out = fozzy::corpus_command(config, command)?;
            print_json_or_text(cli, &out)?;
            Ok(ExitCode::SUCCESS)
        }

        Command::Artifacts { command } => {
            let out = fozzy::artifacts_command(config, command)?;
            print_json_or_text(cli, &out)?;
            Ok(ExitCode::SUCCESS)
        }

        Command::Report { command } => {
            let out = fozzy::report_command(config, command)?;
            print_json_or_text(cli, &out)?;
            Ok(ExitCode::SUCCESS)
        }

        Command::Doctor { deep } => {
            let report = fozzy::doctor(config, *deep)?;
            print_json_or_text(cli, &report)?;
            Ok(ExitCode::SUCCESS)
        }

        Command::Env => {
            let info = fozzy::env_info(config);
            print_json_or_text(cli, &info)?;
            Ok(ExitCode::SUCCESS)
        }

        Command::Version => {
            let info = fozzy::version_info();
            print_json_or_text(cli, &info)?;
            Ok(ExitCode::SUCCESS)
        }

        Command::Usage => {
            let doc = fozzy::usage_doc();
            if cli.json {
                print_json_or_text(cli, &doc)?;
            } else {
                println!("{}", doc.pretty());
            }
            Ok(ExitCode::SUCCESS)
        }
    }
}

fn print_run_summary(cli: &Cli, summary: &RunSummary) -> anyhow::Result<()> {
    if cli.json {
        print_json_or_text(cli, summary)?;
    } else {
        println!("{}", summary.pretty());
    }
    Ok(())
}

fn print_json_or_text<T: serde::Serialize>(cli: &Cli, value: &T) -> anyhow::Result<()> {
    if cli.json {
        println!("{}", serde_json::to_string(value)?);
    } else {
        println!("{}", serde_json::to_string_pretty(value)?);
    }
    Ok(())
}

fn print_error_and_exit(cli: &Cli, err: anyhow::Error) -> ExitCode {
    let msg = format!("{err:#}");
    if cli.json {
        let out = serde_json::json!({
            "status": "error",
            "code": "error",
            "message": msg,
        });
        println!("{}", out.to_string());
    } else {
        eprintln!("{msg}");
    }
    ExitCode::from(2)
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
