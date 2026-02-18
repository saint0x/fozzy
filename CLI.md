fozzy — deterministic full-stack testing + fuzzing + distributed exploration

USAGE:
  fozzy <command> [args] [--flags]

CORE COMMANDS:
  init                      Initialize a fozzy project (config + scaffolding)
  test                      Run regular tests (optionally deterministic)
  run                       Run a single scenario file (one-off)
  fuzz                      Coverage-guided or property-based fuzzing
  explore                   Deterministic distributed schedule + fault exploration
  replay                    Replay a previously recorded run exactly
  trace                     Verify trace integrity/schema warnings
  shrink                    Minimize a failing run (input + schedule + fault trace)
  corpus                    Manage fuzz corpora (add/list/minimize/export/import)
  artifacts                 Inspect/export artifacts (traces, timelines, diffs)
  report                    Render / query run reports (JSON, JUnit, HTML)
  doctor                    Diagnose nondeterminism + environment issues
  ci                        Run canonical local gate checks for a trace
  env                        Print environment + capability backend info
  version                   Print version and build info

TEST:
  fozzy test [globs] [--det] [--seed <n>] [--jobs <n>] [--timeout <dur>]
            [--filter <expr>] [--reporter <json|pretty|junit|html>]
            [--record <path>] [--record-collision error|overwrite|append] [--fail-fast]

FUZZ:
  fozzy fuzz <target> [--mode coverage|property] [--seed <n>] [--time <dur>]
            [--runs <n>] [--max-input <bytes>] [--corpus <dir>]
            [--mutator <name>] [--shrink] [--record <path>]
            [--record-collision error|overwrite|append]
            [--reporter <...>] [--crash-only] [--minimize]

EXPLORE (distributed):
  fozzy explore <scenario> [--seed <n>] [--time <dur>] [--steps <n>]
            [--nodes <n>] [--faults <preset|file>] [--schedule <strategy>]
            [--checker <name>] [--record <path>] [--record-collision error|overwrite|append] [--shrink]
            [--reporter <...>] [--minimize]
  schedules: fifo|bfs|dfs|random|pct|coverage_guided
  presets: --faults none|partition-first-two|heal-first-two|crash-first|restart-first
  checkers: --checker kv_all_equal:<key>|kv_present_on_all:<key>|kv_node_equals:<node>:<key>:<value>
  note: `--checker` overrides scenario invariants; `kv_all_equal` is evaluated as a final-state convergence invariant.

REPLAY:
  fozzy replay <trace.fozzy> [--step] [--until <t>] [--json] [--dump-events]

TRACE:
  fozzy trace verify <trace.fozzy>

SHRINK:
  fozzy shrink <trace.fozzy> [--out <trace>] [--budget <dur>] [--aggressive]
            [--minimize input|schedule|faults|all] [--reporter <json|pretty|junit|html>]

CORPUS:
  fozzy corpus list <dir>
  fozzy corpus add <dir> <file>
  fozzy corpus minimize <dir> [--budget <dur>]
  fozzy corpus export <dir> --out <zip>
  fozzy corpus import <zip> --out <dir>

ARTIFACTS:
  fozzy artifacts ls <run-id|trace>
  fozzy artifacts diff <left-run-id|trace> <right-run-id|trace>
  fozzy artifacts export <run-id|trace> --out <dir|zip>
  fozzy artifacts pack <run-id|trace> --out <dir|zip>    (adds env/version/commandline metadata)

REPORT:
  fozzy report show <run-id|trace> [--format json|pretty|junit|html]
  fozzy report query <run-id|trace> --jq <expr>   (path subset: .a.b, a.b, .arr[0], .arr[].field, $.a.b)
  fozzy report query <run-id|trace> --list-paths
  fozzy report flaky <run-id|trace> <run-id|trace> [more...] [--flake-budget <pct>]

CI:
  fozzy ci <trace.fozzy> [--flake-run <run-id|trace>]... [--flake-budget <pct>]

DOCTOR:
  fozzy doctor [--deep] [--scenario <path>] [--runs <n>] [--seed <n>] [--json]

GLOBAL FLAGS:
  --config <path>        default: fozzy.toml
  --cwd <path>
  --log <trace|debug|info|warn|error>
  --json                 machine-readable output
  --strict               treat warning-like conditions as errors
  --no-color
