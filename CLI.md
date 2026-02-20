# Fozzy CLI

Deterministic full-stack testing, fuzzing, replay, shrinking, and distributed fault exploration.

## Quick Start

```bash
fozzy init
fozzy test tests/**/*.fozzy.json --det --seed 7
fozzy run tests/example.fozzy.json --record run.fozzy
fozzy replay run.fozzy --json
```

## Usage

```bash
fozzy [GLOBAL_FLAGS] <COMMAND> [ARGS] [COMMAND_FLAGS]
```

Global flags can be placed before or after subcommands.
Strict mode is enabled by default; pass `--unsafe` to opt out.
Execution policy: use the full command surface by default. Skip commands only when the target system truly does not have the required scope/inputs.

## Global Flags

| Flag | Purpose |
|---|---|
| `--config <path>` | Config file path (default: `fozzy.toml`) |
| `--cwd <path>` | Execute in the specified working directory |
| `--log <trace\|debug\|info\|warn\|error>` | Log level |
| `--proc-backend <scripted\|host>` | Process backend for `proc_spawn` (default from config: `scripted`) |
| `--fs-backend <virtual\|host>` | Filesystem backend for `fs_*` steps (default from config: `virtual`) |
| `--http-backend <scripted\|host>` | HTTP backend for `http_*` steps (default from config: `scripted`) |
| `--json` | Emit machine-readable JSON |
| `--strict` | Keep strict mode enabled (default behavior) |
| `--unsafe` | Opt out of strict mode and run relaxed checks |
| `--no-color` | Disable ANSI color output |

## Command Surface

| Command | Use When | Example |
|---|---|---|
| `init` | Create project config/scaffold (with test-type starters) | `fozzy init --template rust --with run,memory,explore,fuzz,host` |
| `full` | Run the complete command-surface gate with guidance and graceful skips | `fozzy full --scenario-root tests --seed 7` |
| `test` | Run suites/globs of scenarios | `fozzy test tests/**/*.fozzy.json --det` |
| `run` | Run one scenario directly | `fozzy run tests/example.fozzy.json` |
| `fuzz` | Mutation/property fuzzing | `fozzy fuzz fn:utf8 --runs 1000` |
| `explore` | Distributed schedules + faults | `fozzy explore tests/kv.explore.fozzy.json --schedule bfs` |
| `replay` | Deterministically replay a trace | `fozzy replay .fozzy/runs/<runId>/trace.fozzy` |
| `trace verify` | Verify trace checksum/schema | `fozzy trace verify trace.fozzy --json` |
| `shrink` | Minimize a recorded trace | `fozzy shrink trace.fozzy --minimize all` |
| `corpus` | Manage fuzz corpus files | `fozzy corpus export .fozzy/corpus --out corpus.zip` |
| `artifacts` | List/diff/export run artifacts | `fozzy artifacts pack <runId> --out pack.zip` |
| `report` | Render/query reports | `fozzy report show <runId> --format json` |
| `memory` | Inspect memory graph/diff/top leaks | `fozzy memory top <runId|trace>` |
| `map` | Build language-agnostic topology/hotspot/suite maps | `fozzy map suites --root . --scenario-root tests --json` |
| `doctor` | Diagnose determinism/env issues | `fozzy doctor --deep --scenario tests/example.fozzy.json` |
| `ci` | Run local gate bundle for a trace | `fozzy ci trace.fozzy --flake-run r1 --flake-run r2 --flake-budget 5` |
| `env` | Print runtime capability info | `fozzy env --json` |
| `version` | Print version/build info | `fozzy version --json` |
| `schema` | Print supported scenario file/step schema (`steps` alias) | `fozzy schema --json` |
| `validate` | Validate scenario parse/shape with diagnostics | `fozzy validate tests/example.fozzy.json --json` |

## Command Syntax

### `init`

```bash
fozzy init [--force] [--template <rust|ts|minimal>] \
  [--with <run,fuzz,explore,memory,host,all>] [--all-tests]
```

By default, `fozzy init` scaffolds all test types (`all`) so projects run out of the box.
Use `--with` to explicitly select scaffold types.
Generated files include starter scenarios plus `tests/INIT_GUIDE.md` with commands and setup guidance.

### `full`

```bash
fozzy full [--scenario-root <dir>] [--seed <n>] [--doctor-runs <n>] \
  [--fuzz-time <dur>] [--explore-steps <n>] [--explore-nodes <n>] \
  [--allow-expected-failures] [--scenario-filter <substring>] \
  [--skip-steps <comma,list>] [--required-steps <comma,list>] \
  [--require-topology-coverage <repo_root>] [--topology-min-risk <0..100>] \
  [--topology-profile <balanced|pedantic|overkill>]
```

`fozzy full` is the hand-holding end-to-end gate. It targets the full CLI surface:
`init`, `test`, `run`, `fuzz`, `explore`, `replay`, `trace verify`, `shrink`, `corpus`, `artifacts`, `report`, `memory`, `doctor`, `ci`, `env`, `version`, `usage`.
If a required input is missing (for example no distributed scenario), it records a graceful skip instead of crashing.
Use `--allow-expected-failures` for mixed pass/fail scenario roots where fail-class replay parity is expected, and use `--scenario-filter`/step policies to scope CI contracts.
Use `--require-topology-coverage` to enforce that high-risk hotspot areas from `fozzy map suites` have matching scenario coverage. Topology profile defaults to `pedantic`.
Strictest setting suggestion: strict mode is already on by default; pass `--unsafe` only when intentionally relaxing checks.

### `test`

```bash
fozzy test [globs...] [--det] [--seed <n>] [--jobs <n>] [--timeout <dur>] \
  [--filter <expr>] [--reporter <json|pretty|junit|html>] \
  [--record <path>] [--record-collision error|overwrite|append] [--fail-fast] \
  [--mem-track] [--mem-limit-mb <n>] [--mem-fail-after <n>] \
  [--mem-fragmentation-seed <n>] [--mem-pressure-wave <pattern>] \
  [--fail-on-leak] [--leak-budget <bytes>] [--mem-artifacts]
```

`fozzy test` executes Fozzy scenario files. It does not directly launch arbitrary host test commands.
For host execution, use `--proc-backend host`, `--fs-backend host`, and/or `--http-backend host` (non-deterministic mode only). Host-process and host-http responses are captured as replay decisions so `fozzy replay` remains deterministic.
`http_request` supports request `headers` and response `expect_headers` assertions.
Strictest setting suggestion: strict mode is already on by default; pass `--unsafe` only when intentionally relaxing checks.

### `run`

```bash
fozzy run <scenario> [--det] [--seed <n>] [--timeout <dur>] \
  [--reporter <json|pretty|junit|html>] \
  [--record <path>] [--record-collision error|overwrite|append] \
  [--mem-track] [--mem-limit-mb <n>] [--mem-fail-after <n>] \
  [--mem-fragmentation-seed <n>] [--mem-pressure-wave <pattern>] \
  [--fail-on-leak] [--leak-budget <bytes>] [--mem-artifacts]
```
Strictest setting suggestion: strict mode is already on by default; pass `--unsafe` only when intentionally relaxing checks.

### `fuzz`

```bash
fozzy fuzz <target> [--mode coverage|property] [--seed <n>] [--time <dur>] \
  [--runs <n>] [--max-input <bytes>] [--corpus <dir>] [--mutator <name>] \
  [--shrink] [--record <path>] [--record-collision error|overwrite|append] \
  [--reporter <json|pretty|junit|html>] [--crash-only] [--minimize] \
  [--mem-track] [--mem-limit-mb <n>] [--mem-fail-after <n>] \
  [--mem-fragmentation-seed <n>] [--mem-pressure-wave <pattern>] \
  [--fail-on-leak] [--leak-budget <bytes>] [--mem-artifacts]
```
Strictest setting suggestion: strict mode is already on by default; pass `--unsafe` only when intentionally relaxing checks.

### `explore`

```bash
fozzy explore <scenario> [--seed <n>] [--time <dur>] [--steps <n>] [--nodes <n>] \
  [--faults <preset|file>] [--schedule <strategy>] [--checker <name>] \
  [--record <path>] [--record-collision error|overwrite|append] [--shrink] \
  [--reporter <json|pretty|junit|html>] [--minimize] \
  [--mem-track] [--mem-limit-mb <n>] [--mem-fail-after <n>] \
  [--mem-fragmentation-seed <n>] [--mem-pressure-wave <pattern>] \
  [--fail-on-leak] [--leak-budget <bytes>] [--mem-artifacts]
```

`--schedule`: `fifo | bfs | dfs | random | pct | coverage_guided`  
`--faults` preset: `none | partition-first-two | heal-first-two | crash-first | restart-first`  
`--checker`: `kv_all_equal:<key> | kv_present_on_all:<key> | kv_node_equals:<node>:<key>:<value>`

`--checker` overrides scenario invariants. `kv_all_equal` is evaluated as final-state convergence.
Strictest setting suggestion: strict mode is already on by default; pass `--unsafe` only when intentionally relaxing checks.

### `replay`

```bash
fozzy replay <trace.fozzy> [--step] [--until <dur>] [--dump-events] [--reporter <json|pretty|junit|html>]
```
Strictest setting suggestion: strict mode is already on by default; pass `--unsafe` only when intentionally relaxing checks.

### `trace verify`

```bash
fozzy trace verify <trace.fozzy>
```
Strictest setting suggestion: strict mode is already on by default; pass `--unsafe` only when intentionally relaxing checks.

### `shrink`

```bash
fozzy shrink <trace.fozzy> [--out <trace>] [--budget <dur>] [--aggressive] \
  [--minimize input|schedule|faults|all] [--reporter <json|pretty|junit|html>]
```
Strictest setting suggestion: strict mode is already on by default; pass `--unsafe` only when intentionally relaxing checks.

### `corpus`

```bash
fozzy corpus list <dir>
fozzy corpus add <dir> <file>
fozzy corpus minimize <dir> [--budget <dur>]
fozzy corpus export <dir> --out <zip>
fozzy corpus import <zip> --out <dir>
```
Strictest setting suggestion: strict mode is already on by default; pass `--unsafe` only when intentionally relaxing checks.

### `artifacts`

```bash
fozzy artifacts ls <run-id|trace>
fozzy artifacts diff <left-run-id|trace> <right-run-id|trace>
fozzy artifacts export <run-id|trace> --out <dir|zip>
fozzy artifacts pack <run-id|trace> --out <dir|zip>
```

`pack` includes reproducer metadata (`env`, `version`, `commandline`).
Run selectors also support aliases: `latest`, `last-pass`, `last-fail`.
For race-sensitive CI automation, prefer explicit `runId` or trace paths over aliases.
Strictest setting suggestion: strict mode is already on by default; pass `--unsafe` only when intentionally relaxing checks.

### `report`

```bash
fozzy report show <run-id|trace> [--format json|pretty|junit|html]
fozzy report query <run-id|trace> --jq <expr>
fozzy report query <run-id|trace> --list-paths
fozzy report flaky <run-id|trace> <run-id|trace> [more...] [--flake-budget <pct>]
```

`report query --jq` supports path-style selectors (subset):
` .a.b`, `a.b`, `.arr[0]`, `.arr[].field`, `$.a.b`
Run selectors also support aliases: `latest`, `last-pass`, `last-fail`.
For race-sensitive CI automation, prefer explicit `runId` or trace paths over aliases.
Strictest setting suggestion: strict mode is already on by default; pass `--unsafe` only when intentionally relaxing checks.

### `memory`

```bash
fozzy memory graph <run-id|trace> [--out <path>]
fozzy memory diff <left-run-id|trace> <right-run-id|trace>
fozzy memory top <run-id|trace> [--limit <n>]
```

Strictest setting suggestion: strict mode is already on by default; pass `--unsafe` only when intentionally relaxing checks.
Run selectors also support aliases: `latest`, `last-pass`, `last-fail`.
For race-sensitive CI automation, prefer explicit `runId` or trace paths over aliases.

### `map`

```bash
fozzy map hotspots [--root <repo>] [--min-risk <0..100>] [--limit <n>]
fozzy map services [--root <repo>]
fozzy map suites [--root <repo>] [--scenario-root <dir>] [--min-risk <0..100>] [--profile <balanced|pedantic|overkill>] [--limit <n>]
```

`map` is language-agnostic and derives risk hotspots from control-flow density, concurrency indicators, external side-effect boundaries, failure/timeout/retry logic, and entrypoint/service signals.
Use `map suites` to find high-risk hotspots lacking dedicated scenario coverage and drive granular Fozzy suite generation.
`map suites` defaults to `--profile pedantic` (safer-by-default over-spec bias).

### `doctor`

```bash
fozzy doctor [--deep] [--scenario <path>] [--runs <n>] [--seed <n>]
```
Strictest setting suggestion: strict mode is already on by default; pass `--unsafe` only when intentionally relaxing checks.

### `ci`

```bash
fozzy ci <trace.fozzy> [--flake-run <run-id|trace>]... [--flake-budget <pct>]
```
Strictest setting suggestion: strict mode is already on by default; pass `--unsafe` only when intentionally relaxing checks.

### `env`

```bash
fozzy env
```

### `version`

```bash
fozzy version
```

### `schema`

```bash
fozzy schema
```

Prints a machine-readable scenario surface:
- top-level file variants (`steps`, `distributed`, `suites`)
- supported `steps[].type` values
- supported distributed step and invariant types
Alias: `fozzy steps --json`.
Strictest setting suggestion: strict mode is already on by default; pass `--unsafe` only when intentionally relaxing checks.

### `validate`

```bash
fozzy validate <scenario.fozzy.json>
```

Validates parse + step-shape semantics and returns non-zero on invalid scenarios.
Strictest setting suggestion: strict mode is already on by default; pass `--unsafe` only when intentionally relaxing checks.
