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

## Global Flags

| Flag | Purpose |
|---|---|
| `--config <path>` | Config file path (default: `fozzy.toml`) |
| `--cwd <path>` | Execute in the specified working directory |
| `--log <trace\|debug\|info\|warn\|error>` | Log level |
| `--json` | Emit machine-readable JSON |
| `--strict` | Promote warning-like conditions to failures |
| `--no-color` | Disable ANSI color output |

## Command Surface

| Command | Use When | Example |
|---|---|---|
| `init` | Create project config/scaffold | `fozzy init --template rust` |
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
| `doctor` | Diagnose determinism/env issues | `fozzy doctor --deep --scenario tests/example.fozzy.json` |
| `ci` | Run local gate bundle for a trace | `fozzy ci trace.fozzy --flake-run r1 --flake-run r2 --flake-budget 5` |
| `env` | Print runtime capability info | `fozzy env --json` |
| `version` | Print version/build info | `fozzy version --json` |

## Command Syntax

### `init`

```bash
fozzy init [--force] [--template <rust>]
```

### `test`

```bash
fozzy test [globs...] [--det] [--seed <n>] [--jobs <n>] [--timeout <dur>] \
  [--filter <expr>] [--reporter <json|pretty|junit|html>] \
  [--record <path>] [--record-collision error|overwrite|append] [--fail-fast]
```

`fozzy test` executes Fozzy scenario files. It does not directly launch arbitrary host test commands.

### `run`

```bash
fozzy run <scenario> [--det] [--seed <n>] [--timeout <dur>] \
  [--reporter <json|pretty|junit|html>] \
  [--record <path>] [--record-collision error|overwrite|append]
```

### `fuzz`

```bash
fozzy fuzz <target> [--mode coverage|property] [--seed <n>] [--time <dur>] \
  [--runs <n>] [--max-input <bytes>] [--corpus <dir>] [--mutator <name>] \
  [--shrink] [--record <path>] [--record-collision error|overwrite|append] \
  [--reporter <json|pretty|junit|html>] [--crash-only] [--minimize]
```

### `explore`

```bash
fozzy explore <scenario> [--seed <n>] [--time <dur>] [--steps <n>] [--nodes <n>] \
  [--faults <preset|file>] [--schedule <strategy>] [--checker <name>] \
  [--record <path>] [--record-collision error|overwrite|append] [--shrink] \
  [--reporter <json|pretty|junit|html>] [--minimize]
```

`--schedule`: `fifo | bfs | dfs | random | pct | coverage_guided`  
`--faults` preset: `none | partition-first-two | heal-first-two | crash-first | restart-first`  
`--checker`: `kv_all_equal:<key> | kv_present_on_all:<key> | kv_node_equals:<node>:<key>:<value>`

`--checker` overrides scenario invariants. `kv_all_equal` is evaluated as final-state convergence.

### `replay`

```bash
fozzy replay <trace.fozzy> [--step] [--until <dur>] [--dump-events] [--reporter <json|pretty|junit|html>]
```

### `trace verify`

```bash
fozzy trace verify <trace.fozzy>
```

### `shrink`

```bash
fozzy shrink <trace.fozzy> [--out <trace>] [--budget <dur>] [--aggressive] \
  [--minimize input|schedule|faults|all] [--reporter <json|pretty|junit|html>]
```

### `corpus`

```bash
fozzy corpus list <dir>
fozzy corpus add <dir> <file>
fozzy corpus minimize <dir> [--budget <dur>]
fozzy corpus export <dir> --out <zip>
fozzy corpus import <zip> --out <dir>
```

### `artifacts`

```bash
fozzy artifacts ls <run-id|trace>
fozzy artifacts diff <left-run-id|trace> <right-run-id|trace>
fozzy artifacts export <run-id|trace> --out <dir|zip>
fozzy artifacts pack <run-id|trace> --out <dir|zip>
```

`pack` includes reproducer metadata (`env`, `version`, `commandline`).

### `report`

```bash
fozzy report show <run-id|trace> [--format json|pretty|junit|html]
fozzy report query <run-id|trace> --jq <expr>
fozzy report query <run-id|trace> --list-paths
fozzy report flaky <run-id|trace> <run-id|trace> [more...] [--flake-budget <pct>]
```

`report query --jq` supports path-style selectors (subset):
` .a.b`, `a.b`, `.arr[0]`, `.arr[].field`, `$.a.b`

### `doctor`

```bash
fozzy doctor [--deep] [--scenario <path>] [--runs <n>] [--seed <n>]
```

### `ci`

```bash
fozzy ci <trace.fozzy> [--flake-run <run-id|trace>]... [--flake-budget <pct>]
```

### `env`

```bash
fozzy env
```

### `version`

```bash
fozzy version
```
