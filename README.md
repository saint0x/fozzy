# Fozzy

Fozzy is a deterministic testing engine for systems code.
It provides one Rust-native runtime and one CLI for test execution, fuzzing, distributed schedule exploration, replay, and shrinking.

## Why use Fozzy

Fozzy is designed to catch and debug high-cost failures that traditional test runners miss:

- Nondeterministic failures: order/race behavior that is hard to reproduce.
- Distributed consistency bugs: partition/heal/crash/restart edge cases.
- Timeout and hang regressions: deterministic virtual-time validation.
- Flakiness drift: run-set variance and flake-budget policy gates.
- Input robustness bugs: malformed inputs and mutation-discovered crashes.
- Replay drift: when a recorded failure no longer reproduces exactly.
- Artifact integrity problems: corrupted traces, invalid checksums, broken exports.

Result: every failure can be recorded, replayed, minimized, and shared as a reproducible artifact.

## Core Guarantees

- Deterministic runtime in `--det` mode (seeded RNG, virtual time, decision logging).
- Replay-safe trace model (`.fozzy`) with schema/version + checksum integrity support.
- Strict mode (`--strict`) to promote warning-like conditions to hard failures.
- Atomic artifact writes and collision-safe recording policies.
- Machine-readable JSON outputs across run, replay, report, and CI gating flows.
- Deterministic memory correctness mode (`--mem-track`) with leak budgets and replayable memory artifacts.

## Runtime Backends

Fozzy uses deterministic-first capability backends, with host execution available explicitly when needed.

- Process:
`scripted` (`proc_when` + `proc_spawn`) by default, optional host mode via `--proc-backend host`.
- Filesystem:
`virtual` overlay by default, optional host mode via `--fs-backend host` (cwd-root sandboxed).
- HTTP:
`scripted` (`http_when` + `http_request`) by default, optional host mode via `--http-backend host`.
`http_request` supports request headers and response-header assertions (`expect_headers`) in both scripted and host modes.
Host HTTP backend supports both `http://` and `https://` endpoints.

Host backends are non-deterministic execution modes and are rejected with `--det`.
Host proc/http outcomes are captured as replay decisions so `fozzy replay` remains deterministic.

Inspect active runtime capabilities with:

```bash
fozzy env --json
```

## CLI Surface

- `fozzy test`: execute scenario suites.
- `fozzy run`: execute a single scenario.
- `fozzy fuzz`: mutation/property fuzzing.
- `fozzy explore`: deterministic distributed schedule/fault exploration.
- `fozzy replay`: reproduce a recorded trace.
- `fozzy shrink`: minimize failing traces.
- `fozzy ci`: local gate bundle (verify + replay + artifact integrity + optional flake budget).
- `fozzy report`: render/query reports.
- `fozzy memory`: inspect memory graphs, leak tops, and memory diffs.
- `fozzy artifacts`: list/export/pack run artifacts.
- `fozzy map`: language-agnostic code topology mapping for hotspot-driven suite planning.

Full command contract: [CLI.md](CLI.md)

## Quickstart

```bash
fozzy init --force
fozzy run tests/example.fozzy.json --det --json
```

Record/replay/shrink flow:

```bash
fozzy run fixtures/fail.fozzy.json --det --json
fozzy replay .fozzy/runs/<runId>/trace.fozzy --json
fozzy shrink .fozzy/runs/<runId>/trace.fozzy --minimize all --json
```

Gate a trace before merge:

```bash
fozzy ci .fozzy/runs/<runId>/trace.fozzy --json
```

Strict integrity check:

```bash
fozzy --strict trace verify .fozzy/runs/<runId>/trace.fozzy --json
```

## Install (dev)

```bash
cargo install --path .
fozzy version --json
```

## Repository Docs

- [CLI.md](CLI.md): complete command contract

## License

MIT (see `LICENSE`).
