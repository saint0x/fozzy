# Fozzy

Deterministic full-stack testing: test, replay, shrink, fuzz, and distributed exploration via one engine and one CLI.

Status: pre-1.0. This repository is being implemented from [PLAN.md](PLAN.md).

## What Bugs Fozzy Catches

Fozzy is built to catch high-cost bugs that normal unit/integration runs miss:

- Nondeterministic failures: race/order bugs that pass once and fail once.
- Distributed consistency bugs: partition/heal/crash/restart edge cases.
- Timeout and hang regressions: deterministic virtual-time and replayed schedule checks.
- Flaky test behavior: run-set variance and flake budget enforcement.
- Input robustness bugs: malformed input, parser edge cases, and fuzz-discovered crashes.
- Replay drift: cases where a recorded failure no longer reproduces exactly.
- Artifact integrity issues: corrupted traces, missing checksums (in strict mode), broken exports.

Outcome: failures are reproducible, shrinkable, and diagnosable, so teams spend less time on “cannot reproduce” and more time fixing root cause.

## Execution Scope

Fozzy is a deterministic scenario engine, not a drop-in executor for arbitrary repo test commands.

- `proc` is currently scripted (`proc_when` + `proc_spawn`), not host process execution.
- `http` is currently scripted (`http_when` + `http_request`), not live outbound HTTP.
- `fs` uses deterministic virtual overlay semantics.

Use `fozzy env --json` to inspect active capability backends.

## Test Modes

- `fozzy test`: scenario suite execution for normal CI pipelines (scenario files, not direct shell/cargo/jest command execution).
- `fozzy run`: single-scenario deterministic debug loop.
- `fozzy fuzz`: coverage/property fuzzing with trace capture and shrink.
- `fozzy explore`: schedule/fault exploration for distributed scenarios.
- `fozzy replay`: exact failure reproduction from a `.fozzy` trace.
- `fozzy shrink`: minimization to smallest actionable reproducer.
- `fozzy ci`: canonical gate bundle for trace verify + replay + export integrity (+ optional flake budget).

## Install (dev)

```bash
cargo install --path .
fozzy version --json
```

## Quickstart

Initialize a project and run the example scenario:

```bash
fozzy init --force
fozzy run tests/example.fozzy.json --det --json
```

Record a trace on failure, then replay and shrink it:

```bash
fozzy run tests/fail.fozzy.json --det --json
fozzy replay .fozzy/runs/<runId>/trace.fozzy --json
fozzy shrink .fozzy/runs/<runId>/trace.fozzy --minimize all --json
```

Run a local production-style gate for a trace:

```bash
fozzy ci .fozzy/runs/<runId>/trace.fozzy --json
```

Verify trace integrity and enforce strict checksum/warning policy:

```bash
fozzy --strict trace verify .fozzy/runs/<runId>/trace.fozzy --json
```

Create a reproducer bundle (trace/report/events + env/version/commandline):

```bash
fozzy artifacts pack .fozzy/runs/<runId>/trace.fozzy --out repro.zip --json
```

## CLI

The canonical CLI surface is documented in [CLI.md](CLI.md).

## Repo Docs

- [PLAN.md](PLAN.md): execution plan / milestones
- [RUST-STYLE-GUIDE.md](RUST-STYLE-GUIDE.md): Rust conventions for this codebase
- [SDK-TS.md](SDK-TS.md): TypeScript SDK contract (thin wrapper over the binary)
- [sdk-ts/](sdk-ts/): production TypeScript SDK package scaffold (`fozzy-sdk`)

## License

MIT (see `LICENSE`).
