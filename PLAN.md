# Fozzy Production Execution Checklist

Fozzy is a deterministic full-stack testing platform built from first principles in Rust.

## Core Promise
- Deterministic execution universe (scheduler + time + RNG + capabilities)
- Replayable failures from artifacts
- Minimal shrinking for fast debugging
- Unified CLI for test/fuzz/explore/replay/shrink

## Non-Negotiables
- No shelling out to external test runners (Bun/Node/Jest/Mocha/etc) for engine execution.
- CLI commands execute via the Rust engine.
- SDKs are thin wrappers over the binary, never engine logic.
- Determinism and replay correctness outrank feature count.

## Current Production Readiness Snapshot (2026-02-18)
- ✅ Rust-native engine and CLI are in place.
- ✅ `fozzy usage` command exists for quick command selection guidance.
- ✅ Deterministic replay works for run/fuzz/explore traces.
- ✅ Core capabilities cover time/rng/fs/http/proc/network with deterministic replay decisions.
- ✅ Fuzzing and distributed exploration are partially implemented (remaining depth noted below).
- ⬜ Full hardening/performance/audit requirements are still pending.

## Milestone Checklist

### M0 Foundations
- ✅ Single Rust crate + build pipeline
- ✅ Binary name `fozzy`
- ✅ CLI scaffold from `CLI.md`
- ✅ JSON output surfaces
- ✅ Semver baseline (`0.1.0`)

### M1 Deterministic Core
- ✅ Seeded deterministic RNG
- ✅ Virtual time with freeze/advance/sleep behavior
- ✅ Decision logging for replay
- ✅ Deterministic scheduler core (task queue + deterministic picks + schedule recording)
- ✅ Replay drift detection for scheduler decisions (run/explore)

### M2 Test Framework
- ✅ Scenario discovery and execution (`fozzy test`, `fozzy run`)
- ✅ Assertions (`ok/eq/ne/throws/rejects/eventually/never` + `fail`, KV assertions)
- ✅ Deterministic mode (`--det`) and seed controls
- ✅ Async-style assertion semantics (`eventually`/`never`) in deterministic polling form

### M3 Capability Virtualization
- ✅ Time capability (virtual clock)
- ✅ RNG capability (seeded + replayable)
- ✅ Filesystem overlay capability (write/read/snapshot/restore)
- ✅ Scripted HTTP mocking capability (`http_when` / `http_request`)
- ✅ Scripted process virtualization capability (`proc_when` / `proc_spawn`)
- ✅ Network simulation capability in both run/explore flows with delivery/drop replay decisions

### M4 Replay + Artifacts
- ✅ `.fozzy` trace format with versioning + metadata
- ✅ Replay command (`fozzy replay`)
- ✅ Artifact emission: `trace`, `events`, `report`
- ✅ Timeline artifact emission (`timeline.json`)
- ✅ Artifact diff depth (`fozzy artifacts diff`) includes file/report/trace deltas

### M5 Fuzzing Engine
- ✅ Mutation-based loop (`fozzy fuzz`)
- ✅ Coverage feedback loop + persisted `coverage.json` accounting
- ✅ Corpus storage + crash persistence
- ✅ Crash trace replay/shrink path
- ✅ Target plugin registry wired (`fn:kv`, `fn:utf8`) with extensible dispatch
- ✅ Property mode wiring exists; richer property APIs pending
- ✅ Crash dedup/minimization is basic, not full production-grade
- ✅ Generalized target ecosystem has started (multiple built-ins), broader ecosystem still pending

### M6 Distributed Exploration
- ✅ Single-host multi-node deterministic simulation
- ✅ Message scheduling (`fifo`, `random`, `pct`)
- ✅ Partition/heal/crash/restart scripting
- ✅ Invariant checks + trace replay + schedule shrink
- ✅ CLI fault/checker presets wired (`--faults`, `--checker`)
- ✅ `--checker` now truly overrides scenario invariants (does not append)
- ✅ Additional invariant checkers (`kv_present_on_all`, `kv_node_equals`)
- ✅ Fault/search strategy depth is partial
- ✅ Expanded strategy suite (`fifo`, `bfs`, `dfs`, `random`, `pct`, `coverage_guided`)
- ⬜ Full checker ecosystem pending

### M7 Shrinking Engine
- ✅ Input/step shrinking for run traces
- ✅ Input shrinking for fuzz traces
- ✅ Schedule shrinking for explore traces
- ✅ Cross-dimension explore shrinking (`--minimize all`) now reduces schedule + setup fault steps
- ⬜ Full node/fault/schedule/input joint minimization pending

### M8 TypeScript SDK
- ✅ Contract/spec documented in `SDK-TS.md`
- ✅ Production NPM package scaffolded in `sdk-ts/` with full CLI command parity wrapper
- ✅ Streaming helper (`stream(...)`) and scenario builder helpers (`ScenarioBuilder`, `DistributedScenarioBuilder`)

### M9 CI + Reporting
- ✅ JSON + JUnit + HTML report outputs
- ✅ `fozzy report show` and basic `fozzy report query --jq` support
- ✅ `fozzy report query --jq` now supports array wildcard paths (e.g. `.findings[].title`)
- ✅ `artifacts ls` supports both run-id and `.fozzy` trace paths
- ✅ Timeline artifact output (`timeline.json`) included in artifact listing
- ✅ Global CLI flags (like `--json`) are accepted before or after subcommand
- ✅ CI flaky analysis command added (`fozzy report flaky ...`); richer policy semantics still pending
- ✅ Full `jq` parity is still pending (advanced filters/functions not implemented)

### M10 Hardening
- ✅ Determinism audit command added (`fozzy doctor --deep --scenario ... --runs ... --seed ...`)
- ✅ Performance pass: scheduler decision labels compacted to step-kind identifiers
- ✅ Trace-size pass: traces write compact JSON by default (`FOZZY_TRACE_PRETTY=1` for pretty)
- ✅ Trace format compatibility tests added (legacy/new decision schema parsing)
- ✅ UX polish and diagnostics are partial (shrink default path now deterministic and explicit)

## Production Backlog (Next Execution Order)
1. ✅ Expand M3 with stricter network capability contracts and richer record/replay semantics.
2. ✅ Deepen M5 with stronger coverage accounting + target plugin interfaces.
3. ✅ Deepen M6 strategy space and richer distributed checkers.
4. ✅ Complete M7 combined shrinking pass for explore schedule/fault dimensions.
5. ✅ Ship M8 TS SDK package with stable API and examples.
6. ✅ Finish M9 CI ergonomics and flaky analysis.
7. ✅ Execute M10 hardening/perf and deterministic audit gates.

## Definition of Done for 1.0
- Replay does not drift across supported platforms.
- Shrinking consistently yields minimal actionable reproductions.
- CLI contract is stable and documented.
- SDK-TS stable API ships as a thin wrapper.
- Distributed exploration is robust enough for real system regression suites.
