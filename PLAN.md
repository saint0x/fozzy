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
- ✅ Hardening wave landed: checksum-backed traces, collision-safe recording, schema warnings on replay.
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
- ✅ `fuzz --record` now emits requested trace path for both pass and fail outcomes
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
- ✅ Schedule consistency fix: replication now uses per-key version ordering to avoid DFS stale-write divergence
- ⬜ Full checker ecosystem pending

### M7 Shrinking Engine
- ✅ Input/step shrinking for run traces
- ✅ Input shrinking for fuzz traces
- ✅ Schedule shrinking for explore traces
- ✅ Cross-dimension explore shrinking (`--minimize all`) now reduces schedule + setup fault steps
- ✅ Shrink status-preservation guard: passing traces stay passing after minimize/replay
- ⬜ Full node/fault/schedule/input joint minimization pending

### M8 TypeScript SDK
- ✅ Contract/spec documented in `SDK-TS.md`
- ✅ Production NPM package scaffolded in `sdk-ts/` with full CLI command parity wrapper
- ✅ Streaming helper (`stream(...)`) and scenario builder helpers (`ScenarioBuilder`, `DistributedScenarioBuilder`)
- ✅ Type-safe SDK pipeline: strict TS config, declaration output (`dist/index.d.ts`), prepack typecheck+build

### M9 CI + Reporting
- ✅ JSON + JUnit + HTML report outputs
- ✅ `fozzy report show` and basic `fozzy report query --jq` support
- ✅ `fozzy report query --jq` now supports array wildcard paths (e.g. `.findings[].title`)
- ✅ `fozzy report query --jq` accepts jq-style path ergonomics (`findings[0].title`, `$.findings[0].title`)
- ✅ `artifacts ls` supports both run-id and `.fozzy` trace paths
- ✅ Timeline artifact output (`timeline.json`) included in artifact listing
- ✅ Global CLI flags (like `--json`) are accepted before or after subcommand
- ✅ `--json` mode now emits JSON error envelopes for CLI parse/usage failures (for example missing required args), not plain-text parse output
- ✅ CI flaky analysis command added (`fozzy report flaky ...`); richer policy semantics still pending
- ✅ Full `jq` parity is still pending (advanced filters/functions not implemented)
- ✅ `report query` now supports `--list-paths` shape introspection
- ✅ Missed `report query` paths now return "did you mean ..." suggestions (for example `identity.runId`)
- ✅ `report flaky` now reports `flakeRatePct` and supports `--flake-budget <pct>` enforcement

### M10 Hardening
- ✅ Determinism audit command added (`fozzy doctor --deep --scenario ... --runs ... --seed ...`)
- ✅ Performance pass: scheduler decision labels compacted to step-kind identifiers
- ✅ Trace-size pass: traces write compact JSON by default (`FOZZY_TRACE_PRETTY=1` for pretty)
- ✅ Trace format compatibility tests added (legacy/new decision schema parsing)
- ✅ UX polish and diagnostics are partial (shrink default path now deterministic and explicit)
- ✅ Deterministic timeout semantics fixed: `--timeout` now applies to virtual elapsed time under `--det`
- ✅ Atomic trace writes prevent concurrent same-path `--record` corruption
- ✅ Explicit `--record-collision=error|overwrite|append` policy on `run/test/fuzz/explore`
- ✅ Deterministic active-writer lock conflict error for same-path `--record`
- ✅ Trace integrity checksum validation on read/replay
- ✅ `fozzy trace verify <path>` integrity + schema warning command
- ✅ Replay now emits explicit stale-schema warnings for older trace versions
- ✅ Artifacts export now fails non-zero when no artifacts are produced or input run/trace is missing
- ✅ Artifacts export ZIP writes are atomic (no empty/corrupt partial output on failure)
- ✅ CI gate added: export artifact ZIP must exist and pass `unzip -t` integrity validation
- ✅ Canonical local gate command added: `fozzy ci <trace>` (trace verify + replay outcome class + artifacts zip integrity + optional flake budget)
- ✅ Deterministic run manifest artifact added: `manifest.json` with fixed schema (`fozzy.run_manifest.v1`) across run modes
- ✅ Reproducer pack export added: `fozzy artifacts pack <run|trace> --out <dir|zip>` including trace/report/events + env/version/commandline metadata
- ✅ `artifacts pack/export --out <dir>` and `corpus import --out <dir>` now preflight all targets so symlink-block failures are atomic (no partial outputs written)
- ✅ `artifacts pack/export` now fail non-zero on incomplete run directories (required bundle files missing) instead of emitting partial bundles
- ✅ Run-id `artifacts pack/export <run>` now honor normal run contracts without requiring `trace.fozzy`/`events.json` (minimum required: `report.json` + valid `manifest.json`)
- ✅ `artifacts pack/export --out <dir>` now reject stale pre-existing unrelated files in output directories (prevents mixed old/new contamination)
- ✅ `artifacts pack/export --out <dir>` now enforce exact-output synchronization by pruning stale pre-existing entries (non-strict and strict modes consistent)
- ✅ `artifacts pack/export` now validate `manifest.json` schema+parse integrity and fail non-zero on corrupted manifest bytes
- ✅ File-output mode (`--out <zip>`) now enforces symlink-safe output path traversal checks (including parent path components)
- ✅ `corpus import` now rejects Windows-style unsafe archive paths (`..\\`, drive-prefixed, UNC-root) on all platforms
- ✅ `corpus import` now rejects unsafe/special archive filenames (control chars, NUL-containing names, Windows-reserved names, trailing-dot/space, cross-platform invalid chars)
- ✅ `corpus import` now rejects NUL-containing raw zip entry names before normalization, preventing ambiguous/truncated filename writes
- ✅ `corpus import` now rejects duplicate archive targets including alias/case-collision forms (for example `dup.bin`, `./dup.bin`, `DUP.BIN`) to prevent silent last-write-wins
- ✅ `corpus import` now preflights raw zip central-directory entries to reject duplicate names and NUL-collision aliases even when archive libraries collapse duplicate headers
- ✅ `corpus import` now refuses overwriting existing output files, preventing duplicate/fallback overwrite behavior during import
- ✅ `corpus export --out <zip>` now rejects symlinked output files and symlinked parent path components (strict and non-strict behavior consistent)
- ✅ `corpus export` now fails non-zero for missing/invalid or empty source corpus directories (no empty zip success artifacts)
- ✅ `corpus export` failure paths are atomic: unreadable source failures do not create output zips and do not clobber pre-existing output files
- ✅ `artifacts pack --out <zip>` is now byte-deterministic for the same run (stable metadata payload and fixed ZIP entry timestamps)
- ✅ CLI contract test matrix expanded across run-like commands, parse failures, and explicit exit-code contract (`0/1/2`)
- ✅ Filesystem chaos/security matrix expanded with host-fs sandbox/path-escape rejection and host-fs execution contract coverage (local test suite)
- ✅ Concurrent stress/repro gates added to local integration suite (`same .fozzy root` multi-run stability checks)
- ✅ `--strict` warning-to-error mode added for run/replay/shrink warning findings, `trace verify`, and `doctor`
- ✅ `trace verify --json --strict` now emits a single final JSON document (error-only on strict failure), preserving machine-parse contract
- ✅ `artifacts pack/export --help` now reflects runtime contract via `RUN_OR_TRACE` argument naming
- ✅ Trace ingest now enforces explicit header compatibility (`format=fozzy-trace`, schema `version` in supported range) for verify/replay/ci, independent of checksum presence
- ✅ Local parity/golden hardening tests added: run-like common flag parsing and end-to-end `record -> replay -> shrink -> replay(min)` for run/fuzz/explore
- ✅ End-to-end golden flows (`record -> replay -> shrink -> replay(min)`) per mode

### M11 Host Capability Execution
- ✅ Added explicit process backend mode (`proc_backend = scripted|host`) with CLI override (`--proc-backend`) and config default
- ✅ Implemented host `proc_spawn` execution path for `fozzy run` / `fozzy test` (non-deterministic mode)
- ✅ Added deterministic safety gate: `--det` + `--proc-backend host` is rejected with explicit error
- ✅ Improved contract/docs/diagnostics for scripted-vs-host proc behavior
- ✅ Added replay/trace semantics for host-proc runs: traces now capture proc result decisions and replay consumes them deterministically; verify warns on legacy host-proc traces without proc decisions
- ✅ Expanded host backend architecture beyond proc:
  - ✅ Host FS backend (`--fs-backend host`) with cwd-root sandboxing and explicit path-escape rejection
  - ✅ Host HTTP backend (`--http-backend host`) now supports both `http://` and `https://` endpoints with deterministic replay decisions
  - ✅ HTTP DSL expanded for production assertions: `http_request.headers` (request headers) and `http_request.expect_headers` / `http_when.headers` (response headers)
  - ✅ Determinism contracts enforced (`--det` rejects host fs/http/proc backends with explicit errors)
  - ✅ Replay contracts enforced for host execution (proc/http decision capture + legacy warning diagnostics)

### M12 Memory Mode (Deterministic Memory Correctness Engine)
- ⬜ Memory capability contract finalized (`memory` as first-class runtime capability, deterministic-first, replay-first)
- ⬜ Schema strategy finalized (trace + report + manifest + memory artifacts versioning)
- ⬜ Deterministic memory execution contract implemented:
  - ⬜ Allocation order determinism
  - ⬜ Leak determinism
  - ⬜ OOM determinism
  - ⬜ Shrink determinism

#### M12.1 Deterministic Tracking Foundation
- ⬜ Runtime memory state integrated into core execution context (`ExecCtx`) without breaking existing capability patterns
- ⬜ Deterministic allocation id generation + callsite hashing
- ⬜ Allocation lifetime recording (alloc/free/in-use/peak)
- ⬜ Seed-stable allocation ordering preserved under replay
- ⬜ Memory counters surfaced in `report.json` and `manifest.json`
- ⬜ `memory.timeline.json` artifact emitted with stable ordering + schema tag

#### M12.2 Deterministic Leak Detection
- ⬜ End-of-run leak accounting implemented and replay-stable
- ⬜ Leak findings integrated with existing finding taxonomy and strict-mode semantics
- ⬜ Leak budget policy implemented (`--leak-budget`)
- ⬜ Leak hard-fail policy implemented (`--fail-on-leak`)
- ⬜ `memory.leaks.json` artifact emitted and included in artifacts list/export/pack
- ⬜ CI/report integration:
  - ⬜ `fozzy ci` checks include deterministic leak policy when memory mode is enabled
  - ⬜ `fozzy report` surfaces leak counts and budget status

#### M12.3 Deterministic Memory Pressure + OOM Injection
- ⬜ Virtual memory ceiling support (`--mem-limit-mb`) implemented and replay-stable
- ⬜ Allocation failure scripting (`--mem-fail-after`) implemented and replay-stable
- ⬜ Runtime API hooks for memory pressure behavior implemented
- ⬜ Replay drift detection includes memory-failure decision mismatches
- ⬜ Deterministic/host-mode contracts documented and enforced

#### M12.4 Memory-Aware Shrinking
- ⬜ Shrink objective extended to preserve leak/non-leak outcome class
- ⬜ Leak-minimal reproduction strategy implemented
- ⬜ Memory delta comparison artifact added (`memory.delta.json`)
- ⬜ Shrink output remains replayable and deterministic
- ⬜ Existing shrink behavior for non-memory traces remains unchanged

#### M12.5 Memory Forensics Artifacts
- ⬜ Allocation graph model implemented
- ⬜ `memory.graph.json` artifact emitted with stable deterministic node/edge ordering
- ⬜ Artifact diff/export/pack support includes memory graph + memory deltas
- ⬜ Artifact schema docs published for all memory artifact types

#### M12.6 Memory Pressure Fuzzing / Explore Integration
- ⬜ Fuzz mode integrates memory pressure controls without replay drift
- ⬜ Explore mode supports deterministic memory pressure fault scheduling
- ⬜ Fragmentation/pressure-wave controls designed and shipped behind explicit flags
- ⬜ Coverage/checker model extended for memory-pressure outcomes

#### M12.7 CLI / SDK / Docs Parity
- ⬜ CLI flags shipped and documented:
  - ⬜ `--mem-track`
  - ⬜ `--mem-limit-mb`
  - ⬜ `--mem-fail-after`
  - ⬜ `--fail-on-leak`
  - ⬜ `--leak-budget`
  - ⬜ `--mem-artifacts`
- ⬜ `fozzy usage`, `CLI.md`, `README.md`, and scenario docs updated
- ⬜ TS SDK parity shipped (`sdk-ts/` and `SDK-TS.md`) for all new memory controls

#### M12.8 Verification / Hardening Gate (Production)
- ⬜ Unit tests:
  - ⬜ allocator determinism
  - ⬜ leak accounting correctness
  - ⬜ OOM/fail-after determinism
  - ⬜ trace/report/artifact serde compatibility
- ⬜ Integration tests:
  - ⬜ golden flow coverage for memory run/test/fuzz/explore paths
  - ⬜ CLI parity tests for all memory flags and strict-mode behaviors
  - ⬜ artifacts list/diff/export/pack coverage for memory artifacts
- ⬜ Determinism audit command gates added for memory scenarios
- ⬜ End-to-end required gate sequence for memory shipping:
  - ⬜ `fozzy doctor --deep --scenario <memory_scenario> --runs 5 --seed <seed> --json`
  - ⬜ `fozzy test --det --strict <memory_scenarios...> --json`
  - ⬜ `fozzy run <memory_scenario> --det --record <trace.fozzy> --json`
  - ⬜ `fozzy trace verify <trace.fozzy> --strict --json`
  - ⬜ `fozzy replay <trace.fozzy> --json`
  - ⬜ `fozzy ci <trace.fozzy> --json`
- ⬜ Host-backed runtime checks executed where feasible for delivery confidence:
  - ⬜ `fozzy run ... --proc-backend host --fs-backend host --http-backend host --json`

## Production Backlog (Next Execution Order)
1. ⬜ Execute M12.1 deterministic memory tracking foundation.
2. ⬜ Execute M12.2 deterministic leak detection + CI/report policy integration.
3. ⬜ Execute M12.3 memory pressure limits + deterministic OOM injection.
4. ⬜ Execute M12.4 memory-aware shrinking (`memory.delta.json`) with replay-preservation checks.
5. ⬜ Execute M12.5 memory forensic artifacts (`memory.graph.json`) + artifact tooling parity.
6. ⬜ Execute M12.6 fuzz/explore memory-pressure integration.
7. ⬜ Execute M12.7 CLI/SDK/docs parity.
8. ⬜ Execute M12.8 hardening gate and production release criteria.

## Definition of Done for 1.0
- Replay does not drift across supported platforms.
- Shrinking consistently yields minimal actionable reproductions.
- CLI contract is stable and documented.
- SDK-TS stable API ships as a thin wrapper.
- Distributed exploration is robust enough for real system regression suites.

## Definition of Done for Memory Mode v1
- Deterministic allocation tracking is replay-stable across supported platforms.
- Leak outcomes are reproducible and enforceable in CI (`--fail-on-leak` / `--leak-budget`).
- Memory artifacts are stable, schema-versioned, diffable, and included in artifact workflows.
- Shrinking preserves memory outcome class and produces smaller actionable leak repro traces.
- Trace/replay/verify/ci flows reject or warn on memory-schema drift using existing strict-mode policy.
