Fozzy — Execution Plan

Fozzy is a deterministic, full-stack testing platform combining:
  • Normal test framework
  • Deterministic replay
  • Fuzzing (coverage + property)
  • Distributed systems exploration
  • Fault injection
  • Perfect mocking via capability virtualization

This document defines the full build plan, execution order, and engineering checkpoints.

Related docs:
  • CLI.md → canonical CLI surface and contract
  • SDK-TS.md → TypeScript SDK wrapping the binary

⸻

Implementation Status (as of 2026-02-18)

This repo is actively implementing this plan. Current state:

Completed / working (v0.1)
  • Single Rust crate (`src/`), shipping a `fozzy` binary
  • CLI scaffold (init/test/run/replay/shrink/corpus/artifacts/report/doctor/env/version/usage)
  • Deterministic core (seeded RNG + virtual time + decision log)
  • Test execution is Rust-native (no shell-out to Bun/Node/Jest/Mocha/etc)
  • Trace recording (.fozzy JSON) on failure or explicit `--record`
  • Deterministic replay from trace + basic artifacts (report.json, events.json, trace.fozzy)
  • Basic shrinking (step deletion shrink for scenario traces)
  • JUnit + HTML report rendering (minimal)
  • `fozzy usage` agent-oriented “what to use when” overview
  • Basic fuzzing loop (`fozzy fuzz fn:kv`): mutation + simple coverage feedback + crash recording + replay/shrink
  • Capability virtualization (partial): deterministic virtual filesystem overlay steps (fs write/read/snapshot/restore)
  • Deterministic distributed exploration (partial): `fozzy explore` multi-node single-host simulation with FIFO/random schedules + trace record/replay + basic schedule shrinking

Not yet implemented (planned)
  • Full coverage-guided fuzzing + crash dedup (M5)
  • Distributed exploration runner (M6)
  • Multi-dimensional shrinking (input + schedule + faults) (M7)
  • Full capability virtualization (net/fs/http/proc record+replay) (M3)
  • TS SDK packaging (M8)
  • CI polish + flaky detection + stable exit semantics across all modes (M9)
  • Hardening/perf/determinism audits (M10)

Milestones (tracked)
  • M0 Foundations: DONE (repo, build, CLI skeleton, JSON output, semver)
  • M1 Deterministic Core: PARTIAL (RNG/time/decision log/record+replay; scheduler not yet)
  • M2 Test Framework: PARTIAL (scenario runner + assertions; full discovery DSL not yet)
  • M3 Capabilities: PARTIAL (virtual fs overlay; net/http/proc not yet)
  • M4 Replay + Artifacts: PARTIAL (trace/events/report; timeline/diffs not yet)
  • M5 Fuzzing Engine: PARTIAL (basic mutation+feedback loop; target system not yet generalized)
  • M6 Distributed Explore: PARTIAL (single-host simulation; message schedule exploration + partitions/crash scripting; full fault space + strategies not yet)
  • M7 Shrinking Engine: PARTIAL (basic step shrink only)
  • M8 TypeScript SDK: NOT DONE (spec exists in SDK-TS.md)
  • M9 CI + Reporting: PARTIAL (JUnit/HTML emitted; CI UX not yet complete)
  • M10 Hardening: NOT DONE

⸻

0. Goals

Primary Goal

Ship a deterministic testing platform that developers trust as a single tool for:
  • Unit tests
  • Integration tests
  • Fuzzing
  • Distributed correctness testing
  • Reproducible debugging

Secondary Goals
  • Deterministic replay for all failures
  • Minimal repro shrinking
  • Batteries-included mocking
  • CI-native ergonomics
  • Rust-first core, multi-language SDKs

⸻

1. Non-Goals (v1)

To avoid scope explosion:
  • No Kubernetes-native runner (v1)
  • No browser UI (CLI + HTML reports only)
  • No native Windows engine support (CLI may work)
  • No plugin marketplace
  • No distributed multi-machine engine (single host only)

⸻

2. Core Product Philosophy

Fozzy is not just a fuzzer.

It is:

A deterministic execution universe that testing modes plug into.

Everything is built on one runtime:
  • Deterministic scheduler
  • Virtual time
  • Deterministic RNG
  • Controlled IO capabilities
  • Record/replay engine

All higher-level features are thin layers on top of this runtime.

Production Constraint (Non-Negotiable)
  • No shelling out to external test runners (Bun/Node/Jest/Mocha/etc) under the hood.
  • `fozzy test`/`fozzy run`/`fozzy fuzz`/`fozzy explore` must execute via the Rust engine from first principles.
  • SDKs may spawn the `fozzy` binary, but must never implement engine logic.

⸻

3. Architecture Overview

                ┌─────────────────────────┐
                │       SDKs (TS, etc)   │
                │  thin wrappers over CLI│
                └────────────┬───────────┘
                             │
                    ┌────────▼────────┐
                    │     CLI Layer   │
                    │  (argument DSL) │
                    └────────┬────────┘
                             │
                ┌────────────▼────────────┐
                │    Execution Engine     │
                │ deterministic universe  │
                └───────┬────────┬───────┘
                        │        │
         ┌──────────────▼──┐  ┌──▼──────────────┐
         │  Runners         │  │  Capabilities   │
         │ test/fuzz/explore│  │ net/fs/time/... │
         └──────────────┬──┘  └───────────────┬┘
                        │                     │
                  ┌─────▼─────┐       ┌──────▼──────┐
                  │ Record/    │       │ Checkers     │
                  │ Replay     │       │ invariants   │
                  └────────────┘       └──────────────┘


⸻

4. Milestone Overview

Milestone Name  Outcome
M0  Foundations Repo + build + CLI scaffold
M1  Deterministic Core  Replayable execution universe
M2  Test Framework  Normal testing + assertions
M3  Capabilities  Mockable IO abstraction layer
M4  Replay + Artifacts  Full repro pipeline
M5  Fuzzing Engine  Coverage + property fuzzing
M6  Distributed Explore Multi-node deterministic testing
M7  Shrinking Minimal repro generation
M8  TS SDK  Production-ready SDK
M9  CI + Reports  Adoption-ready tooling
M10 Hardening Stability + performance


⸻

5. Detailed Execution Plan

⸻

M0 — Foundations

Objectives
  • Create a stable development base
  • Lock CLI contracts early

Checklist
  • Repo structure finalized
  • Rust workspace layout
  • Binary name reserved (fozzy)
  • CLI skeleton matching CLI.md
  • JSON output contract defined
  • Versioning scheme (semver)

Repo Layout

/engine
/cli
/runtime
/capabilities
/checkers
/reporting
/sdk-ts
/docs

Deliverable
  • CLI commands compile but stubbed

⸻

M1 — Deterministic Core

This is the most important milestone.

Objectives

Build the deterministic execution universe.

Components

Deterministic RNG
  • Seeded global RNG
  • Forkable streams
  • Stable cross-platform behavior

Virtual Time
  • Logical clock
  • Deterministic timers
  • Time freeze/advance

Scheduler
  • Deterministic task queue
  • Instrumented yield points
  • Schedule recording

Decision Log
  • All nondeterministic decisions logged
  • Replay fidelity guarantees

Deliverable
  • Deterministic runs with perfect replay

⸻

M2 — Test Framework

Objectives

Make Fozzy usable as a normal test runner.

Features
  • Test discovery
  • Assertions
  • Async test support
  • Parallel test execution
  • Deterministic mode toggle

Assertions
  • eq / ne
  • ok
  • throws
  • rejects
  • eventually / never

Deliverable

`fozzy test` replaces Jest/Mocha for early adopters (without invoking them internally).

⸻

M3 — Capability System

Objective

Enable perfect mocking via capability virtualization.

Capabilities (v1)
  • Time
  • RNG
  • Network (simulated)
  • HTTP scripting
  • Filesystem overlay
  • Process spawning

Requirements
  • Deterministic behavior
  • Scriptable mocks
  • Record/replay compatibility

Deliverable

“Mock anything” milestone achieved.

⸻

M4 — Replay + Artifacts

Objectives

Make debugging magical.

Features
  • Trace recording format (.fozzy)
  • Deterministic replay engine
  • Timeline generation
  • Event logs
  • Artifact export

Artifacts
  • trace
  • timeline
  • structured events
  • failure report

Deliverable

One-line repro guarantee:

fozzy replay trace.fozzy


⸻

M5 — Fuzzing Engine

Objectives

Add mutation-based discovery.

Features
  • Byte-level mutators
  • Structured mutators (JSON)
  • Property testing mode
  • Corpus storage
  • Crash deduplication

CLI
  • fozzy fuzz
  • fozzy corpus

Deliverable

Coverage-guided fuzzing operational.

⸻

M6 — Distributed Exploration

Objectives

Fozzy becomes category-defining here.

Features
  • Multi-node simulation runner
  • Deterministic network transport
  • Message reordering
  • Partitions
  • Node crashes/restarts

Schedules
  • random
  • PCT
  • coverage-guided

Deliverable

Deterministic distributed testing.

⸻

M7 — Shrinking Engine

Objectives

Minimal repro automation.

Dimensions
  • Input shrinking
  • Schedule shrinking
  • Fault shrinking
  • Node count shrinking

Deliverable

fozzy shrink trace.fozzy

→ smallest failing scenario

⸻

M8 — TypeScript SDK

Aligned with SDK-TS.md.

Objectives

Ship production SDK.

Requirements
  • Thin binary wrapper
  • Stable JSON parsing
  • Streaming support
  • Scenario builders
  • Artifact helpers

Non-goals
  • No engine logic in TS

Deliverable

NPM package ready.

⸻

M9 — CI + Reporting

Objectives

Adoption readiness.

Features
  • JUnit output
  • HTML reports
  • JSON query tooling
  • Flaky test detection
  • CI exit code semantics

Deliverable

Drop-in CI compatibility.

⸻

M10 — Hardening

Objectives

Make it production-grade.

Areas
  • Replay determinism audits
  • Performance optimization
  • Memory footprint reduction
  • Trace format stability
  • CLI UX polish

Deliverable

v1.0 readiness.

⸻

6. Checkers (Correctness Layer)

Checkers validate correctness beyond assertions.

v1 Checkers
  • Invariants
  • Panic detection
  • Deadlock detection

v2 Checkers
  • Linearizability
  • Refinement testing
  • Serializability

⸻

7. Trace Format

.fozzy trace must be:
  • Deterministic
  • Portable
  • Forward-compatible

Must include
  • Seed
  • Engine version
  • Decision log
  • Inputs
  • Fault injections

⸻

8. Performance Targets

Metric  Target
Replay fidelity 100%
Test overhead <2x normal runtime
Replay speed  ≥10k decisions/sec
Trace size  <5MB typical


⸻

9. Developer Experience Targets

CLI UX
  • Deterministic by default where possible
  • Repro seeds always shown
  • One-line shrink

Error Output

Must include:
  • seed
  • runId
  • trace path
  • repro command

⸻

10. Risks

Technical Risks
  • Deterministic scheduler complexity
  • Replay drift bugs
  • Cross-platform timing differences
  • Trace bloat

Product Risks
  • Over-scope
  • Slow first impression
  • Fuzzing expectations mismatch

⸻

11. Risk Mitigation
  • Lock deterministic core early
  • Ship small but solid milestones
  • Maintain strict CLI contracts
  • Keep SDK thin

⸻

12. Success Criteria

Fozzy v1 is successful if:
  • Engineers trust replay determinism
  • Shrinking works reliably
  • Distributed exploration is usable
  • TS SDK adoption is smooth

⸻

13. Future Extensions

Not in v1, but planned:
  • Native Rust SDK (no binary hop)
  • Python SDK
  • K8s execution mode
  • Visual timeline UI
  • Plugin checker ecosystem
  • Hardware simulation hooks

⸻

14. Execution Order (Strict)

If time-constrained, prioritize:
  1.  Deterministic core
  2.  Replay fidelity
  3.  Test framework
  4.  Artifacts
  5.  Fuzzing
  6.  Distributed explore
  7.  Shrinking
  8.  SDK polish

Everything else is secondary.

⸻

15. Engineering Principles
  • Determinism > features
  • Replayability > performance
  • CLI stability > internal purity
  • Thin SDKs, fat engine
  • Fail loudly on nondeterminism
  • First-principles engine execution: no “run another test runner” shortcuts

⸻

16. Definition of Done (v1)

Fozzy 1.0 ships when:
  • Deterministic replay never drifts
  • Shrinking consistently works
  • CLI stable across platforms
  • SDK-TS stable API
  • Real-world distributed demo published

⸻

17. Closing Notes

Fozzy is not:
  • Just a fuzzer
  • Just a test runner
  • Just a chaos tool

It is:

A deterministic execution platform for proving software correctness under real-world conditions.

If the deterministic universe is correct, everything else compounds.

⸻

If you want, I can generate next:
  • fozzy.toml full schema
  • ARCHITECTURE.md (engine internals)
  • TRACE.md (binary trace format spec)
  • or a Phase 0 bootstrap task list for your team to start coding immediately.
