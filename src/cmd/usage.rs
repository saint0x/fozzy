//! `fozzy usage`: a compact "what to use when" guide for agents and humans.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsageDoc {
    pub title: String,
    pub items: Vec<UsageItem>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsageItem {
    pub command: String,
    pub when: String,
    pub how: String,
}

impl UsageDoc {
    pub fn pretty(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!("{}\n\n", self.title));
        for item in &self.items {
            out.push_str(&format!("{}:\n", item.command));
            out.push_str(&format!("  when: {}\n", item.when));
            out.push_str(&format!("  how:  {}\n\n", item.how));
        }
        out.trim_end().to_string()
    }
}

pub fn usage_doc() -> UsageDoc {
    UsageDoc {
        title: "Fozzy CLI usage (use the full surface by default)".to_string(),
        items: vec![
            UsageItem {
                command: "fozzy full".to_string(),
                when: "Run the complete Fozzy surface-area gate with setup guidance and graceful skip behavior for missing inputs.".to_string(),
                how: "fozzy full --scenario-root tests --seed 1337 --doctor-runs 5 --fuzz-time 2s --explore-steps 200 --explore-nodes 3 --allow-expected-failures --scenario-filter memory --skip-steps fuzz --required-steps usage,version,test_det,run_record_trace,replay,ci,shrink --require-topology-coverage . --topology-min-risk 60 --topology-profile pedantic. This command exercises init/test/run/fuzz/explore/replay/trace verify/shrink/corpus/artifacts/report/memory/map/doctor/ci/env/version/usage with policy controls for mixed scenario sets and can enforce high-risk topology hotspot coverage. Strictest setting: strict mode is on by default; add `--unsafe` only to opt out.".to_string(),
            },
            UsageItem {
                command: "fozzy map".to_string(),
                when: "Generate a language-agnostic code-topology map (hotspots, service boundaries, and granular suite recommendations).".to_string(),
                how: "fozzy map hotspots --root . --min-risk 60 --limit 50 --json; fozzy map services --root . --json; fozzy map suites --root . --scenario-root tests --min-risk 60 --profile pedantic --json. `pedantic` is the default profile and biases toward over-specifying granular suite coverage; optionally use `balanced` or `overkill`.".to_string(),
            },
            UsageItem {
                command: "fozzy init".to_string(),
                when: "Start a new project or bootstrap config/artifact directories.".to_string(),
                how: "fozzy init --template rust --with run,memory,explore,fuzz,host --force (or just `fozzy init` for all scaffold types by default). Then edit tests/*.fozzy.json inputs/assertions and run `fozzy full --scenario-root tests --seed 7`.".to_string(),
            },
            UsageItem {
                command: "fozzy test".to_string(),
                when: "Run a suite of Fozzy scenarios in CI; turn on --det to make failures replayable. This is not a direct shell/cargo/jest runner.".to_string(),
                how: "fozzy test --det --seed 1337 --record /tmp/test.fozzy --mem-track --fail-on-leak --leak-budget 0; with multiple scenarios, traces are /tmp/test.1.fozzy, /tmp/test.2.fozzy, etc. Host backends (`--proc-backend host`, `--fs-backend host`, `--http-backend host`) are non-det only. Strictest setting: strict mode is on by default; add `--unsafe` only to opt out.".to_string(),
            },
            UsageItem {
                command: "fozzy run".to_string(),
                when: "Run a single scenario one-off while iterating locally or debugging a specific failure.".to_string(),
                how: "fozzy run tests/example.fozzy.json --det --timeout 2s --json --mem-track --mem-limit-mb 256 --mem-fail-after 10000 --mem-artifacts; in --det mode timeout is enforced on virtual elapsed time. For host execution, use `--proc-backend host`, `--fs-backend host`, `--http-backend host` (non-det). `http_request` supports `headers` + `expect_headers` assertions. Strictest setting: strict mode is on by default; add `--unsafe` only to opt out.".to_string(),
            },
            UsageItem {
                command: "fozzy replay".to_string(),
                when: "Reproduce a failure exactly from a recorded trace, to debug without drift.".to_string(),
                how: "fozzy replay .fozzy/runs/<runId>/trace.fozzy --dump-events --json. Strictest setting: strict mode is on by default; add `--unsafe` only to opt out.".to_string(),
            },
            UsageItem {
                command: "fozzy trace verify".to_string(),
                when: "Validate trace integrity/version before replaying or handing artifacts to CI/other teams.".to_string(),
                how: "fozzy trace verify .fozzy/runs/<runId>/trace.fozzy --json. Strictest setting: strict mode is on by default; add `--unsafe` only to opt out.".to_string(),
            },
            UsageItem {
                command: "fozzy shrink".to_string(),
                when: "Minimize a failing run to the smallest scenario/trace that still triggers the bug.".to_string(),
                how: "fozzy shrink trace.fozzy --minimize all --budget 30s --json (then replay the .min.fozzy output). Strictest setting: strict mode is on by default; add `--unsafe` only to opt out.".to_string(),
            },
            UsageItem {
                command: "fozzy fuzz".to_string(),
                when: "Find new bugs automatically by mutating inputs and exploring states; use for robustness/security testing.".to_string(),
                how: "fozzy fuzz fn:kv --mode coverage --time 30s --record /tmp/fuzz.fozzy (record writes a trace path for both pass and fail runs). Strictest setting: strict mode is on by default; add `--unsafe` only to opt out.".to_string(),
            },
            UsageItem {
                command: "fozzy explore".to_string(),
                when: "Test distributed/system scenarios by exploring schedules and injecting faults deterministically.".to_string(),
                how: "fozzy explore tests/kv.explore.fozzy.json --schedule coverage_guided --faults partition-first-two --checker kv_all_equal:k --nodes 3 --steps 200 --json. Strictest setting: strict mode is on by default; add `--unsafe` only to opt out.".to_string(),
            },
            UsageItem {
                command: "fozzy corpus".to_string(),
                when: "Manage fuzz corpora: seed inputs, export/import to share failing cases across machines/CI.".to_string(),
                how: "fozzy corpus add <dir> <file>; fozzy corpus list <dir>; fozzy corpus export <dir> --out corpus.zip.".to_string(),
            },
            UsageItem {
                command: "fozzy artifacts".to_string(),
                when: "List/export run files or diff two runs/traces to quickly see artifact/report/trace drift.".to_string(),
                how: "fozzy artifacts ls <runId>; fozzy artifacts diff <left> <right>; fozzy artifacts export <runId> --out out.zip; fozzy artifacts pack <runId|trace> --out repro.zip. Aliases (`latest`, `last-pass`, `last-fail`) are supported, but CI should prefer explicit run ids or trace paths when race-sensitive.".to_string(),
            },
            UsageItem {
                command: "fozzy report".to_string(),
                when: "Render a run summary in a specific format for CI (JUnit) or humans (HTML/pretty).".to_string(),
                how: "fozzy report show <runId|trace> --format junit; fozzy report query <runId> --jq '.findings[].title'; fozzy report flaky <run1> <run2> --flake-budget 5. Aliases (`latest`, `last-pass`, `last-fail`) are supported, but CI should prefer explicit run ids or trace paths when race-sensitive.".to_string(),
            },
            UsageItem {
                command: "fozzy memory".to_string(),
                when: "Inspect memory-focused diagnostics (graph, leak top-N, run-to-run memory deltas)."
                    .to_string(),
                how: "fozzy memory top <runId|trace> --limit 20; fozzy memory diff <left> <right>; fozzy memory graph <runId|trace> --out memory.graph.export.json. Strictest setting: strict mode is on by default; add `--unsafe` only to opt out."
                    .to_string(),
            },
            UsageItem {
                command: "fozzy ci".to_string(),
                when: "Run a canonical local gate bundle for one trace: verify, replay outcome check, artifacts zip integrity, optional flake budget.".to_string(),
                how: "fozzy ci .fozzy/runs/<runId>/trace.fozzy --flake-run <run1> --flake-run <run2> --flake-budget 5 --json. Strictest setting: strict mode is on by default; add `--unsafe` only to opt out.".to_string(),
            },
            UsageItem {
                command: "fozzy doctor".to_string(),
                when: "Diagnose environment issues and sources of nondeterminism before trusting replay in CI.".to_string(),
                how: "fozzy doctor --deep --scenario tests/example.fozzy.json --runs 5 --seed 123 --json. Strictest setting: strict mode is on by default; add `--unsafe` only to opt out.".to_string(),
            },
            UsageItem {
                command: "fozzy env".to_string(),
                when: "Inspect current capability backends and whether they are deterministic.".to_string(),
                how: "fozzy env --json.".to_string(),
            },
            UsageItem {
                command: "fozzy version".to_string(),
                when: "Print version/build metadata for bug reports and CI logs.".to_string(),
                how: "fozzy version --json.".to_string(),
            },
            UsageItem {
                command: "fozzy schema".to_string(),
                when: "Inspect supported scenario-file variants and step types for authoring and automation.".to_string(),
                how: "fozzy schema --json (alias: `fozzy steps --json`).".to_string(),
            },
            UsageItem {
                command: "fozzy validate".to_string(),
                when: "Validate a scenario file and return deterministic parser/shape diagnostics before running tests.".to_string(),
                how: "fozzy validate tests/example.fozzy.json --json; non-zero exit indicates parse or validation issues.".to_string(),
            },
        ],
    }
}
