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
        title: "Fozzy CLI usage (what to use when)".to_string(),
        items: vec![
            UsageItem {
                command: "fozzy init".to_string(),
                when: "Start a new project or bootstrap config/artifact directories.".to_string(),
                how: "fozzy init --force; then edit fozzy.toml and add scenarios under tests/.".to_string(),
            },
            UsageItem {
                command: "fozzy test".to_string(),
                when: "Run a suite of scenarios as your normal CI test runner; turn on --det to make failures replayable.".to_string(),
                how: "fozzy test --det --seed 1337 --record /tmp/test.fozzy; with multiple scenarios, traces are /tmp/test.1.fozzy, /tmp/test.2.fozzy, etc.".to_string(),
            },
            UsageItem {
                command: "fozzy run".to_string(),
                when: "Run a single scenario one-off while iterating locally or debugging a specific failure.".to_string(),
                how: "fozzy run tests/example.fozzy.json --det --timeout 2s --json; in --det mode timeout is enforced on virtual elapsed time.".to_string(),
            },
            UsageItem {
                command: "fozzy replay".to_string(),
                when: "Reproduce a failure exactly from a recorded trace, to debug without drift.".to_string(),
                how: "fozzy replay .fozzy/runs/<runId>/trace.fozzy --dump-events --json.".to_string(),
            },
            UsageItem {
                command: "fozzy shrink".to_string(),
                when: "Minimize a failing run to the smallest scenario/trace that still triggers the bug.".to_string(),
                how: "fozzy shrink trace.fozzy --minimize all --budget 30s --json (then replay the .min.fozzy output).".to_string(),
            },
            UsageItem {
                command: "fozzy fuzz".to_string(),
                when: "Find new bugs automatically by mutating inputs and exploring states; use for robustness/security testing.".to_string(),
                how: "fozzy fuzz fn:kv --mode coverage --time 30s --record /tmp/fuzz.fozzy (record writes a trace path for both pass and fail runs).".to_string(),
            },
            UsageItem {
                command: "fozzy explore".to_string(),
                when: "Test distributed/system scenarios by exploring schedules and injecting faults deterministically.".to_string(),
                how: "fozzy explore tests/kv.explore.fozzy.json --schedule coverage_guided --faults partition-first-two --checker kv_all_equal:k --nodes 3 --steps 200 --json.".to_string(),
            },
            UsageItem {
                command: "fozzy corpus".to_string(),
                when: "Manage fuzz corpora: seed inputs, export/import to share failing cases across machines/CI.".to_string(),
                how: "fozzy corpus add <dir> <file>; fozzy corpus list <dir>; fozzy corpus export <dir> --out corpus.zip.".to_string(),
            },
            UsageItem {
                command: "fozzy artifacts".to_string(),
                when: "List/export run files or diff two runs/traces to quickly see artifact/report/trace drift.".to_string(),
                how: "fozzy artifacts ls <runId>; fozzy artifacts diff <left> <right>; fozzy artifacts export <runId> --out out.zip.".to_string(),
            },
            UsageItem {
                command: "fozzy report".to_string(),
                when: "Render a run summary in a specific format for CI (JUnit) or humans (HTML/pretty).".to_string(),
                how: "fozzy report show <runId|trace> --format junit; fozzy report query <runId> --jq '.findings[].title'; fozzy report flaky <run1> <run2>.".to_string(),
            },
            UsageItem {
                command: "fozzy doctor".to_string(),
                when: "Diagnose environment issues and sources of nondeterminism before trusting replay in CI.".to_string(),
                how: "fozzy doctor --deep --scenario tests/example.fozzy.json --runs 5 --seed 123 --json.".to_string(),
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
        ],
    }
}
