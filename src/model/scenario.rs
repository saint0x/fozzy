//! Scenario file parsing and a minimal deterministic step DSL for v0.1.

use serde::{Deserialize, Serialize};

use std::path::{Path, PathBuf};

use crate::{FozzyError, FozzyResult, parse_duration};

#[derive(Debug, Clone)]
pub struct ScenarioPath {
    path: PathBuf,
}

impl ScenarioPath {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    pub fn as_path(&self) -> &Path {
        &self.path
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ScenarioFile {
    Steps(ScenarioV1Steps),
    Suites(ScenarioV1Suites),
    Distributed(ScenarioV1Distributed),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScenarioV1Steps {
    pub version: u32,
    pub name: String,
    pub steps: Vec<Step>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScenarioV1Suites {
    pub version: u32,
    pub name: String,
    pub suites: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScenarioV1Distributed {
    pub version: u32,
    pub name: String,
    pub distributed: DistributedDef,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DistributedDef {
    #[serde(default)]
    pub nodes: Option<Vec<String>>,
    #[serde(default)]
    pub node_count: Option<usize>,
    pub steps: Vec<DistributedStep>,
    #[serde(default)]
    pub invariants: Vec<DistributedInvariant>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum DistributedStep {
    ClientPut {
        node: String,
        key: String,
        value: String,
    },
    ClientGetAssert {
        node: String,
        key: String,
        equals: Option<String>,
        is_null: Option<bool>,
    },
    Partition {
        a: String,
        b: String,
    },
    Heal {
        a: String,
        b: String,
    },
    Crash {
        node: String,
    },
    Restart {
        node: String,
    },
    Tick {
        duration: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum DistributedInvariant {
    KvAllEqual {
        key: String,
    },
    KvPresentOnAll {
        key: String,
    },
    KvNodeEquals {
        node: String,
        key: String,
        equals: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Step {
    TraceEvent {
        name: String,
        #[serde(default)]
        fields: serde_json::Map<String, serde_json::Value>,
    },
    RandU64 {
        #[serde(default)]
        key: Option<String>,
    },
    AssertOk {
        value: bool,
        #[serde(default)]
        msg: Option<String>,
    },
    AssertEqInt {
        a: i64,
        b: i64,
        #[serde(default)]
        msg: Option<String>,
    },
    AssertNeInt {
        a: i64,
        b: i64,
        #[serde(default)]
        msg: Option<String>,
    },
    AssertEqStr {
        a: String,
        b: String,
        #[serde(default)]
        msg: Option<String>,
    },
    AssertNeStr {
        a: String,
        b: String,
        #[serde(default)]
        msg: Option<String>,
    },
    Sleep {
        duration: String,
    },
    Advance {
        duration: String,
    },
    Freeze {
        #[serde(default)]
        at_ms: Option<u64>,
    },
    Unfreeze,
    SetKv {
        key: String,
        value: String,
    },
    GetKvAssert {
        key: String,
        equals: Option<String>,
        is_null: Option<bool>,
    },
    FsWrite {
        path: String,
        data: String,
    },
    FsReadAssert {
        path: String,
        equals: String,
    },
    FsSnapshot {
        name: String,
    },
    FsRestore {
        name: String,
    },
    HttpWhen {
        method: String,
        path: String,
        status: u16,
        #[serde(default)]
        headers: Option<std::collections::BTreeMap<String, String>>,
        #[serde(default)]
        body: Option<String>,
        #[serde(default)]
        json: Option<serde_json::Value>,
        #[serde(default)]
        delay: Option<String>,
        #[serde(default)]
        times: Option<u64>,
    },
    HttpRequest {
        method: String,
        path: String,
        #[serde(default)]
        headers: Option<std::collections::BTreeMap<String, String>>,
        #[serde(default)]
        body: Option<String>,
        #[serde(default)]
        expect_status: Option<u16>,
        #[serde(default)]
        expect_headers: Option<std::collections::BTreeMap<String, String>>,
        #[serde(default)]
        expect_body: Option<String>,
        #[serde(default)]
        expect_json: Option<serde_json::Value>,
        #[serde(default)]
        save_body_as: Option<String>,
    },
    ProcWhen {
        cmd: String,
        #[serde(default)]
        args: Option<Vec<String>>,
        exit_code: i32,
        #[serde(default)]
        stdout: Option<String>,
        #[serde(default)]
        stderr: Option<String>,
        #[serde(default)]
        times: Option<u64>,
    },
    ProcSpawn {
        cmd: String,
        #[serde(default)]
        args: Option<Vec<String>>,
        #[serde(default)]
        expect_exit: Option<i32>,
        #[serde(default)]
        expect_stdout: Option<String>,
        #[serde(default)]
        expect_stderr: Option<String>,
        #[serde(default)]
        save_stdout_as: Option<String>,
    },
    NetPartition {
        a: String,
        b: String,
    },
    NetHeal {
        a: String,
        b: String,
    },
    NetSetDropRate {
        rate: f64,
    },
    NetSetReorder {
        enabled: bool,
    },
    NetSend {
        from: String,
        to: String,
        payload: String,
    },
    NetDeliverOne {
        #[serde(default)]
        strategy: Option<String>,
    },
    NetRecvAssert {
        node: String,
        #[serde(default)]
        from: Option<String>,
        payload: String,
    },
    MemoryAlloc {
        bytes: u64,
        #[serde(default)]
        key: Option<String>,
        #[serde(default)]
        tag: Option<String>,
    },
    MemoryFree {
        #[serde(default)]
        alloc_id: Option<u64>,
        #[serde(default)]
        key: Option<String>,
    },
    MemoryLimitMb {
        mb: u64,
    },
    MemoryFailAfterAllocs {
        count: u64,
    },
    MemoryCheckpoint {
        name: String,
    },
    MemoryAssertInUseBytes {
        equals: u64,
    },
    AssertThrows {
        steps: Vec<Step>,
    },
    AssertRejects {
        steps: Vec<Step>,
    },
    AssertEventuallyKv {
        key: String,
        equals: String,
        within: String,
        poll: String,
        #[serde(default)]
        msg: Option<String>,
    },
    AssertNeverKv {
        key: String,
        equals: String,
        within: String,
        poll: String,
        #[serde(default)]
        msg: Option<String>,
    },
    Fail {
        message: String,
    },
    Panic {
        message: String,
    },
}

impl Step {
    pub fn kind_name(&self) -> &'static str {
        match self {
            Step::TraceEvent { .. } => "trace_event",
            Step::RandU64 { .. } => "rand_u64",
            Step::AssertOk { .. } => "assert_ok",
            Step::AssertEqInt { .. } => "assert_eq_int",
            Step::AssertNeInt { .. } => "assert_ne_int",
            Step::AssertEqStr { .. } => "assert_eq_str",
            Step::AssertNeStr { .. } => "assert_ne_str",
            Step::Sleep { .. } => "sleep",
            Step::Advance { .. } => "advance",
            Step::Freeze { .. } => "freeze",
            Step::Unfreeze => "unfreeze",
            Step::SetKv { .. } => "set_kv",
            Step::GetKvAssert { .. } => "get_kv_assert",
            Step::FsWrite { .. } => "fs_write",
            Step::FsReadAssert { .. } => "fs_read_assert",
            Step::FsSnapshot { .. } => "fs_snapshot",
            Step::FsRestore { .. } => "fs_restore",
            Step::HttpWhen { .. } => "http_when",
            Step::HttpRequest { .. } => "http_request",
            Step::ProcWhen { .. } => "proc_when",
            Step::ProcSpawn { .. } => "proc_spawn",
            Step::NetPartition { .. } => "net_partition",
            Step::NetHeal { .. } => "net_heal",
            Step::NetSetDropRate { .. } => "net_set_drop_rate",
            Step::NetSetReorder { .. } => "net_set_reorder",
            Step::NetSend { .. } => "net_send",
            Step::NetDeliverOne { .. } => "net_deliver_one",
            Step::NetRecvAssert { .. } => "net_recv_assert",
            Step::MemoryAlloc { .. } => "memory_alloc",
            Step::MemoryFree { .. } => "memory_free",
            Step::MemoryLimitMb { .. } => "memory_limit_mb",
            Step::MemoryFailAfterAllocs { .. } => "memory_fail_after_allocs",
            Step::MemoryCheckpoint { .. } => "memory_checkpoint",
            Step::MemoryAssertInUseBytes { .. } => "memory_assert_in_use_bytes",
            Step::AssertThrows { .. } => "assert_throws",
            Step::AssertRejects { .. } => "assert_rejects",
            Step::AssertEventuallyKv { .. } => "assert_eventually_kv",
            Step::AssertNeverKv { .. } => "assert_never_kv",
            Step::Fail { .. } => "fail",
            Step::Panic { .. } => "panic",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Scenario {
    pub name: String,
    pub steps: Vec<Step>,
}

impl Scenario {
    pub fn load(path: &ScenarioPath) -> FozzyResult<Self> {
        let bytes = std::fs::read(path.as_path())?;
        let file: ScenarioFile = serde_json::from_slice(&bytes)?;
        match file {
            ScenarioFile::Steps(s) => {
                if s.version != 1 {
                    return Err(FozzyError::Scenario(format!(
                        "unsupported scenario version {} (expected 1)",
                        s.version
                    )));
                }
                Ok(Self {
                    name: s.name,
                    steps: s.steps,
                })
            }
            ScenarioFile::Suites(_s) => Err(FozzyError::Scenario(format!(
                "scenario file {} uses `suites` without an executable step DSL (v0.1 only supports `steps`)",
                path.as_path().display()
            ))),
            ScenarioFile::Distributed(_d) => Err(FozzyError::Scenario(format!(
                "scenario file {} is a distributed scenario; use `fozzy explore`",
                path.as_path().display()
            ))),
        }
    }

    pub fn validate(&self) -> FozzyResult<()> {
        for step in &self.steps {
            match step {
                Step::Sleep { duration } | Step::Advance { duration } => {
                    parse_duration(duration)?;
                }
                Step::AssertEventuallyKv { within, poll, .. }
                | Step::AssertNeverKv { within, poll, .. } => {
                    parse_duration(within)?;
                    parse_duration(poll)?;
                }
                Step::GetKvAssert {
                    equals: Some(_),
                    is_null: Some(true),
                    ..
                } => {
                    return Err(FozzyError::Scenario(
                        "GetKvAssert: cannot set both equals and is_null=true".to_string(),
                    ));
                }
                Step::MemoryFree { alloc_id, key } if alloc_id.is_some() == key.is_some() => {
                    return Err(FozzyError::Scenario(
                        "MemoryFree: set exactly one of alloc_id or key".to_string(),
                    ));
                }
                _ => {}
            }
        }
        Ok(())
    }

    pub fn example() -> ScenarioV1Steps {
        ScenarioV1Steps {
            version: 1,
            name: "example".to_string(),
            steps: vec![
                Step::TraceEvent {
                    name: "setup".to_string(),
                    fields: serde_json::Map::new(),
                },
                Step::RandU64 {
                    key: Some("rand".to_string()),
                },
                Step::Sleep {
                    duration: "10ms".to_string(),
                },
                Step::AssertEqInt {
                    a: 1,
                    b: 1,
                    msg: None,
                },
            ],
        }
    }
}
