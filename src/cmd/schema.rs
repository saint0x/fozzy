//! Scenario/schema introspection for automation and authoring.

use serde::Serialize;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize)]
pub struct SchemaDoc {
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    #[serde(rename = "fileVariants")]
    pub file_variants: Vec<FileVariant>,
    #[serde(rename = "stepTypes")]
    pub step_types: Vec<&'static str>,
    #[serde(rename = "distributedStepTypes")]
    pub distributed_step_types: Vec<&'static str>,
    #[serde(rename = "distributedInvariantTypes")]
    pub distributed_invariant_types: Vec<&'static str>,
    #[serde(rename = "stepSchemas")]
    pub step_schemas: BTreeMap<&'static str, StepSchema>,
    #[serde(rename = "distributedStepSchemas")]
    pub distributed_step_schemas: BTreeMap<&'static str, StepSchema>,
    #[serde(rename = "distributedInvariantSchemas")]
    pub distributed_invariant_schemas: BTreeMap<&'static str, StepSchema>,
}

#[derive(Debug, Clone, Serialize)]
pub struct FileVariant {
    pub name: &'static str,
    #[serde(rename = "requiredTopLevelKeys")]
    pub required_top_level_keys: Vec<&'static str>,
    #[serde(rename = "minimalExample")]
    pub minimal_example: serde_json::Value,
}

#[derive(Debug, Clone, Serialize)]
pub struct StepSchema {
    #[serde(rename = "requiredFields")]
    pub required_fields: Vec<&'static str>,
    #[serde(rename = "optionalFields")]
    pub optional_fields: Vec<&'static str>,
    pub example: serde_json::Value,
    pub notes: String,
}

pub fn schema_doc() -> SchemaDoc {
    let step_types = vec![
        "trace_event",
        "rand_u64",
        "assert_ok",
        "assert_eq_int",
        "assert_ne_int",
        "assert_eq_str",
        "assert_ne_str",
        "sleep",
        "advance",
        "freeze",
        "unfreeze",
        "set_kv",
        "get_kv_assert",
        "fs_write",
        "fs_read_assert",
        "fs_snapshot",
        "fs_restore",
        "http_when",
        "http_request",
        "proc_when",
        "proc_spawn",
        "net_partition",
        "net_heal",
        "net_set_drop_rate",
        "net_set_reorder",
        "net_send",
        "net_deliver_one",
        "net_recv_assert",
        "memory_alloc",
        "memory_free",
        "memory_limit_mb",
        "memory_fail_after_allocs",
        "memory_fragmentation",
        "memory_pressure_wave",
        "memory_checkpoint",
        "memory_assert_in_use_bytes",
        "assert_throws",
        "assert_rejects",
        "assert_eventually_kv",
        "assert_never_kv",
        "fail",
        "panic",
    ];
    let distributed_step_types = vec![
        "client_put",
        "client_get_assert",
        "partition",
        "heal",
        "crash",
        "restart",
        "tick",
    ];
    let distributed_invariant_types = vec!["kv_all_equal", "kv_present_on_all", "kv_node_equals"];

    let mut step_schemas = BTreeMap::<&'static str, StepSchema>::new();
    step_schemas.insert(
        "proc_when",
        StepSchema {
            required_fields: vec!["type", "cmd", "exit_code"],
            optional_fields: vec!["args", "stdout", "stderr", "times"],
            example: serde_json::json!({
                "type": "proc_when",
                "cmd": "git",
                "args": ["status", "--porcelain"],
                "exit_code": 0,
                "stdout": "",
                "times": 1
            }),
            notes: "Use `exit_code` (not `exit`). `times` defaults to unlimited when omitted."
                .to_string(),
        },
    );
    step_schemas.insert(
        "proc_spawn",
        StepSchema {
            required_fields: vec!["type", "cmd"],
            optional_fields: vec![
                "args",
                "expect_exit",
                "expect_stdout",
                "expect_stderr",
                "save_stdout_as",
            ],
            example: serde_json::json!({
                "type": "proc_spawn",
                "cmd": "echo",
                "args": ["hello"],
                "expect_exit": 0,
                "expect_stdout": "hello\n"
            }),
            notes:
                "Assertions are optional; omitted expectations mean \"do not assert that field\"."
                    .to_string(),
        },
    );
    step_schemas.insert(
        "http_when",
        StepSchema {
            required_fields: vec!["type", "method", "path", "status"],
            optional_fields: vec!["headers", "body", "json", "delay", "times"],
            example: serde_json::json!({
                "type": "http_when",
                "method": "GET",
                "path": "/healthz",
                "status": 200,
                "json": {"ok": true},
                "times": 1
            }),
            notes: "Set at most one of `body` or `json`.".to_string(),
        },
    );
    step_schemas.insert(
        "http_request",
        StepSchema {
            required_fields: vec!["type", "method", "path"],
            optional_fields: vec![
                "headers",
                "body",
                "expect_status",
                "expect_headers",
                "expect_body",
                "expect_json",
                "save_body_as",
            ],
            example: serde_json::json!({
                "type": "http_request",
                "method": "GET",
                "path": "/healthz",
                "expect_status": 200,
                "expect_json": {"ok": true}
            }),
            notes: "Response assertions are optional.".to_string(),
        },
    );
    step_schemas.insert(
        "memory_free",
        StepSchema {
            required_fields: vec!["type"],
            optional_fields: vec!["alloc_id", "key"],
            example: serde_json::json!({
                "type": "memory_free",
                "key": "buf"
            }),
            notes: "Set exactly one of `alloc_id` or `key`.".to_string(),
        },
    );
    for step in &step_types {
        step_schemas.entry(step).or_insert_with(|| StepSchema {
            required_fields: vec!["type"],
            optional_fields: vec![],
            example: serde_json::json!({ "type": step }),
            notes: "Step-specific fields are defined by the runtime DSL; this entry is intentionally minimal."
                .to_string(),
        });
    }

    let mut distributed_step_schemas = BTreeMap::<&'static str, StepSchema>::new();
    distributed_step_schemas.insert(
        "client_put",
        StepSchema {
            required_fields: vec!["type", "node", "key", "value"],
            optional_fields: vec![],
            example: serde_json::json!({
                "type": "client_put",
                "node": "n0",
                "key": "k",
                "value": "v"
            }),
            notes: "Node must exist in distributed nodes list or generated node_count set."
                .to_string(),
        },
    );
    distributed_step_schemas.insert(
        "tick",
        StepSchema {
            required_fields: vec!["type", "duration"],
            optional_fields: vec![],
            example: serde_json::json!({
                "type": "tick",
                "duration": "10ms"
            }),
            notes: "Duration accepts the same parser as `sleep`/`advance`.".to_string(),
        },
    );
    for step in &distributed_step_types {
        distributed_step_schemas
            .entry(step)
            .or_insert_with(|| StepSchema {
                required_fields: vec!["type"],
                optional_fields: vec![],
                example: serde_json::json!({ "type": step }),
                notes: "Distributed step-specific fields are required as defined by the DSL."
                    .to_string(),
            });
    }

    let mut distributed_invariant_schemas = BTreeMap::<&'static str, StepSchema>::new();
    distributed_invariant_schemas.insert(
        "kv_present_on_all",
        StepSchema {
            required_fields: vec!["type", "key"],
            optional_fields: vec![],
            example: serde_json::json!({
                "type": "kv_present_on_all",
                "key": "k"
            }),
            notes: "Fails if any live node is missing `key`.".to_string(),
        },
    );
    distributed_invariant_schemas.insert(
        "kv_node_equals",
        StepSchema {
            required_fields: vec!["type", "node", "key", "equals"],
            optional_fields: vec![],
            example: serde_json::json!({
                "type": "kv_node_equals",
                "node": "n1",
                "key": "k",
                "equals": "v"
            }),
            notes: "Node must exist in the distributed topology.".to_string(),
        },
    );
    for inv in &distributed_invariant_types {
        distributed_invariant_schemas
            .entry(inv)
            .or_insert_with(|| StepSchema {
                required_fields: vec!["type"],
                optional_fields: vec![],
                example: serde_json::json!({ "type": inv }),
                notes: "Invariant-specific fields are required as defined by the DSL.".to_string(),
            });
    }

    SchemaDoc {
        schema_version: "fozzy.schema_doc.v2".to_string(),
        file_variants: vec![
            FileVariant {
                name: "steps",
                required_top_level_keys: vec!["version", "name", "steps"],
                minimal_example: serde_json::json!({
                    "version": 1,
                    "name": "example",
                    "steps": [
                        { "type": "trace_event", "name": "setup" },
                        { "type": "assert_eq_int", "a": 1, "b": 1 }
                    ]
                }),
            },
            FileVariant {
                name: "distributed",
                required_top_level_keys: vec!["version", "name", "distributed"],
                minimal_example: serde_json::json!({
                    "version": 1,
                    "name": "distributed-example",
                    "distributed": {
                        "node_count": 3,
                        "steps": [
                            { "type": "client_put", "node": "n0", "key": "k", "value": "v" },
                            { "type": "tick", "duration": "10ms" }
                        ],
                        "invariants": [
                            { "type": "kv_present_on_all", "key": "k" }
                        ]
                    }
                }),
            },
            FileVariant {
                name: "suites",
                required_top_level_keys: vec!["version", "name", "suites"],
                minimal_example: serde_json::json!({
                    "version": 1,
                    "name": "suites-placeholder",
                    "suites": {}
                }),
            },
        ],
        step_types,
        distributed_step_types,
        distributed_invariant_types,
        step_schemas,
        distributed_step_schemas,
        distributed_invariant_schemas,
    }
}
