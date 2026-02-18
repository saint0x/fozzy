//! Environment and version metadata for `fozzy env` / `fozzy version`.

use serde::{Deserialize, Serialize};

use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvInfo {
    pub os: String,
    pub arch: String,
    pub fozzy: VersionInfo,
    pub capabilities: BTreeMap<String, CapabilityInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityInfo {
    pub backend: String,
    pub deterministic: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionInfo {
    pub version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub commit: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub build_date: Option<String>,
}

pub fn version_info() -> VersionInfo {
    VersionInfo {
        version: env!("CARGO_PKG_VERSION").to_string(),
        commit: option_env!("FOZZY_COMMIT").map(|s| s.to_string()),
        build_date: option_env!("FOZZY_BUILD_DATE").map(|s| s.to_string()),
    }
}

pub fn env_info(_config: &crate::Config) -> EnvInfo {
    let mut capabilities = BTreeMap::new();
    capabilities.insert(
        "time".to_string(),
        CapabilityInfo {
            backend: "virtual".to_string(),
            deterministic: true,
        },
    );
    capabilities.insert(
        "rng".to_string(),
        CapabilityInfo {
            backend: "chacha20".to_string(),
            deterministic: true,
        },
    );
    capabilities.insert(
        "fs".to_string(),
        CapabilityInfo {
            backend: "virtual_overlay".to_string(),
            deterministic: true,
        },
    );
    capabilities.insert(
        "http".to_string(),
        CapabilityInfo {
            backend: "scripted".to_string(),
            deterministic: true,
        },
    );
    capabilities.insert(
        "net".to_string(),
        CapabilityInfo {
            backend: "simulated".to_string(),
            deterministic: true,
        },
    );
    capabilities.insert(
        "proc".to_string(),
        CapabilityInfo {
            backend: "scripted".to_string(),
            deterministic: true,
        },
    );

    EnvInfo {
        os: std::env::consts::OS.to_string(),
        arch: std::env::consts::ARCH.to_string(),
        fozzy: version_info(),
        capabilities,
    }
}
