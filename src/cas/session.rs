use std::collections::BTreeMap;

use serde::Serialize;

use crate::policy::AttestationMode;

#[derive(Serialize)]
pub struct CasNamespaceSession {
    pub version: String,
    pub name: String,
    pub access_policy: AccessPolicy,
}

#[derive(Serialize)]
pub struct CasSession {
    pub version: String,
    pub name: String,
    pub predecessor: Option<String>,
    pub images: Vec<Image>,
    pub services: Vec<Service>,
    pub access_policy: AccessPolicy,
    pub security: Security,
    pub creator: String,
}

#[derive(Serialize)]
pub struct Image {
    pub name: String,
}

#[derive(Serialize)]
pub struct Service {
    pub name: String,
    pub image_name: Option<String>,
    pub mrenclaves: Vec<String>,
    pub environment: BTreeMap<String, String>,
    pub command: String,
    pub pwd: String,
    pub fspf_path: Option<String>,
    pub fspf_key: Option<String>,
    pub fspf_tag: Option<String>,
    pub persistency: String,
}

#[derive(Serialize)]
pub struct AccessPolicy {
    pub read: Vec<String>,
    pub update: Vec<String>,
}

impl Default for AccessPolicy {
    fn default() -> Self {
        let creator = String::from("CREATOR");
        Self {
            read: vec![creator.clone()],
            update: vec![creator],
        }
    }
}

#[derive(Serialize)]
pub struct Security {
    pub attestation: SecurityAttestation,
}

#[derive(Serialize)]
pub struct SecurityAttestation {
    pub mode: String,
    pub tolerate: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub ignore_advisories: Option<String>,
}

impl From<AttestationMode> for SecurityAttestation {
    fn from(val: AttestationMode) -> Self {
        let preset: SecurityAttestationPreset = val.into();
        Self::from(preset)
    }
}

pub enum SecurityAttestationPreset {
    None,
    Hardware {
        tolerate: Vec<String>,
        ignore_advisories: String,
    },
}

impl From<AttestationMode> for SecurityAttestationPreset {
    fn from(val: AttestationMode) -> Self {
        match val {
            AttestationMode::None => Self::None,
            AttestationMode::HardwareInsecure => Self::Hardware {
                tolerate: vec![
                    "hyperthreading".to_owned(),
                    "insecure-igpu".to_owned(),
                    "outdated-tcb".to_owned(),
                    "software-hardening-needed".to_owned(),
                    "insecure-configuration".to_owned(),
                    "debug-mode".to_owned(),
                ],
                ignore_advisories: "*".to_owned(),
            },
        }
    }
}

impl From<SecurityAttestationPreset> for SecurityAttestation {
    fn from(value: SecurityAttestationPreset) -> Self {
        match value {
            SecurityAttestationPreset::None => Self {
                mode: "none".to_owned(),
                tolerate: None,
                ignore_advisories: None,
            },
            SecurityAttestationPreset::Hardware {
                tolerate,
                ignore_advisories,
            } => Self {
                mode: "hardware".to_owned(),
                tolerate: Some(tolerate),
                ignore_advisories: Some(ignore_advisories),
            },
        }
    }
}
