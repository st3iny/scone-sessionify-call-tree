use std::collections::BTreeMap;

use anyhow::Result;
use rand::Rng;

use crate::cas::{
    api::CasApiClient,
    config::CasConfig,
    session::{AccessPolicy, CasNamespaceSession, CasSession, Image, Security, Service},
};

pub async fn create_session_for_exec(
    cas_config: &CasConfig,
    creator_cert_pem: &str,
    command: &[String],
    env: BTreeMap<String, String>,
) -> Result<String> {
    let client = CasApiClient::with_default_cas(cas_config)?;

    let namespace = random_ns_name();
    let session = random_session_name();

    // Create namespace
    let namespace_session = CasNamespaceSession {
        version: "0.3".to_owned(),
        name: namespace.clone(),
        access_policy: Default::default(),
    };
    let namespace_session_yaml = serde_yaml::to_string(&namespace_session)?;
    client
        .post_session(namespace_session_yaml.as_bytes().to_vec())
        .await?;

    // Create session
    let session = create_session(
        &namespace,
        &session,
        None,
        command,
        env,
        &[],
        creator_cert_pem,
        AttestationMode::None,
    )?;
    let service = &session.services[0];
    let session_yaml = serde_yaml::to_string(&session)?;

    client
        .post_session(session_yaml.as_bytes().to_vec())
        .await?;

    let config_id = format!("{}/{}", session.name, service.name);
    Ok(config_id)
}

pub fn create_session(
    namespace: &str,
    name: &str,
    image_name: Option<&str>,
    command: &[String],
    env: BTreeMap<String, String>,
    mr_enclave: &[String],
    creator_cert_pem: &str,
    attestation_mode: AttestationMode,
) -> Result<CasSession> {
    let name = name.to_owned();
    let image_name = image_name.map(String::from);
    let mut images = Vec::new();
    if let Some(image_name) = &image_name {
        images.push(Image {
            name: image_name.clone(),
        })
    }
    Ok(CasSession {
        version: "0.3".to_owned(),
        name: format!("{namespace}/{name}"),
        predecessor: None,
        images,
        services: vec![Service {
            name: "generated".to_owned(),
            image_name,
            mrenclaves: mr_enclave.to_vec(),
            environment: env,
            command: build_command(command),
            pwd: "/".to_owned(),
            fspf_path: None,
            fspf_key: None,
            fspf_tag: None,
            persistency: "None".to_owned(),
        }],
        access_policy: AccessPolicy::default(),
        security: Security {
            attestation: attestation_mode.into(),
        },
        creator: creator_cert_pem.to_owned(),
    })
}

fn build_command(command: &[String]) -> String {
    let mut joined = String::new();
    for arg in command {
        if arg.contains(' ') {
            joined.push_str(&format!("'{arg}' "));
        } else {
            joined.push_str(&format!("{arg} "));
        }
    }
    joined.trim_end().to_owned()
}

#[derive(Clone, Copy)]
pub enum AttestationMode {
    None,
    HardwareInsecure,
}

fn random_ns_name() -> String {
    let mut rng = rand::thread_rng();
    let random: u32 = rng.gen();
    format!("str--{}-{random:x}", env!("CARGO_CRATE_NAME"))
}

fn random_session_name() -> String {
    let mut rng = rand::thread_rng();
    let random: u32 = rng.gen();
    format!("session-{random:x}")
}
