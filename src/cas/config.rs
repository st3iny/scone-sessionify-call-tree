use std::{collections::HashMap, fs::File, path::Path};

use anyhow::{anyhow, Context, Result};
use reqwest::{Certificate, Client, Identity};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct CasConfig {
    pub default_cas: String,
    pub identity: String,
    pub cas_db: HashMap<String, CasDbEntry>,
}

#[derive(Debug, Deserialize)]
pub struct CasDbEntry {
    pub url: String,
    pub chain: String,
}

impl CasConfig {
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let file = File::open(path)
            .with_context(|| format!("Failed to open CAS config file at {path:?}"))?;
        serde_json::from_reader(file).context("Failed to deserialize CAS config")
    }

    pub fn build_reqwest_client(&self) -> Result<Client> {
        let mut client_builder = Client::builder()
            .tls_built_in_root_certs(false)
            .identity(self.identity()?);
        for cert in self.ca()? {
            client_builder = client_builder.add_root_certificate(cert);
        }
        let client = client_builder.build()?;
        Ok(client)
    }

    pub fn identity_cert_pem(&self) -> Result<String> {
        let (identity_cert, _) =
            split_identity(&self.identity).ok_or_else(|| anyhow!("Invalid identity format"))?;
        Ok(identity_cert)
    }

    fn identity(&self) -> Result<Identity> {
        let (identity_cert, identity_key) =
            split_identity(&self.identity).ok_or_else(|| anyhow!("Invalid identity format"))?;
        let identity = Identity::from_pkcs8_pem(identity_cert.as_bytes(), identity_key.as_bytes())?;
        Ok(identity)
    }

    fn ca(&self) -> Result<Vec<Certificate>> {
        let chain = Certificate::from_pem_bundle(
            self.cas_db
                .get(&self.default_cas)
                .ok_or_else(|| anyhow!("default_cas is not in cas_db"))?
                .chain
                .as_bytes(),
        )?;
        Ok(chain)
    }
}

/// Expects the private key to come first and returns (cert, key)
fn split_identity(identity: &str) -> Option<(String, String)> {
    let mut iter = identity.split_inclusive("-----END PRIVATE KEY-----\n");
    let key = iter.next()?.to_owned();
    let cert = iter.next()?.to_owned();
    Some((cert, key))
}
