use anyhow::{bail, Result};
use reqwest::Client;

use super::config::CasConfig;

pub struct CasApiClient {
    client: Client,
    cas_url: String,
}

impl CasApiClient {
    pub fn with_default_cas(config: &CasConfig) -> Result<Self> {
        let client = config.build_reqwest_client()?;
        Ok(Self {
            client,
            cas_url: config.default_cas.clone(),
        })
    }

    pub async fn post_session(&self, session: Vec<u8>) -> Result<()> {
        let url = format!("https://{}:8081/v1/sessions", self.cas_url);
        println!("POST {url}\n{}", String::from_utf8_lossy(&session));
        let res = self
            .client
            .post(url)
            .body(session)
            .header("Content-Type", "application/yaml")
            .send()
            .await?;

        let status = res.status();

        let res_body = res.text().await?;
        println!("CAS replied: {res_body}");

        if status.is_success() {
            return Ok(());
        }

        bail!(res_body);
    }
}
