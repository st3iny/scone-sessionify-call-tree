use std::{collections::BTreeMap, os::unix::process::CommandExt, path::PathBuf, process::Command};

use anyhow::{Context, Result};

use crate::{cas::config::CasConfig, policy::create_session_for_exec};

mod cas;
mod policy;

/// Main entry point to be called by the SCONE runtime just before a parent requests forking and
/// executing another binary.
pub async fn gen_and_exec(args: &[String], env: &[String]) -> Result<()> {
    println!("Inherited environment:");
    for (key, val) in std::env::vars() {
        println!("{key}={val}");
    }
    println!();

    let env_map: BTreeMap<String, String> = env
        .iter()
        .filter_map(|env| env.split_once('='))
        .map(|(key, value)| (key.to_owned(), value.to_owned()))
        .collect();

    let mut cmd = Command::new(&args[0]);
    cmd.args(&args[1..]);
    cmd.envs(&env_map);

    let cas_config = load_cas_config()?;
    let creator = cas_config.identity_cert_pem()?;
    let config_id = create_session_for_exec(&cas_config, &creator, args, env_map).await?;
    cmd.env("SCONE_CONFIG_ID", config_id);

    println!("Execing {cmd:?}");
    let error = cmd.exec();
    Err(error).context("Failed to exec child")
}

// TODO: This is a bit hacky and should be done properly!
//       The whole .cas folder from a dev machine needs to be mounted or bundled at $HOME/.cas in
//       the image for this to work.
fn load_cas_config() -> Result<CasConfig> {
    let path = PathBuf::from(std::env::var("HOME")?)
        .join(".cas")
        .join("config.json");
    CasConfig::load(path)
}
