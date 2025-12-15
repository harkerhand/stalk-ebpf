use std::process::exit;

use log::debug;
pub mod config;
pub mod event;
pub mod stalk;
use clap::Parser;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();
    init_rlimit()?;
    let cli = config::Cli::parse();
    let config_content = tokio::fs::read_to_string(cli.config_file).await?;
    let config: config::StalkConfig = toml::from_str(&config_content)?;
    stalk::stalk(config.items).await?;

    let ctrl_c = tokio::signal::ctrl_c();
    println!("Waiting for Ctrl-C...");
    ctrl_c.await?;
    println!("Exiting...");
    exit(0);
}

fn init_rlimit() -> anyhow::Result<()> {
    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }
    Ok(())
}
