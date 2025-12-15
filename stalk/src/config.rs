use std::path::PathBuf;

use serde::{Deserialize, Serialize};

#[derive(clap::Parser, Debug)]
#[command(name = "stalk", about = "A simple eBPF stalker", version)]
pub struct Cli {
    #[arg(
        short,
        long,
        default_value = "config.toml",
        help = "Path to config file"
    )]
    pub config_file: PathBuf,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StalkConfig {
    pub items: Vec<StalkItem>,
    pub port: u16,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum StalkItem {
    Execve,
    Openat,
    Read,
    Net(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_serialize_deserialize() {
        let config = StalkConfig {
            items: vec![
                StalkItem::Execve,
                StalkItem::Openat,
                StalkItem::Read,
                StalkItem::Net("eth2".to_string()),
            ],
            port: 3000,
        };

        let toml_str = toml::to_string(&config).unwrap();
        let deserialized_config: StalkConfig = toml::from_str(&toml_str).unwrap();

        assert_eq!(config.items.len(), deserialized_config.items.len());
    }
}
