#[macro_use]
extern crate serde_derive;

#[macro_use]
extern crate log;

use std::collections::HashMap;

use ipnetwork::IpNetwork;

pub mod api;
pub mod pty;

#[derive(Serialize, Deserialize, Debug, Default)]
#[serde(rename_all = "PascalCase")]
pub struct RunConfig {
    pub image_config: Option<ImageConfig>,
    pub exec_override: Option<Vec<String>>,
    pub extra_env: Option<HashMap<String, String>>,
    pub user_override: Option<String>,
    pub cmd_override: Option<String>,
    #[serde(rename = "IPConfigs")]
    pub ip_configs: Option<Vec<IPConfig>>,
    #[serde(default)]
    pub tty: bool,
    pub hostname: String,
    pub mounts: Option<Vec<Mount>>,

    pub root_device: Option<String>,

    pub etc_resolv: Option<EtcResolv>,
    pub etc_hosts: Option<Vec<EtcHost>>,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct ImageConfig {
    pub entrypoint: Option<Vec<String>>,
    pub cmd: Option<Vec<String>>,
    pub env: Option<Vec<String>>,
    pub working_dir: Option<String>,
    pub user: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct IPConfig {
    pub gateway: IpNetwork,
    #[serde(rename = "IP")]
    pub ip: IpNetwork,
    pub mask: u8,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct Mount {
    pub mount_path: String,
    pub device_path: String,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct EtcHost {
    pub host: String,
    #[serde(rename = "IP")]
    pub ip: String,
    pub desc: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct EtcResolv {
    pub nameservers: Vec<String>,
}
