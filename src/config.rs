// Copyright Rivtower Technologies LLC.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use crate::error::Error;
use cloud_util::common::read_toml;
use md5::{compute, Digest};
use rcgen::BasicConstraints;
use rcgen::Certificate;
use rcgen::CertificateParams;
use rcgen::IsCa;
use rcgen::KeyPair;
use rcgen::PKCS_ECDSA_P256_SHA256;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::prelude::*;
use std::path::Path;

fn default_reconnect_timeout() -> u64 {
    5
}

fn default_try_hot_update_interval() -> u64 {
    60
}

#[derive(Serialize, Deserialize, Clone)]
pub struct PeerConfig {
    pub host: String,
    pub port: u16,
    pub domain: String,
}

#[derive(Serialize, Deserialize)]
#[serde(default)]
pub struct NetworkConfig {
    // server grpc port, as network_port
    pub grpc_port: u16,
    // p2p port
    pub listen_port: u16,
    // node reconnect pod, in seconds
    pub reconnect_timeout: u64,
    // config hot update interval, in senconds
    pub try_hot_update_interval: u64,
    // CA certification, raw string
    pub ca_cert: String,
    // Server certification, raw string
    pub cert: String,
    // Server certification private key
    pub priv_key: String,
    // tls version, choice "1.2" or "1.3"
    pub protocols: Option<Vec<String>>,
    // cypher suits
    pub cypher_suits: Option<Vec<String>>,
    // peers net config info
    pub peers: Vec<PeerConfig>,
}

impl NetworkConfig {
    pub fn new(config_str: &str) -> Self {
        read_toml(config_str, "network_tls")
    }
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            grpc_port: 50000,
            listen_port: 40000,
            reconnect_timeout: 5,
            try_hot_update_interval: 60,
            ca_cert: "".to_string(),
            cert: "".to_string(),
            priv_key: "".to_string(),
            protocols: None,
            cypher_suits: None,
            peers: vec![],
        }
    }
}

// a wrapper
#[derive(Serialize, Deserialize)]
struct Config {
    #[serde(rename = "network_tls")]
    network: NetworkConfig,
}

fn ca_cert() -> (Certificate, String, String) {
    let mut params = CertificateParams::new(vec![]);
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);

    let keypair = KeyPair::generate(&PKCS_ECDSA_P256_SHA256).unwrap();
    params.key_pair.replace(keypair);

    let cert = Certificate::from_params(params).unwrap();
    let cert_pem = cert.serialize_pem_with_signer(&cert).unwrap();
    let key_pem = cert.serialize_private_key_pem();
    (cert, cert_pem, key_pem)
}

fn cert(domain: &str, signer: &Certificate) -> (Certificate, String, String) {
    let subject_alt_names = vec![domain.into()];
    let mut params = CertificateParams::new(subject_alt_names);

    let keypair = KeyPair::generate(&PKCS_ECDSA_P256_SHA256).unwrap();
    params.key_pair.replace(keypair);

    let cert = Certificate::from_params(params).unwrap();
    let cert_pem = cert.serialize_pem_with_signer(signer).unwrap();
    let key_pem = cert.serialize_private_key_pem();
    (cert, cert_pem, key_pem)
}

pub fn generate_config(peer_count: usize) {
    let (ca_cert, ca_cert_pem, ca_key_pem) = ca_cert();

    let mut f = fs::File::create("ca_key.pem").unwrap();
    f.write_all(ca_key_pem.as_bytes()).unwrap();

    let peers: Vec<PeerConfig> = (0..peer_count)
        .map(|i| {
            let domain = format!("peer{}.fy", i);
            let port = (40000 + i) as u16;
            PeerConfig {
                host: "localhost".into(),
                port,
                domain,
            }
        })
        .collect();

    peers.iter().enumerate().for_each(|(i, p)| {
        // peers except ourself
        let mut peers = peers.clone();
        let this = peers.remove(i as usize);

        let (_, cert, priv_key) = cert(&p.domain, &ca_cert);
        let config = {
            let network = NetworkConfig {
                grpc_port: (50000 + i * 1000) as u16,
                listen_port: this.port,
                reconnect_timeout: default_reconnect_timeout(),
                try_hot_update_interval: default_try_hot_update_interval(),
                ca_cert: ca_cert_pem.clone(),
                cert,
                priv_key,
                peers,
                protocols: None,
                cypher_suits: None,
            };
            Config { network }
        };

        let path = format!("peer{}.toml", i);
        let mut f = fs::File::create(&path).unwrap();
        f.write_all(toml::to_string_pretty(&config).unwrap().as_bytes())
            .unwrap();
    });
}

pub fn load_config(path: impl AsRef<Path>) -> Result<NetworkConfig, Error> {
    if let Ok(s) = fs::read_to_string(path) {
        if let Ok(config) = toml::from_str(&s) {
            let c: Config = config;
            Ok(c.network)
        } else {
            Err(Error::ParseTomlFail)
        }
    } else {
        Err(Error::FileNotExist)
    }
}

pub fn calculate_md5(path: impl AsRef<Path>) -> Result<Digest, Error> {
    if let Ok(s) = fs::read_to_string(path) {
        Ok(compute(s))
    } else {
        Err(Error::FileNotExist)
    }
}

#[cfg(test)]
mod tests {
    use super::NetworkConfig;
    use crate::util::{load_certs, load_private_key};

    #[test]
    fn basic_test() {
        let config = NetworkConfig::new("example/config.toml");
        load_certs(&config.ca_cert);
        load_certs(&config.cert);
        load_private_key(&config.priv_key);

        assert_eq!(config.grpc_port, 51234);
        assert_eq!(config.listen_port, 41234);
    }
}
