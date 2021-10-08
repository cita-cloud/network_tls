use std::fs::File;
use std::io::prelude::*;
use std::path::Path;

use rcgen::BasicConstraints;
use rcgen::Certificate;
use rcgen::CertificateParams;
use rcgen::IsCa;
use rcgen::KeyPair;
use rcgen::PKCS_ECDSA_P256_SHA256;

use toml::Value;

use serde::{Deserialize, Serialize};

fn default_reconnect_timeout() -> u64 {
    5
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PeerConfig {
    pub host: String,
    pub port: u16,

    // TODO: is this name suitable?
    pub domain: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct NetworkConfig {
    pub grpc_port: u16,
    pub listen_port: u16,

    #[serde(default = "default_reconnect_timeout")]
    pub reconnect_timeout: u64, // in seconds

    pub ca_cert: String,

    pub cert: String,
    // TODO: better security
    pub priv_key: String,

    #[serde(default)]
    // https://github.com/alexcrichton/toml-rs/issues/258
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub peers: Vec<PeerConfig>,
}

// a wrapper
#[derive(Serialize, Deserialize, Debug, Clone)]
struct Config {
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

    let mut f = File::create("ca_key.pem").unwrap();
    f.write_all(ca_key_pem.as_bytes()).unwrap();

    let peers: Vec<PeerConfig> = (0..peer_count)
        .map(|i| {
            let domain = format!("peer{}.fy", i);
            let port = (30000 + i * 1000) as u16;
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
                ca_cert: ca_cert_pem.clone(),
                cert,
                priv_key,
                peers,
            };
            Config { network }
        };

        let path = format!("peer{}.toml", i);
        let mut f = File::create(&path).unwrap();
        f.write_all(toml::to_string_pretty(&config).unwrap().as_bytes())
            .unwrap();
    });
}

pub fn load_config(path: impl AsRef<Path>) -> NetworkConfig {
    let s = {
        let mut f = File::open(path).unwrap();
        let mut buf = String::new();
        f.read_to_string(&mut buf).unwrap();
        buf
    };

    let config: Value = s.parse().unwrap();
    NetworkConfig::deserialize(config["network"].clone()).unwrap()
}
