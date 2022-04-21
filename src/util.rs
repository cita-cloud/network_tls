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

use crate::config::NetworkConfig;
use rustls_pemfile::{certs, pkcs8_private_keys, rsa_private_keys};
use std::io::BufReader;
use std::sync::Arc;
use tokio_rustls::rustls::client::ServerCertVerifier;
use tokio_rustls::rustls::server::ClientCertVerifier;
use tokio_rustls::rustls::version::{TLS12, TLS13};
use tokio_rustls::rustls::{
    Certificate, ClientConfig, Error as TlsError, PrivateKey, RootCertStore, ServerConfig,
    SupportedCipherSuite, SupportedProtocolVersion, ALL_CIPHER_SUITES,
};
use tokio_rustls::webpki;

fn find_suite(name: &str) -> Option<SupportedCipherSuite> {
    for suite in ALL_CIPHER_SUITES {
        let cs_name = format!("{:?}", suite.suite()).to_lowercase();

        if cs_name == name.to_string().to_lowercase() {
            return Some(*suite);
        }
    }
    None
}

fn lookup_suites(suites: &[String]) -> Vec<SupportedCipherSuite> {
    let mut out = Vec::new();

    for cs_name in suites {
        let scs = find_suite(cs_name);
        match scs {
            Some(s) => out.push(s),
            None => panic!("cannot look up cipher suite '{}'", cs_name),
        }
    }

    out
}

/// Make a vector of protocol versions named in `versions`
fn lookup_versions(versions: &[String]) -> Vec<&'static SupportedProtocolVersion> {
    let mut out = Vec::new();

    for vname in versions {
        let version = match vname.as_ref() {
            "1.2" => &TLS12,
            "1.3" => &TLS13,
            _ => panic!(
                "cannot look up version '{}', valid are '1.2' and '1.3'",
                vname
            ),
        };
        out.push(version);
    }

    out
}

pub fn load_certs(cert_str: &str) -> Vec<Certificate> {
    let mut reader = BufReader::new(cert_str.as_bytes());
    certs(&mut reader)
        .unwrap()
        .into_iter()
        .map(Certificate)
        .collect()
}

fn load_private_key(key_str: &str) -> PrivateKey {
    let mut reader = BufReader::new(key_str.as_bytes());
    let rsa_keys = rsa_private_keys(&mut reader).expect("file contains invalid rsa private key");

    if !rsa_keys.is_empty() {
        return PrivateKey(rsa_keys[0].clone());
    }

    let mut reader = BufReader::new(key_str.as_bytes());
    let pkcs8_keys =
        pkcs8_private_keys(&mut reader).expect("file contains invalid pkcs8 private key");

    assert!(!pkcs8_keys.is_empty());
    PrivateKey(pkcs8_keys[0].clone())
}

/// Build a `ServerConfig` from our NetConfig
pub fn make_server_config(
    config: &NetworkConfig,
    verifier: Arc<dyn ClientCertVerifier>,
) -> ServerConfig {
    let cacerts = load_certs(&config.ca_cert);
    let mut certs = load_certs(&config.cert);
    let priv_key = load_private_key(&config.priv_key);

    // Specially for server.crt not a cert-chain only one server certificate, so manually make
    // a cert-chain.
    if certs.len() == 1 && !cacerts.is_empty() {
        certs.extend(cacerts);
    }

    let server_config = ServerConfig::builder();

    let server_config = if config.cypher_suits.is_some() {
        server_config.with_cipher_suites(&lookup_suites(config.cypher_suits.as_ref().unwrap()))
    } else {
        server_config.with_safe_default_cipher_suites()
    };

    let server_config = server_config.with_safe_default_kx_groups();

    let server_config = if config.protocols.is_some() {
        server_config
            .with_protocol_versions(lookup_versions(config.protocols.as_ref().unwrap()).as_slice())
            .unwrap()
    } else {
        server_config.with_safe_default_protocol_versions().unwrap()
    };

    server_config
        .with_client_cert_verifier(verifier)
        .with_single_cert(certs, priv_key)
        .unwrap()
}

/// Build a `ClientConfig` from our NetConfig
pub fn make_client_config(
    config: &NetworkConfig,
    verifier: Arc<dyn ServerCertVerifier>,
) -> ClientConfig {
    let client_config = ClientConfig::builder();

    let client_config = if config.cypher_suits.is_some() {
        client_config.with_cipher_suites(&lookup_suites(config.cypher_suits.as_ref().unwrap()))
    } else {
        client_config.with_safe_default_cipher_suites()
    };

    let client_config = client_config.with_safe_default_kx_groups();

    let client_config = if config.protocols.is_some() {
        client_config
            .with_protocol_versions(lookup_versions(config.protocols.as_ref().unwrap()).as_slice())
            .unwrap()
    } else {
        client_config.with_safe_default_protocol_versions().unwrap()
    };

    let mut reader = BufReader::new(config.ca_cert.as_bytes());

    let mut client_root_cert_store = RootCertStore::empty();
    client_root_cert_store.add_parsable_certificates(&certs(&mut reader).unwrap());

    let client_config = client_config.with_root_certificates(client_root_cert_store);

    let mut certs = load_certs(&config.cert);
    let cacerts = load_certs(&config.ca_cert);
    let priv_key = load_private_key(&config.priv_key);

    // Specially for server.crt not a cert-chain only one server certificate, so manually make
    // a cert-chain.
    if certs.len() == 1 && !cacerts.is_empty() {
        certs.extend(cacerts);
    }

    let mut client_config = client_config.with_single_cert(certs, priv_key).unwrap();

    client_config.dangerous().set_certificate_verifier(verifier);
    client_config
}

pub fn pki_error(error: webpki::Error) -> TlsError {
    use webpki::Error::*;
    match error {
        BadDer | BadDerTime => TlsError::InvalidCertificateEncoding,
        InvalidSignatureForPublicKey => TlsError::InvalidCertificateSignature,
        UnsupportedSignatureAlgorithm | UnsupportedSignatureAlgorithmForPublicKey => {
            TlsError::InvalidCertificateSignatureType
        }
        e => TlsError::InvalidCertificateData(format!("invalid peer certificate: {}", e)),
    }
}
