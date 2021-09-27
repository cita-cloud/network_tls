use std::collections::HashMap;
use std::io::BufReader;
use std::sync::Arc;

use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio_rustls::{
    rustls::{
        internal::pemfile, Certificate, ClientCertVerified, ClientCertVerifier, ClientConfig,
        DistinguishedNames, OwnedTrustAnchor, RootCertStore, ServerConfig, Session, TLSError,
    },
    webpki::{self, DNSName, DNSNameRef},
    TlsAcceptor,
};

use x509_parser::extensions::GeneralName;
use x509_parser::prelude::X509Certificate;
use x509_parser::traits::FromDer;

use crate::{config::NetworkConfig, peer::Peer, peer::PeerHandle, proto::NetworkMsg};

type SignatureAlgorithms = &'static [&'static webpki::SignatureAlgorithm];

/// Which signature verification mechanisms we support.  No particular
/// order.
static SUPPORTED_SIG_ALGS: SignatureAlgorithms = &[
    &webpki::ECDSA_P256_SHA256,
    &webpki::ECDSA_P256_SHA384,
    &webpki::ECDSA_P384_SHA256,
    &webpki::ECDSA_P384_SHA384,
    &webpki::ED25519,
    &webpki::RSA_PSS_2048_8192_SHA256_LEGACY_KEY,
    &webpki::RSA_PSS_2048_8192_SHA384_LEGACY_KEY,
    &webpki::RSA_PSS_2048_8192_SHA512_LEGACY_KEY,
    &webpki::RSA_PKCS1_2048_8192_SHA256,
    &webpki::RSA_PKCS1_2048_8192_SHA384,
    &webpki::RSA_PKCS1_2048_8192_SHA512,
    &webpki::RSA_PKCS1_3072_8192_SHA384,
];

type CertChainAndRoots<'a, 'b> = (
    webpki::EndEntityCert<'a>,
    Vec<&'a [u8]>,
    Vec<webpki::TrustAnchor<'b>>,
);

fn try_now() -> Result<webpki::Time, TLSError> {
    webpki::Time::try_from(std::time::SystemTime::now())
        .map_err(|_| TLSError::FailedToGetCurrentTime)
}

fn prepare<'a, 'b>(
    roots: &'b RootCertStore,
    presented_certs: &'a [Certificate],
) -> Result<CertChainAndRoots<'a, 'b>, TLSError> {
    if presented_certs.is_empty() {
        return Err(TLSError::NoCertificatesPresented);
    }

    // EE cert must appear first.
    let cert = webpki::EndEntityCert::from(&presented_certs[0].0).map_err(TLSError::WebPKIError)?;

    let chain: Vec<&'a [u8]> = presented_certs
        .iter()
        .skip(1)
        .map(|cert| cert.0.as_ref())
        .collect();

    let trustroots: Vec<webpki::TrustAnchor> = roots
        .roots
        .iter()
        .map(OwnedTrustAnchor::to_trust_anchor)
        .collect();

    Ok((cert, chain, trustroots))
}

struct AllowKnownAuthenticatedClient {
    roots: RootCertStore,
    known: Vec<DNSName>,
}

impl ClientCertVerifier for AllowKnownAuthenticatedClient {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self, _sni: Option<&webpki::DNSName>) -> Option<bool> {
        Some(true)
    }

    fn client_auth_root_subjects(
        &self,
        _sni: Option<&webpki::DNSName>,
    ) -> Option<DistinguishedNames> {
        Some(self.roots.get_subjects())
    }

    fn verify_client_cert(
        &self,
        presented_certs: &[Certificate],
        _sni: Option<&webpki::DNSName>,
    ) -> Result<ClientCertVerified, TLSError> {
        let (cert, chain, trustroots) = prepare(&self.roots, presented_certs)?;
        let now = try_now()?;
        dbg!(cert.verify_is_valid_tls_client_cert(
            SUPPORTED_SIG_ALGS,
            &webpki::TLSClientTrustAnchors(&trustroots),
            &chain,
            now,
        ))
        .map_err(TLSError::WebPKIError)?;

        cert.verify_is_valid_for_at_least_one_dns_name(self.known.iter().map(|n| n.as_ref()))
            .map_err(TLSError::WebPKIError)?;

        Ok(ClientCertVerified::assertion())
    }
}

pub struct Server {
    listen_port: u16,
    peers: Arc<HashMap<String, PeerHandle>>,

    tls_acceptor: TlsAcceptor,

    inbound_msg_rx: Option<mpsc::Receiver<NetworkMsg>>,
}

impl Server {
    pub fn new(config: NetworkConfig) -> Self {
        let certs = {
            let mut rd = BufReader::new(config.cert.as_bytes());
            pemfile::certs(&mut rd).unwrap()
        };
        let priv_key = {
            let mut rd = BufReader::new(config.priv_key.as_ref().unwrap().as_bytes());
            pemfile::pkcs8_private_keys(&mut rd).unwrap().remove(0)
        };

        let roots = {
            let mut rd = BufReader::new(config.ca_cert.as_bytes());
            let mut roots = RootCertStore::empty();
            roots.add_pem_file(&mut rd).unwrap();
            roots
        };

        let client_config = {
            let mut client_config = ClientConfig::new();
            client_config.root_store = roots.clone();
            client_config
                .set_single_client_cert(certs.clone(), priv_key.clone())
                .unwrap();
            Arc::new(client_config)
        };

        let tls_acceptor = {
            let mut server_config = {
                let known = config
                    .peers
                    .iter()
                    .map(|c| {
                        DNSNameRef::try_from_ascii(c.domain.as_bytes())
                            .unwrap()
                            .to_owned()
                    })
                    .collect();

                let verifier = AllowKnownAuthenticatedClient { roots, known };
                ServerConfig::new(Arc::new(verifier))
            };
            server_config.set_single_cert(certs, priv_key).unwrap();

            TlsAcceptor::from(Arc::new(server_config))
        };

        let (inbound_msg_tx, inbound_msg_rx) = mpsc::channel(64);
        let mut peers = HashMap::new();
        for c in config.peers {
            let (peer, handle) = Peer::new(&c.domain, &c.host, c.port, inbound_msg_tx.clone());
            let client_config = client_config.clone();
            tokio::spawn(async move {
                peer.run(client_config).await;
            });
            peers.insert(c.domain, handle);
        }
        Self {
            listen_port: config.listen_port,
            peers: Arc::new(peers),
            tls_acceptor,
            inbound_msg_rx: Some(inbound_msg_rx),
        }
    }

    pub async fn serve(mut self) {
        let listener = TcpListener::bind(("0.0.0.0", self.listen_port))
            .await
            .unwrap();

        let peers = self.peers.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                let h = peers.values().next().unwrap();
                h.send_msg(NetworkMsg {
                    module: "network".into(),
                    r#type: "test".into(),
                    origin: 42,
                    msg: vec![],
                })
                .await;
            }
        });

        let mut inbound_msg_rx = self.inbound_msg_rx.take().unwrap();
        tokio::spawn(async move {
            while let Some(msg) = inbound_msg_rx.recv().await {
                println!("recv {:?}", msg);
            }
        });

        loop {
            let (stream, _) = listener.accept().await.unwrap();

            let tls_acceptor = self.tls_acceptor.clone();
            let peers = self.peers.clone();
            tokio::spawn(async move {
                // TODO: consider those unwraps and logic
                let stream = tls_acceptor.accept(stream).await.unwrap();
                let certs = stream.get_ref().1.get_peer_certificates().unwrap();
                let dns = {
                    let cert = certs.first().unwrap();
                    let (_, parsed) = X509Certificate::from_der(cert.as_ref()).unwrap();
                    let (_, san) = parsed.tbs_certificate.subject_alternative_name().unwrap();
                    san.general_names
                        .iter()
                        .find_map(|n| {
                            if let GeneralName::DNSName(dns) = *n {
                                Some(dns.to_owned())
                            } else {
                                None
                            }
                        })
                        .unwrap()
                };
                if let Some(peer) = peers.get(&dns) {
                    peer.accept(stream).await;
                }
            });
        }
    }
}
