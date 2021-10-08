use std::collections::HashMap;
use std::io::BufReader;
use std::sync::Arc;

use tracing::{info, warn, error};

use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio::sync::RwLock;
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

// The `ClientCertVerifier` impl is from [rustls](https://docs.rs/rustls/0.20.0/src/rustls/verify.rs.html)

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

struct AllowKnownClientOnly {
    roots: RootCertStore,
    known: Vec<DNSName>,
}

impl ClientCertVerifier for AllowKnownClientOnly {
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
        cert.verify_is_valid_tls_client_cert(
            SUPPORTED_SIG_ALGS,
            &webpki::TLSClientTrustAnchors(&trustroots),
            &chain,
            now,
        )
        .map_err(TLSError::WebPKIError)?;

        cert.verify_is_valid_for_at_least_one_dns_name(self.known.iter().map(|n| n.as_ref()))
            .map_err(TLSError::WebPKIError)?;

        Ok(ClientCertVerified::assertion())
    }
}

pub struct Server {
    listen_port: u16,
    peers: Arc<RwLock<HashMap<String, PeerHandle>>>,

    tls_acceptor: TlsAcceptor,
}

impl Server {
    pub async fn setup(config: NetworkConfig) {
        let certs = {
            let mut rd = BufReader::new(config.cert.as_bytes());
            pemfile::certs(&mut rd).unwrap()
        };
        let priv_key = {
            let mut rd = BufReader::new(config.priv_key.as_bytes());
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

                let verifier = AllowKnownClientOnly { roots, known };
                ServerConfig::new(Arc::new(verifier))
            };
            server_config.set_single_cert(certs, priv_key).unwrap();

            TlsAcceptor::from(Arc::new(server_config))
        };

        let (inbound_msg_tx, inbound_msg_rx) = mpsc::channel(1024);
        let peers = {
            let mut peers = HashMap::new();
            for (id, c) in config.peers.into_iter().enumerate() {
                let (peer, handle) = Peer::new(
                    // start from 1
                    (id + 1) as u64,
                    &c.domain,
                    &c.host,
                    c.port,
                    client_config.clone(),
                    config.reconnect_timeout,
                    inbound_msg_tx.clone(),
                );
                tokio::spawn(async move {
                    peer.run().await;
                });
                peers.insert(c.domain, handle);
            }
            Arc::new(RwLock::new(peers))
        };

        let dispatch_table = Arc::new(RwLock::new(HashMap::new()));
        let dispatcher = NetworkMsgDispatcher {
            dispatch_table: dispatch_table.clone(),
            inbound_msg_rx,
        };
        tokio::spawn(async move {
            dispatcher.run().await;
        });

        let network_svc = CitaCloudNetworkServiceServer {
            dispatch_table,
            peers: peers.clone(),
        };
        let grpc_addr = format!("0.0.0.0:{}", config.grpc_port).parse().unwrap();
        tokio::spawn(async move {
            tonic::transport::Server::builder()
                .add_service(NetworkServiceServer::new(network_svc))
                .serve(grpc_addr)
                .await
                .unwrap();
        });

        let this = Self {
            listen_port: config.listen_port,
            peers,
            tls_acceptor,
        };

        this.serve().await;
    }

    async fn serve(self) {
        let addr = ("0.0.0.0", self.listen_port);
        let listener = TcpListener::bind(addr).await.unwrap();

        info!("listen on `{}:{}`", addr.0, addr.1);

        loop {
            let (stream, _) = match listener.accept().await {
                Ok(stream) => stream,
                Err(e) => {
                    warn!("accept tcp stream error: {}", e);
                    continue;
                }
            };

            let tls_acceptor = self.tls_acceptor.clone();
            let peers = self.peers.clone();
            tokio::spawn(async move {
                // TODO: consider those unwraps and logic
                let stream = match tls_acceptor.accept(stream).await {
                    Ok(stream) => stream,
                    Err(e) => {
                        warn!("tls report error: {}", e);
                        return;
                    }
                };
                let certs = stream.get_ref().1.get_peer_certificates().unwrap();
                let dns_s: Vec<String> = {
                    let cert = certs.first().unwrap();
                    let (_, parsed) = X509Certificate::from_der(cert.as_ref()).unwrap();
                    let (_, san) = parsed.tbs_certificate.subject_alternative_name().unwrap();
                    san.general_names
                        .iter()
                        .filter_map(|n| {
                            if let GeneralName::DNSName(dns) = *n {
                                Some(dns.to_owned())
                            } else {
                                None
                            }
                        })
                        .collect()
                };

                let guard = peers.read().await;
                if let Some(peer) = dns_s.iter().find_map(|dns| guard.get(dns)) {
                    peer.accept(stream).await;
                } else {
                    error!(
                        peers = ?&*guard,
                        cert.dns = ?dns_s,
                        "no peer instance for this connection"
                    );
                }
            });
        }
    }
}

use crate::proto::{
    Empty, NetworkMsgHandlerServiceClient, NetworkService, NetworkServiceServer,
    NetworkStatusResponse, RegisterInfo, SimpleResponse,
};
use tonic::transport::{Channel, Endpoint};
use tonic::{Request, Response, Status};

pub struct CitaCloudNetworkServiceServer {
    dispatch_table: Arc<RwLock<HashMap<String, NetworkMsgHandlerServiceClient<Channel>>>>,
    peers: Arc<RwLock<HashMap<String, PeerHandle>>>,
}

#[tonic::async_trait]
impl NetworkService for CitaCloudNetworkServiceServer {
    async fn send_msg(
        &self,
        request: Request<NetworkMsg>,
    ) -> Result<Response<SimpleResponse>, Status> {
        let mut msg = request.into_inner();
        // This origin only used in local context, and shouldn't leak outside.
        let origin = msg.origin;
        msg.origin = 0;
        let guard = self.peers.read().await;

        if let Some(peer) = guard.values().find(|peer| peer.id() == origin) {
            peer.send_msg(msg).await;
        } else {
            // TODO: check if it's necessary
            // fallback to broadcast
            for peer in guard.values() {
                peer.send_msg(msg.clone()).await;
            }
        }

        let reply = SimpleResponse { is_success: true };
        Ok(Response::new(reply))
    }

    async fn broadcast(
        &self,
        request: Request<NetworkMsg>,
    ) -> Result<Response<SimpleResponse>, Status> {
        let mut msg = request.into_inner();
        // This origin only used in local context, and shouldn't leak outside.
        msg.origin = 0;
        let guard = self.peers.read().await;

        for peer in guard.values() {
            peer.send_msg(msg.clone()).await;
        }

        let reply = SimpleResponse { is_success: true };
        Ok(Response::new(reply))
    }

    async fn get_network_status(
        &self,
        _request: Request<Empty>,
    ) -> Result<Response<NetworkStatusResponse>, Status> {
        let reply = NetworkStatusResponse {
            peer_count: self.peers.read().await.len() as u64,
        };

        Ok(Response::new(reply))
    }

    async fn register_network_msg_handler(
        &self,
        request: Request<RegisterInfo>,
    ) -> Result<Response<SimpleResponse>, Status> {
        let info = request.into_inner();
        let module_name = info.module_name;
        let hostname = info.hostname;
        let port = info.port;

        let client = {
            let uri = format!("http://{}:{}", hostname, port);
            let channel = Endpoint::from_shared(uri)
                .map_err(|e| Status::invalid_argument(format!("invalid host and port: {}", e)))?
                .connect_lazy()
                .unwrap();
            NetworkMsgHandlerServiceClient::new(channel)
        };

        let mut dispatch_table = self.dispatch_table.write().await;
        dispatch_table.insert(module_name, client);

        let reply = SimpleResponse { is_success: true };
        Ok(Response::new(reply))
    }
}

pub struct NetworkMsgDispatcher {
    inbound_msg_rx: mpsc::Receiver<NetworkMsg>,
    dispatch_table: Arc<RwLock<HashMap<String, NetworkMsgHandlerServiceClient<Channel>>>>,
}

impl NetworkMsgDispatcher {
    async fn run(mut self) {
        while let Some(msg) = self.inbound_msg_rx.recv().await {
            let client = {
                let guard = self.dispatch_table.read().await;
                guard.get(&msg.module).cloned()
            };

            if let Some(mut client) = client {
                let msg_module = msg.module.clone();
                let msg_origin = msg.origin;
                if let Err(e) = client.process_network_msg(msg).await {
                    warn!(
                        msg.module = %msg_module,
                        msg.origin = %msg_origin,
                        error = %e,
                        "registered client processes network msg failed"
                    );
                }
            } else {
                warn!(
                    %msg.module,
                    %msg.origin,
                    "unregistered module, will drop msg"
                );
            }
        }
    }
}
