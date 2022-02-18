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

use std::collections::HashMap;
use std::io::BufReader;
use std::sync::Arc;

use tracing::{error, info, warn};

use parking_lot::RwLock;

use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio_rustls::{
    rustls::{
        internal::pemfile, Certificate, ClientCertVerified, ClientCertVerifier, ClientConfig,
        DistinguishedNames, OwnedTrustAnchor, RootCertStore, ServerConfig, Session, TLSError,
    },
    webpki::{self, DNSNameRef},
    TlsAcceptor,
};

use tonic::transport::{Channel, Endpoint};
use tonic::{Request, Response};

use x509_parser::extensions::GeneralName;
use x509_parser::prelude::X509Certificate;
use x509_parser::traits::FromDer;

use tentacle_multiaddr::MultiAddr;
use tentacle_multiaddr::Protocol;

use crate::{
    config::NetworkConfig,
    peer::Peer,
    peer::PeerHandle,
    proto::{
        Empty, NetworkMsg, NetworkMsgHandlerServiceClient, NetworkService, NetworkServiceServer,
        NetworkStatusResponse, NodeNetInfo, RegisterInfo, StatusCode, TotalNodeNetInfo,
    },
};

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

struct AllowKnownPeerOnly {
    roots: RootCertStore,
    peers: Arc<RwLock<HashMap<String, PeerHandle>>>,
}

impl ClientCertVerifier for AllowKnownPeerOnly {
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

        let guard = self.peers.read();
        let known = guard
            .keys()
            .map(|k| DNSNameRef::try_from_ascii(k.as_bytes()).unwrap());

        cert.verify_is_valid_for_at_least_one_dns_name(known)
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

        let (inbound_msg_tx, inbound_msg_rx) = mpsc::channel(1024);
        let peers = {
            let mut peers = HashMap::new();
            for (id, c) in config.peers.into_iter().enumerate() {
                let (peer, handle) = Peer::new(
                    // start from 1
                    (id + 1) as u64,
                    c.domain.clone(),
                    c.host,
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

        let tls_acceptor = {
            let mut server_config = {
                let verifier = AllowKnownPeerOnly {
                    roots,
                    peers: peers.clone(),
                };
                ServerConfig::new(Arc::new(verifier))
            };
            server_config.set_single_cert(certs, priv_key).unwrap();

            TlsAcceptor::from(Arc::new(server_config))
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
            tls_config: client_config,
            inbound_msg_tx,
            reconnect_timeout: config.reconnect_timeout,
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

                let guard = peers.read();
                if let Some(peer) = dns_s.iter().find_map(|dns| guard.get(dns)) {
                    peer.accept(stream);
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

pub struct CitaCloudNetworkServiceServer {
    dispatch_table: Arc<RwLock<HashMap<String, NetworkMsgHandlerServiceClient<Channel>>>>,
    peers: Arc<RwLock<HashMap<String, PeerHandle>>>,

    // for adding new node
    tls_config: Arc<ClientConfig>,
    inbound_msg_tx: mpsc::Sender<NetworkMsg>,
    reconnect_timeout: u64,
}

#[tonic::async_trait]
impl NetworkService for CitaCloudNetworkServiceServer {
    async fn send_msg(
        &self,
        request: Request<NetworkMsg>,
    ) -> Result<Response<StatusCode>, tonic::Status> {
        let mut msg = request.into_inner();
        // This origin only used in local context, and shouldn't leak outside.
        let origin = msg.origin;
        msg.origin = 0;
        let guard = self.peers.read();

        if let Some(peer) = guard.values().find(|peer| peer.id() == origin) {
            peer.send_msg(msg);
        } else {
            // TODO: check if it's necessary
            // fallback to broadcast
            for peer in guard.values() {
                peer.send_msg(msg.clone());
            }
        }

        let ok = StatusCode { code: 0 };
        Ok(Response::new(ok))
    }

    async fn broadcast(
        &self,
        request: Request<NetworkMsg>,
    ) -> Result<Response<StatusCode>, tonic::Status> {
        let mut msg = request.into_inner();
        // This origin only used in local context, and shouldn't leak outside.
        msg.origin = 0;
        let guard = self.peers.read();

        for peer in guard.values() {
            peer.send_msg(msg.clone());
        }

        let ok = StatusCode { code: 0 };
        Ok(Response::new(ok))
    }

    async fn get_network_status(
        &self,
        _request: Request<Empty>,
    ) -> Result<Response<NetworkStatusResponse>, tonic::Status> {
        let reply = NetworkStatusResponse {
            peer_count: self.peers.read().len() as u64,
        };

        Ok(Response::new(reply))
    }

    async fn register_network_msg_handler(
        &self,
        request: Request<RegisterInfo>,
    ) -> Result<Response<StatusCode>, tonic::Status> {
        let info = request.into_inner();
        let module_name = info.module_name;
        let hostname = info.hostname;
        let port = info.port;

        let client = {
            let uri = format!("http://{}:{}", hostname, port);
            let channel = Endpoint::from_shared(uri)
                .map_err(|e| {
                    tonic::Status::invalid_argument(format!("invalid host and port: {}", e))
                })?
                .connect_lazy()
                .unwrap();
            NetworkMsgHandlerServiceClient::new(channel)
        };

        let mut dispatch_table = self.dispatch_table.write();
        dispatch_table.insert(module_name, client);

        let ok = StatusCode { code: 0 };
        Ok(Response::new(ok))
    }

    async fn add_node(
        &self,
        request: Request<NodeNetInfo>,
    ) -> Result<Response<StatusCode>, tonic::Status> {
        let multiaddr = request.into_inner().multi_address;
        let (host, port, domain) = parse_multiaddr(&multiaddr)?;
        info!(
            multiaddr = %multiaddr,
            host = %host, port = %port, domain = %domain,
            "attempts to add new peer"
        );

        let mut peers = self.peers.write();
        if peers.contains_key(&domain) {
            return Ok(Response::new(StatusCode { code: 405 }));
        }

        let (peer, handle) = Peer::new(
            peers.len() as u64 + 1,
            domain.clone(),
            host.clone(),
            port,
            self.tls_config.clone(),
            self.reconnect_timeout,
            self.inbound_msg_tx.clone(),
        );

        tokio::spawn(async move {
            peer.run().await;
        });
        peers.insert(domain.clone(), handle);

        info!(
            multiaddr = %multiaddr,
            host = %host, port = %port, domain = %domain,
            "new peer added"
        );

        Ok(Response::new(StatusCode { code: 0 }))
    }

    async fn get_peers_net_info(
        &self,
        _request: Request<Empty>,
    ) -> Result<Response<TotalNodeNetInfo>, tonic::Status> {
        let mut node_infos: Vec<NodeNetInfo> = vec![];
        let peers = self.peers.read();
        for (domain, p) in peers.iter() {
            let multiaddr = build_multiaddr(p.host(), p.port(), domain);
            node_infos.push(NodeNetInfo {
                multi_address: multiaddr.to_string(),
                origin: p.id(),
            });
        }

        Ok(Response::new(TotalNodeNetInfo { nodes: node_infos }))
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
                let guard = self.dispatch_table.read();
                guard.get(&msg.module).cloned()
            };

            if let Some(mut client) = client {
                let msg_module = msg.module.clone();
                let msg_origin = msg.origin;
                tokio::spawn(async move {
                    if let Err(e) = client.process_network_msg(msg).await {
                        warn!(
                            msg.module = %msg_module,
                            msg.origin = %msg_origin,
                            error = %e,
                            "registered client processes network msg failed"
                        );
                    }
                });
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

fn parse_multiaddr(s: &str) -> Result<(String, u16, String), tonic::Status> {
    let multiaddr = s
        .parse::<MultiAddr>()
        .map_err(|e| tonic::Status::invalid_argument(format!("parse multiaddr failed: `{}`", e)))?;

    let mut host: Option<String> = None;
    let mut port: Option<u16> = None;
    let mut domain: Option<String> = None;
    for ptcl in multiaddr.iter() {
        match ptcl {
            Protocol::Dns4(dns4) => {
                host.replace(dns4.into());
            }
            Protocol::Dns6(dns6) => {
                host.replace(dns6.into());
            }
            Protocol::Ip4(ipv4) => {
                host.replace(ipv4.to_string());
            }
            Protocol::Ip6(ipv6) => {
                host.replace(ipv6.to_string());
            }
            Protocol::Tcp(p) => {
                port.replace(p);
            }
            Protocol::Tls(d) => {
                domain.replace(d.into());
            }
            _ => (),
        }
    }

    let host =
        host.ok_or_else(|| tonic::Status::invalid_argument("host not present in multiaddr"))?;
    let port =
        port.ok_or_else(|| tonic::Status::invalid_argument("port not present in multiaddr"))?;
    let domain =
        domain.ok_or_else(|| tonic::Status::invalid_argument("domain not present in multiaddr"))?;

    Ok((host, port, domain))
}

fn build_multiaddr(host: &str, port: u16, domain: &str) -> String {
    // TODO: default to return Dns4 for host, consider if it' appropriate
    vec![
        Protocol::Dns4(host.into()),
        Protocol::Tcp(port),
        Protocol::Tls(domain.into()),
    ]
    .into_iter()
    .collect::<MultiAddr>()
    .to_string()
}

#[cfg(test)]
mod test {
    use super::build_multiaddr;
    use super::parse_multiaddr;

    #[test]
    fn test_build_multiaddr() {
        assert_eq!(
            build_multiaddr("localhost", 80, "fy"),
            "/dns4/localhost/tcp/80/tls/fy"
        );
    }

    #[test]
    fn test_parse_multiaddr() {
        assert!(parse_multiaddr("/ip4/127.0.0.1/tcp/5678/tls/fy").is_ok());
    }
}
