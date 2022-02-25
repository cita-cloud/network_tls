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
use std::sync::Arc;
use std::task::Poll;
use std::time::Duration;

use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time;

use tokio_stream::Stream;
use tokio_stream::StreamExt;

use tokio_rustls::rustls::ClientConfig;
use tokio_rustls::webpki::DNSNameRef;
use tokio_rustls::TlsConnector;

use futures::future::poll_fn;
use futures::SinkExt;

use tracing::{debug, info, warn};

use crate::codec::Codec;
use crate::codec::DecodeError;
use crate::proto::NetworkMsg;

type TlsStream = tokio_rustls::TlsStream<TcpStream>;
type ServerTlsStream = tokio_rustls::server::TlsStream<TcpStream>;
type ClientTlsStream = tokio_rustls::client::TlsStream<TcpStream>;

type Framed = tokio_util::codec::Framed<TlsStream, Codec>;

#[derive(Debug, Clone)]
pub struct PeersManger {
    from_config_peers: HashMap<String, PeerHandle>,
    connected_peers: HashMap<String, PeerHandle>,
}

impl PeersManger {
    pub fn new(from_config_peers: HashMap<String, PeerHandle>) -> Self {
        Self {
            from_config_peers,
            connected_peers: HashMap::new(),
        }
    }

    pub fn get_from_config_peers(&self) -> &HashMap<String, PeerHandle> {
        &self.from_config_peers
    }

    pub fn add_from_config_peers(
        &mut self,
        domain: String,
        peer_handle: PeerHandle,
    ) -> Option<PeerHandle> {
        debug!("add_from_config_peers: {}", domain);
        self.from_config_peers.insert(domain, peer_handle)
    }

    pub fn get_connected_peers(&self) -> &HashMap<String, PeerHandle> {
        &self.connected_peers
    }

    pub fn add_connected_peers(&mut self, domain: &str) -> Option<PeerHandle> {
        debug!("add_connected_peers: {}", domain);
        self.connected_peers.insert(
            domain.to_owned(),
            self.get_from_config_peers().get(domain).unwrap().clone(),
        )
    }

    pub fn delete_connected_peers(&mut self, domain: &str) {
        if let Some(peer_handle) = self.connected_peers.get(domain) {
            debug!("delete_connected_peers: {}", domain);
            peer_handle.handle.abort();
            self.connected_peers.remove(domain);
        }
    }

    #[allow(dead_code)]
    pub fn delete_peer(&mut self, domain: &str) {
        if self.from_config_peers.get(domain).is_some() {
            debug!("delete_peer: {}", domain);
            self.from_config_peers.remove(domain);
            self.delete_connected_peers(domain);
        }
    }
}

#[derive(Debug, Clone)]
pub struct PeerHandle {
    id: u64,
    host: String,
    port: u16,
    inbound_stream_tx: mpsc::Sender<ServerTlsStream>,
    outbound_msg_tx: mpsc::Sender<NetworkMsg>,
    // run handle
    handle: Arc<JoinHandle<()>>,
}

impl PeerHandle {
    pub fn id(&self) -> u64 {
        self.id
    }

    pub fn host(&self) -> &str {
        &self.host
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn accept(&self, stream: ServerTlsStream) {
        let inbound_stream_tx = self.inbound_stream_tx.clone();
        tokio::spawn(async move {
            let _ = inbound_stream_tx.send(stream).await;
        });
    }

    pub fn send_msg(&self, msg: NetworkMsg) {
        let outbound_msg_tx = self.outbound_msg_tx.clone();
        tokio::spawn(async move {
            let _ = outbound_msg_tx.send(msg).await;
        });
    }
}

pub struct Peer {
    id: u64,

    domain: String,
    host: String,
    port: u16,

    tls_config: Arc<ClientConfig>,
    reconnect_timeout: u64,

    // msg to send to this peer
    outbound_msg_rx: mpsc::Receiver<NetworkMsg>,
    // msg received from this peer
    inbound_msg_tx: mpsc::Sender<NetworkMsg>,

    inbound_stream_rx: mpsc::Receiver<ServerTlsStream>,
}

impl Peer {
    pub fn init(
        id: u64,
        domain: String,
        host: String,
        port: u16,
        tls_config: Arc<ClientConfig>,
        reconnect_timeout: u64,
        inbound_msg_tx: mpsc::Sender<NetworkMsg>,
    ) -> PeerHandle {
        let (inbound_stream_tx, inbound_stream_rx) = mpsc::channel(1);
        let (outbound_msg_tx, outbound_msg_rx) = mpsc::channel(1024);

        let peer = Self {
            id,
            domain,
            host: host.clone(),
            port,
            tls_config,
            reconnect_timeout,
            outbound_msg_rx,
            inbound_msg_tx,
            inbound_stream_rx,
        };

        let handle = Arc::new(tokio::spawn(async move {
            peer.run().await;
        }));

        PeerHandle {
            id,
            host,
            port,
            inbound_stream_tx,
            outbound_msg_tx,
            handle,
        }
    }

    pub async fn run(mut self) {
        let mut framed: Option<Framed> = None;
        let mut pending_conn: Option<JoinHandle<Result<ClientTlsStream, std::io::Error>>> = None;

        let reconnect_timeout = Duration::from_secs(self.reconnect_timeout);
        let reconnect_timeout_fut = time::sleep(Duration::from_secs(0));
        tokio::pin!(reconnect_timeout_fut);

        loop {
            tokio::select! {
                // spawn task to connect to this peer; outbound stream
                _ = reconnect_timeout_fut.as_mut(), if framed.is_none() && pending_conn.is_none() => {
                    let host = self.host.clone();
                    let port = self.port;
                    info!(peer = %self.domain, host = %host, port = %port, "connecting..");

                    let domain = DNSNameRef::try_from_ascii_str(&self.domain).unwrap().to_owned();
                    let tls_config = self.tls_config.clone();

                    let handle = tokio::spawn(async move {
                        let connector = TlsConnector::from(tls_config);

                        let tcp = TcpStream::connect((host.as_str(), port)).await?;
                        connector.connect(domain.as_ref(), tcp).await
                    });

                    pending_conn.replace(handle);
                }
                // handle previous connection task's result
                Ok(conn_result) = async { pending_conn.as_mut().unwrap().await }, if pending_conn.is_some() => {
                    pending_conn.take();

                    match conn_result {
                        Ok(stream) => {
                            info!(
                                peer = %self.domain,
                                host = %self.host,
                                port = %self.port,
                                r#type = %"outbound",
                                "new connection established"
                            );
                            framed.replace(Framed::new(
                                tokio_rustls::TlsStream::Client(stream),
                                Codec,
                            ));
                        }
                        Err(e) => {
                            debug!(
                                peer = %self.domain,
                                host = %self.host,
                                port = %self.port,
                                reason = %e,
                                "cannot connect to peer"
                            );
                            reconnect_timeout_fut.as_mut().reset(time::Instant::now() + reconnect_timeout);
                        }
                    }
                }
                // accept the established conn from this peer; inbound stream
                Some(stream) = self.inbound_stream_rx.recv() => {
                    if let Some(h) = pending_conn.take() {
                        h.abort();
                    }
                    // receive new stream
                    if framed.is_none() {
                        let incoming_peer_addr = stream.get_ref().0
                            .peer_addr()
                            .map(|s| s.to_string())
                            .unwrap_or_else(|e| format!("`unavalable: {}`", e));
                        info!(
                            peer = %self.domain,
                            host = %self.host,
                            port = %self.port,
                            incoming_peer_addr = ?incoming_peer_addr,
                            r#type = %"inbound",
                            "new connection established"
                        );
                        framed.replace(Framed::new(
                            tokio_rustls::TlsStream::Server(stream),
                            Codec
                        ));
                    }
                }
                // send out msgs to this peer; outbound msgs
                Some(msg) = self.outbound_msg_rx.recv() => {
                    // drain all the available outbound msgs
                    let mut msgs = vec![msg];
                    poll_fn(|cx| {
                        while let Poll::Ready(Some(msg)) = self.outbound_msg_rx.poll_recv(cx) {
                            msgs.push(msg);
                        }
                        Poll::Ready(())
                    }).await;

                    if let Some(fd) = framed.as_mut() {
                        let mut last_result = Ok(());
                        for msg in msgs {
                            last_result = fd.feed(msg).await;
                            if last_result.is_err() {
                                break;
                            }
                        }

                        if last_result.is_ok() {
                            last_result = fd.flush().await;
                        }
                        if let Err(e) = last_result {
                            warn!(
                                peer = %self.domain,
                                host = %self.host,
                                port = %self.port,
                                reason = %e,
                                "send outbound msgs failed, drop the stream"
                            );
                            framed.take();
                            reconnect_timeout_fut.as_mut().reset(time::Instant::now() + reconnect_timeout);
                        }
                    } else {
                        warn!(
                            peer = %self.domain,
                            host = %self.host,
                            port = %self.port,
                            msgs_cnt = %msgs.len(),
                            "drop outbound msgs since no available stream to this peer"
                        );
                    }
                }
                // receive msgs from this peer; inbound msgs
                opt_res = async { framed.as_mut().unwrap().next().await }, if framed.is_some() => {
                    // handle items produced by the stream; return true if the stream should be dropped
                    let f = |opt_res: Option<Result<NetworkMsg, DecodeError>>| {
                        match opt_res {
                            Some(Ok(mut msg)) => {
                                msg.origin = self.id;

                                let inbound_msg_tx = self.inbound_msg_tx.clone();
                                tokio::spawn(async move {
                                    let _ = inbound_msg_tx.send(msg).await;
                                });
                                false
                            }
                            Some(Err(DecodeError::Io(e))) => {
                                // drop the stream
                                warn!(
                                    peer = %self.domain,
                                    host = %self.host,
                                    port = %self.port,
                                    reason = %e,
                                    "framed stream report io error, will drop the stream"
                                );
                                true
                            }
                            Some(Err(e)) => {
                                warn!(
                                    peer = %self.domain,
                                    host = %self.host,
                                    port = %self.port,
                                    reason = %e,
                                    "framed stream report decode error"
                                );
                                false
                            }
                            None => {
                                warn!(
                                    peer = %self.domain,
                                    host = %self.host,
                                    port = %self.port,
                                    "framed stream end, will drop it"
                                );
                                true
                            }
                        }
                    };

                    // drain all the available inbound msgs
                    let mut wants_drop = f(opt_res);
                    if !wants_drop {
                        poll_fn(|cx| {
                            loop {
                                let framed_stream = Pin::new(framed.as_mut().unwrap());
                                match framed_stream.poll_next(cx) {
                                    Poll::Ready(opt_res) => {
                                        wants_drop = f(opt_res);
                                        if wants_drop {
                                            break;
                                        }
                                    }
                                    Poll::Pending => break,
                                }
                            }
                            Poll::Ready(())
                        }).await;
                    }

                    if wants_drop {
                        framed.take();
                        reconnect_timeout_fut.as_mut().reset(time::Instant::now() + reconnect_timeout);
                    }
                }
                else => {
                    info!(
                        peer = %self.domain,
                        host = %self.host,
                        port = %self.port,
                        "Peer stopped",
                    );
                }
            }
        }
    }
}
