use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time;
use tokio_stream::StreamExt;

use tokio_rustls::rustls::ClientConfig;
use tokio_rustls::webpki::DNSNameRef;
use tokio_rustls::TlsConnector;

use futures::SinkExt;

use tracing::{info, warn};

use crate::codec::Codec;
use crate::proto::NetworkMsg;

type TlsStream = tokio_rustls::TlsStream<TcpStream>;
type ServerTlsStream = tokio_rustls::server::TlsStream<TcpStream>;
type ClientTlsStream = tokio_rustls::client::TlsStream<TcpStream>;

type Framed = tokio_util::codec::Framed<TlsStream, Codec>;

#[derive(Debug, Clone)]
pub struct PeerHandle {
    id: u64,
    inbound_stream_tx: mpsc::Sender<ServerTlsStream>,
    outbound_msg_tx: mpsc::Sender<NetworkMsg>,
}

impl PeerHandle {
    pub fn id(&self) -> u64 {
        self.id
    }

    pub async fn accept(&self, stream: ServerTlsStream) {
        self.inbound_stream_tx.send(stream).await.unwrap();
    }

    pub async fn send_msg(&self, msg: NetworkMsg) {
        self.outbound_msg_tx.send(msg).await.unwrap();
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
    pub fn new(
        id: u64,
        domain: &str,
        host: &str,
        port: u16,
        tls_config: Arc<ClientConfig>,
        reconnect_timeout: u64,
        inbound_msg_tx: mpsc::Sender<NetworkMsg>,
    ) -> (Peer, PeerHandle) {
        let (inbound_stream_tx, inbound_stream_rx) = mpsc::channel(1);
        let (outbound_msg_tx, outbound_msg_rx) = mpsc::channel(64);

        let peer = Self {
            id,
            domain: domain.into(),
            host: host.into(),
            port,
            tls_config,
            reconnect_timeout,
            outbound_msg_rx,
            inbound_msg_tx,
            inbound_stream_rx,
        };
        let handle = PeerHandle {
            id,
            inbound_stream_tx,
            outbound_msg_tx,
        };

        (peer, handle)
    }

    pub async fn run(mut self) {
        let mut framed: Option<Framed> = None;
        let mut pending_conn: Option<JoinHandle<Result<ClientTlsStream, std::io::Error>>> = None;

        let reconnect_timeout = Duration::from_secs(self.reconnect_timeout);
        let reconnect_timeout_fut = time::sleep(Duration::from_secs(0));
        tokio::pin!(reconnect_timeout_fut);

        loop {
            tokio::select! {
                _ = reconnect_timeout_fut.as_mut(), if framed.is_none() && pending_conn.is_none() => {
                    // try to connect
                    let host = self.host.clone();
                    let port = self.port;

                    let domain = DNSNameRef::try_from_ascii_str(&self.domain).unwrap().to_owned();
                    let tls_config = self.tls_config.clone();

                    let handle = tokio::spawn(async move {
                        let connector = TlsConnector::from(tls_config);

                        let tcp = TcpStream::connect((host.as_str(), port)).await?;
                        connector.connect(domain.as_ref(), tcp).await
                    });

                    pending_conn.replace(handle);
                }
                Ok(conn_result) = async { pending_conn.as_mut().unwrap().await }, if pending_conn.is_some() => {
                    pending_conn.take();

                    match conn_result {
                        Ok(stream) => {
                            info!(
                                peer = %self.domain,
                                r#type = %"outbound",
                                "new connection established"
                            );
                            framed.replace(Framed::new(
                                tokio_rustls::TlsStream::Client(stream),
                                Codec,
                            ));
                        }
                        Err(_) => {
                            reconnect_timeout_fut.as_mut().reset(time::Instant::now() + reconnect_timeout);
                        }
                    }
                }
                Some(stream) = self.inbound_stream_rx.recv() => {
                    if let Some(h) = pending_conn.take() {
                        h.abort();
                    }
                    // receive new stream
                    if framed.is_none() {
                        info!(
                            peer = %self.domain,
                            r#type = %"inbound",
                            "new connection established"
                        );
                        framed.replace(Framed::new(
                            tokio_rustls::TlsStream::Server(stream),
                            Codec
                        ));
                    }
                }
                // send out msg
                Some(msg) = self.outbound_msg_rx.recv() => {
                    if let Some(fd) = framed.as_mut() {
                        if let Err(e) = fd.send(msg).await {
                            warn!(
                                peer = %self.domain,
                                reason = %e,
                                "send out msg failed, drop connection"
                            );
                            framed.take();
                            reconnect_timeout_fut.as_mut().reset(time::Instant::now() + reconnect_timeout);
                        }
                    }
                }
                Some(result) = async { framed.as_mut().unwrap().next().await }, if framed.is_some() => {
                    match result {
                        Ok(mut msg) => {
                            msg.origin = self.id;
                            let _ = self.inbound_msg_tx.send(msg).await;
                        }
                        Err(e) => {
                            println!("framed stream report error: {}", e);
                            framed.take();
                            reconnect_timeout_fut.as_mut().reset(time::Instant::now() + reconnect_timeout);
                        }
                    }
                }
                else => {
                    println!("Server stoped.");
                }
            }
        }
    }
}
