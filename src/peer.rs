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

use crate::codec::Codec;
use crate::proto::NetworkMsg;

type TlsStream = tokio_rustls::TlsStream<TcpStream>;
type ServerTlsStream = tokio_rustls::server::TlsStream<TcpStream>;
type ClientTlsStream = tokio_rustls::client::TlsStream<TcpStream>;

type Framed = tokio_util::codec::Framed<TlsStream, Codec>;

#[derive(Debug, Clone)]
pub struct PeerHandle {
    inbound_stream_tx: mpsc::Sender<ServerTlsStream>,
    outbound_msg_tx: mpsc::Sender<NetworkMsg>,
}

impl PeerHandle {
    pub async fn accept(&self, stream: ServerTlsStream) {
        self.inbound_stream_tx.send(stream).await.unwrap();
    }

    pub async fn send_msg(&self, msg: NetworkMsg) {
        self.outbound_msg_tx.send(msg).await.unwrap();
    }
}

pub struct Peer {
    domain: String,
    host: String,
    port: u16,

    inbound_stream_rx: mpsc::Receiver<ServerTlsStream>,

    // msg to send to this peer
    outbound_msg_rx: mpsc::Receiver<NetworkMsg>,
    // msg received from this peer
    inbound_msg_tx: mpsc::Sender<NetworkMsg>,
}

impl Peer {
    pub fn new(
        domain: &str,
        host: &str,
        port: u16,
        inbound_msg_tx: mpsc::Sender<NetworkMsg>,
    ) -> (Peer, PeerHandle) {
        let (inbound_stream_tx, inbound_stream_rx) = mpsc::channel(1);
        let (outbound_msg_tx, outbound_msg_rx) = mpsc::channel(64);

        let peer = Self {
            domain: domain.into(),
            host: host.into(),
            port,
            inbound_stream_rx,
            outbound_msg_rx,
            inbound_msg_tx,
        };
        let handle = PeerHandle {
            inbound_stream_tx,
            outbound_msg_tx,
        };

        (peer, handle)
    }

    pub async fn run(mut self, tls_config: Arc<ClientConfig>) {
        let mut framed: Option<Framed> = None;
        let mut pending_conn: Option<JoinHandle<ClientTlsStream>> = None;

        let reconnect_timeout = time::sleep(Duration::from_secs(0));
        tokio::pin!(reconnect_timeout);

        loop {
            tokio::select! {
                _ = reconnect_timeout.as_mut(), if framed.is_none() && pending_conn.is_none() => {
                    // try to connect
                    let host = self.host.clone();
                    let port = self.port;
                    let domain = self.domain.clone();
                    let tls_config = tls_config.clone();

                    let handle = tokio::spawn(async move {
                        let connector = TlsConnector::from(tls_config);
                        let domain = DNSNameRef::try_from_ascii_str(&domain).unwrap();

                        let tcp = TcpStream::connect((host.as_str(), port)).await.unwrap();
                        connector.connect(domain, tcp).await.unwrap()
                    });

                    pending_conn.replace(handle);
                }
                result = async { pending_conn.as_mut().unwrap().await }, if pending_conn.is_some() => {
                    pending_conn.take();
                    match result {
                        Ok(stream) => {
                            framed.replace(Framed::new(
                                tokio_rustls::TlsStream::Client(stream),
                                Codec::new(64 * 1024 * 1024),
                            ));
                        }
                        Err(_) => {
                            reconnect_timeout.as_mut().reset(
                                time::Instant::now() + Duration::from_secs(2)
                            );
                        }
                    }
                }
                Some(stream) = self.inbound_stream_rx.recv() => {
                    if let Some(h) = pending_conn.take() {
                        h.abort();
                    }
                    // receive new stream
                    if framed.is_none() {
                        framed.replace(Framed::new(
                            tokio_rustls::TlsStream::Server(stream),
                            Codec::new(64 * 1024 * 1024),
                        ));
                    }
                }
                Some(msg) = self.outbound_msg_rx.recv() => {
                    // send msg
                    if let Some(fd) = framed.as_mut() {
                        if let Err(e) = fd.send(msg).await {
                            println!("send outbound msg failed: {}", e);
                            framed.take();
                            reconnect_timeout.as_mut().reset(
                                time::Instant::now() + Duration::from_secs(2)
                            );
                        }
                    }
                }
                Some(result) = async { framed.as_mut().unwrap().next().await }, if framed.is_some() => match result {
                    Ok(msg) => {
                        self.inbound_msg_tx.send(msg).await.unwrap();
                    }
                    Err(_) => {
                        framed.take();
                        reconnect_timeout.as_mut().reset(
                            time::Instant::now() + Duration::from_secs(2)
                        );
                    }
                }
            }
        }
    }
}
