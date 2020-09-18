//! QUIC transport protocol support for Tokio
//!
//! [QUIC](https://en.wikipedia.org/wiki/QUIC) is a modern transport protocol addressing
//! shortcomings of TCP, such as head-of-line blocking, poor security, slow handshakes, and
//! inefficient congestion control. This crate provides a portable userspace implementation. It
//! builds on top of quinn-proto, which implements protocol logic independent of any particular
//! runtime.
//!
//! The entry point of this crate is the [`Endpoint`](struct.Endpoint.html).
//!
#![cfg_attr(
    feature = "rustls",
    doc = "```no_run
# use futures::TryFutureExt;
let mut builder = quinn::Endpoint::builder();
// ... configure builder ...
// Ensure you're inside a tokio runtime context
let (endpoint, _) = builder.bind(&\"[::]:0\".parse().unwrap()).unwrap();
// ... use endpoint ...
```"
)]
//! # About QUIC
//!
//! A QUIC connection is an association between two endpoints. The endpoint which initiates the
//! connection is termed the client, and the endpoint which accepts it is termed the server. A
//! single endpoint may function as both client and server for different connections, for example
//! in a peer-to-peer application. To communicate application data, each endpoint may open streams
//! up to a limit dictated by its peer. Typically, that limit is increased as old streams are
//! finished.
//!
//! Streams may be unidirectional or bidirectional, and are cheap to create and disposable. For
//! example, a traditionally datagram-oriented application could use a new stream for every
//! message it wants to send, no longer needing to worry about MTUs. Bidirectional streams behave
//! much like a traditional TCP connection, and are useful for sending messages that have an
//! immediate response, such as an HTTP request. Stream data is delivered reliably, and there is no
//! ordering enforced between data on different streams.
//!
//! By avoiding head-of-line blocking and providing unified congestion control across all streams
//! of a connection, QUIC is able to provide higher throughput and lower latency than one or
//! multiple TCP connections between the same two hosts, while providing more useful behavior than
//! raw UDP sockets.
//!
//! Quinn also exposes unreliable datagrams, which are a low-level primitive preferred when
//! automatic fragmentation and retransmission of certain data is not desired.
//!
//! QUIC uses encryption and identity verification built directly on TLS 1.3. Just as with a TLS
//! server, it is useful for a QUIC server to be identified by a certificate signed by a trusted
//! authority. If this is infeasible--for example, if servers are short-lived or not associated
//! with a domain name--then as with TLS, self-signed certificates can be used to provide
//! encryption alone.
#![warn(missing_docs)]

mod broadcast;
mod builders;
mod connection;
mod endpoint;
mod platform;
mod streams;
mod udp;

pub use proto::{
    crypto, ApplicationClose, Certificate, CertificateChain, ConnectError, ConnectionClose,
    ConnectionError, EcnCodepoint, ParseError, PrivateKey, Transmit, TransportConfig, VarInt,
};

use async_std::sync::{Receiver, Sender};
use async_std::task;

pub use crate::builders::EndpointError;
pub use crate::connection::{SendDatagramError, ZeroRttAccepted};
pub use crate::streams::{ReadError, ReadExactError, ReadToEndError, WriteError};

/// Types that are generic over the crypto protocol implementation
pub mod generic {
    pub use crate::builders::{ClientConfigBuilder, EndpointBuilder, ServerConfigBuilder};
    pub use crate::connection::{
        Connecting, Connection, Datagrams, IncomingBiStreams, IncomingUniStreams, NewConnection,
        OpenBi, OpenUni,
    };
    pub use crate::endpoint::{Endpoint, Incoming};
    pub use crate::streams::{Read, ReadExact, ReadToEnd, RecvStream, SendStream};
    pub use proto::generic::{ClientConfig, ServerConfig};
}

#[cfg(feature = "rustls")]
mod rustls_impls {
    use crate::generic;
    use proto::crypto::rustls::TlsSession;

    /// A `ClientConfig` using rustls for the cryptography protocol
    pub type ClientConfig = generic::ClientConfig<TlsSession>;
    /// A `ServerConfig` using rustls for the cryptography protocol
    pub type ServerConfig = generic::ServerConfig<TlsSession>;

    /// A `ClientConfigBuilder` using rustls for the cryptography protocol
    pub type ClientConfigBuilder = generic::ClientConfigBuilder<TlsSession>;
    /// An `EndpointBuilder` using rustls for the cryptography protocol
    pub type EndpointBuilder = generic::EndpointBuilder<TlsSession>;
    /// A `ServerConfigBuilder` using rustls for the cryptography protocol
    pub type ServerConfigBuilder = generic::ServerConfigBuilder<TlsSession>;

    /// A `Connecting` using rustls for the cryptography protocol
    pub type Connecting = generic::Connecting<TlsSession>;
    /// A `Connection` using rustls for the cryptography protocol
    pub type Connection = generic::Connection<TlsSession>;
    /// A `Datagrams` using rustls for the cryptography protocol
    pub type Datagrams = generic::Datagrams<TlsSession>;
    /// An `IncomingBiStreams` using rustls for the cryptography protocol
    pub type IncomingBiStreams = generic::IncomingBiStreams<TlsSession>;
    /// An `IncomingUniStreams` using rustls for the cryptography protocol
    pub type IncomingUniStreams = generic::IncomingUniStreams<TlsSession>;
    /// A `NewConnection` using rustls for the cryptography protocol
    pub type NewConnection = generic::NewConnection<TlsSession>;
    /// An `OpenBi` using rustls for the cryptography protocol
    pub type OpenBi = generic::OpenBi<TlsSession>;
    /// An `OpenUni` using rustls for the cryptography protocol
    pub type OpenUni = generic::OpenUni<TlsSession>;

    /// An `Endpoint` using rustls for the cryptography protocol
    pub type Endpoint = generic::Endpoint<TlsSession>;
    /// An `Incoming` using rustls for the cryptography protocol
    pub type Incoming = generic::Incoming<TlsSession>;

    /// A `Read` using rustls for the cryptography protocol
    pub type Read<'a> = generic::Read<'a, TlsSession>;
    /// A `ReadExact` using rustls for the cryptography protocol
    pub type ReadExact<'a> = generic::ReadExact<'a, TlsSession>;
    /// A `ReadToEnd` using rustls for the cryptography protocol
    pub type ReadToEnd = generic::ReadToEnd<TlsSession>;
    /// A `RecvStream` using rustls for the cryptography protocol
    pub type RecvStream = generic::RecvStream<TlsSession>;
    /// A `SendStream` using rustls for the cryptography protocol
    pub type SendStream = generic::SendStream<TlsSession>;
}

#[cfg(feature = "rustls")]
pub use rustls_impls::*;

#[derive(Debug)]
enum ConnectionEvent {
    Close {
        error_code: VarInt,
        reason: bytes::Bytes,
    },
    Proto(proto::ConnectionEvent),
}

#[derive(Debug)]
enum EndpointEvent {
    Proto(proto::EndpointEvent),
    Transmit(proto::Transmit),
}

/// Maximum number of send/recv calls to make before moving on to other processing
///
/// This helps ensure we don't starve anything when the CPU is slower than the link. Value selected
/// more or less arbitrarily.
const IO_LOOP_BOUND: usize = 10;

use futures::StreamExt;
use std::{error::Error, net::SocketAddr, sync::Arc};

use crate::{ClientConfig, ClientConfigBuilder, Endpoint};

fn main() {
    task::block_on(async move {
        use async_std::io::{self, BufReader};
        let mut incoming_data = BufReader::new(io::stdin());
        loop {
            let mut line = String::new();
            incoming_data.read_line(&mut line).await.unwrap();

            let blob = base64::decode(line).unwrap();

            let mut counter: usize = 0;

            let mut advance = |count: usize| {
                let left = counter;
                counter += count;
                if counter > blob.len() {
                    return None;
                }
                Some(&blob[left..counter])
            };

            let version = match advance(1) {
                Some(it) => it[0],
                None => continue,
            };

            if version != 0 {
                // First byte indicates version. This is the first revision
                // of the tunneling protocol, so the version byte is expected
                // to be zero. The incoming packet is discarded.
                continue;
            }
        }
    });
}

fn configure_server() -> Result<(ServerConfig, Vec<u8>), Box<dyn Error>> {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert_der = cert.serialize_der().unwrap();
    let priv_key = cert.serialize_private_key_der();
    let priv_key = PrivateKey::from_der(&priv_key)?;

    let mut transport_config = TransportConfig::default();
    transport_config.stream_window_uni(0);
    let mut server_config = ServerConfig::default();
    server_config.transport = Arc::new(transport_config);
    let mut cfg_builder = ServerConfigBuilder::new(server_config);
    let cert = Certificate::from_der(&cert_der)?;
    cfg_builder.certificate(CertificateChain::from_certs(vec![cert]), priv_key)?;

    Ok((cfg_builder.build(), cert_der))
}

fn make_server_endpoint(
    socket: (
        Sender<Transmit>,
        Receiver<(Vec<u8>, SocketAddr, Option<EcnCodepoint>)>,
    ),
) -> Result<(Incoming, Vec<u8>), Box<dyn Error>> {
    let (server_config, server_cert) = configure_server()?;
    let mut endpoint_builder = Endpoint::builder();
    endpoint_builder.listen(server_config);
    let (_endpoint, incoming) = endpoint_builder.with_socket(socket)?;
    Ok((incoming, server_cert))
}

/// Runs a QUIC server bound to given address.
async fn run_server(
    socket: (
        Sender<Transmit>,
        Receiver<(Vec<u8>, SocketAddr, Option<EcnCodepoint>)>,
    ),
) {
    let (mut incoming, _server_cert) = make_server_endpoint(socket).unwrap();
    // accept a single connection
    let incoming_conn = incoming.next().await.unwrap();
    let new_conn = incoming_conn.await.unwrap();
    println!(
        "[server] connection accepted: addr={}",
        new_conn.connection.remote_address()
    );
}

async fn run_client(
    server_addr: SocketAddr,
    socket: (
        Sender<Transmit>,
        Receiver<(Vec<u8>, SocketAddr, Option<EcnCodepoint>)>,
    ),
) -> Result<(), Box<dyn Error>> {
    let client_cfg = configure_client();
    let mut endpoint_builder = Endpoint::builder();
    endpoint_builder.default_client_config(client_cfg);

    let (endpoint, _) = endpoint_builder.with_socket(socket).unwrap();

    // connect to server
    let crate::NewConnection { connection, .. } = endpoint
        .connect(&server_addr, "localhost")
        .unwrap()
        .await
        .unwrap();
    println!("[client] connected: addr={}", connection.remote_address());
    // Dropping handles allows the corresponding objects to automatically shut down
    drop(connection);
    // Make sure the server has a chance to clean up
    endpoint.wait_idle().await;

    Ok(())
}

/// Dummy certificate verifier that treats any certificate as valid.
/// NOTE, such verification is vulnerable to MITM attacks, but convenient for testing.
struct SkipServerVerification;

impl SkipServerVerification {
    fn new() -> Arc<Self> {
        Arc::new(Self)
    }
}

impl rustls::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _roots: &rustls::RootCertStore,
        _presented_certs: &[rustls::Certificate],
        _dns_name: webpki::DNSNameRef,
        _ocsp_response: &[u8],
    ) -> Result<rustls::ServerCertVerified, rustls::TLSError> {
        Ok(rustls::ServerCertVerified::assertion())
    }
}

fn configure_client() -> ClientConfig {
    let mut cfg = ClientConfigBuilder::default().build();
    let tls_cfg: &mut rustls::ClientConfig = Arc::get_mut(&mut cfg.crypto).unwrap();
    // this is only available when compiled with "dangerous_configuration" feature
    tls_cfg
        .dangerous()
        .set_certificate_verifier(SkipServerVerification::new());
    cfg
}
