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
use async_std::prelude::*;
use async_std::sync::channel;

use sodiumoxide::crypto::{box_, hash};

use clap::Clap;

use async_std::os::unix::net::UnixStream;

use futures::AsyncReadExt;

use dashmap::DashMap;

fn synthesize_socket_address(public_encryption_key: &box_::PublicKey) -> SocketAddr {
    let mut hash_state = hash::State::new();
    hash_state.update(public_encryption_key.as_ref());
    let digest = hash_state.finalize();
    let digest = digest.as_ref();

    (
        [
            digest[0], digest[1], digest[2], digest[3], digest[4], digest[5], digest[6], digest[7],
            digest[8], digest[9], digest[10], digest[11], digest[12], digest[13], digest[14],
            digest[15],
        ],
        0,
    )
        .into()
}

#[tokio::main]
async fn main() {
    #[derive(Clap)]
    #[clap(
        version = "1.0",
        author = "Huỳnh Trần Khanh <qcdz9r6wpcbh59@gmail.com>"
    )]
    struct Options {
        #[clap(long)]
        server_socket: String,
        #[clap(long)]
        client_socket: String,
    }

    let options = Arc::new(Options::parse());
    use async_std::io::{self, BufReader};
    let mut incoming_data = BufReader::new(io::stdin());

    let connections = Arc::new(DashMap::<
        SocketAddr,
        Sender<(Vec<u8>, SocketAddr, Option<EcnCodepoint>)>,
    >::new());

    let map_synthetic_address_to_public_key =
        Arc::new(DashMap::<SocketAddr, box_::PublicKey>::new());

    let (my_public_encryption_key, my_private_encryption_key) = box_::gen_keypair();

    let my_private_encryption_key = Arc::new(my_private_encryption_key);

    let (my_server_public_encryption_key, my_server_private_encryption_key) = box_::gen_keypair();

    let my_server_private_encryption_key = Arc::new(my_server_private_encryption_key);
    let my_server_public_encryption_key = Arc::new(my_server_public_encryption_key);

    let (transmit_incoming_server, receive_incoming_server) = channel(1);
    let (transmit_outgoing_server, receive_outgoing_server) = channel::<Transmit>(1);

    {
        let my_server_public_encryption_key = my_server_public_encryption_key.clone();

        tokio::spawn(async move {
            loop {
                use std::time::Duration;

                {
                    let mut message = Vec::new();

                    // Version byte set to 0
                    message.extend_from_slice(&[0u8]);

                    // Message type set to Advertisement
                    message.extend_from_slice(&[0u8]);

                    message.extend_from_slice(my_server_public_encryption_key.as_ref().as_ref());

                    println!("{}", base64::encode(message));
                }

                task::sleep(Duration::from_secs(1)).await;
            }
        });
    }

    {
        let my_server_private_encryption_key = my_server_private_encryption_key.clone();
        let map_synthetic_address_to_public_key = map_synthetic_address_to_public_key.clone();
        tokio::spawn(async move {
            while let Ok(outgoing) = receive_outgoing_server.recv().await {
                let blob = outgoing.contents;

                let mut message = Vec::new();

                // Version byte set to 0
                message.extend_from_slice(&[0u8]);

                // Message type set to Packet
                message.extend_from_slice(&[1u8]);

                message.extend_from_slice(my_server_public_encryption_key.as_ref().as_ref());

                let encrypted_section = {
                    let mut encrypted_section = Vec::new();

                    let nonce = box_::gen_nonce();
                    encrypted_section.extend_from_slice(nonce.as_ref());

                    let ciphertext = box_::seal(
                        &blob,
                        &nonce,
                        &match map_synthetic_address_to_public_key.get(&outgoing.destination) {
                            Some(it) => *it,
                            None => continue,
                        },
                        &my_server_private_encryption_key,
                    );

                    encrypted_section.extend_from_slice(ciphertext.as_ref());

                    encrypted_section
                };

                message.extend_from_slice(encrypted_section.as_ref());

                println!("{}", base64::encode(message));
            }
        });
    }

    {
        let options = options.clone();
        let map_synthetic_address_to_public_key = map_synthetic_address_to_public_key.clone();
        tokio::spawn(async move {
            let (mut incoming, _server_cert) =
                make_server_endpoint((transmit_outgoing_server, receive_incoming_server)).unwrap();

            while let Some(connection) = incoming.next().await {
                let mut connection = match connection.await {
                    Ok(it) => it,
                    Err(_) => continue,
                };

                let synthetic_address = connection.connection.remote_address();

                while let Some(stream) = connection.bi_streams.next().await {
                    let (send, receive) = match stream {
                        Ok(it) => it,
                        Err(_) => break,
                    };

                    let stream = UnixStream::connect(&options.server_socket).await.unwrap();

                    let (reader, writer) = stream.split();

                    tokio::spawn(async move {
                        io::copy(reader, send).await.ok();
                    });

                    tokio::spawn(async move {
                        io::copy(receive, writer).await.ok();
                    });
                }

                map_synthetic_address_to_public_key.remove(&synthetic_address);
            }
        });
    }

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

        let message_type = match advance(1) {
            Some(it) => it[0],
            None => continue,
        };

        enum MessageType {
            Advertisement,
            Packet,
        };

        use MessageType::*;

        let message_type = match message_type {
            0 => Advertisement,
            1 => Packet,
            _ => continue,
        };

        match message_type {
            Advertisement => {
                let public_encryption_key = advance(box_::PUBLICKEYBYTES);

                if let Some(_) = advance(1) {
                    // Discard the packet as it contains additional garbage.
                    continue;
                }

                let public_encryption_key = match public_encryption_key {
                    Some(it) => box_::PublicKey::from_slice(it).unwrap(),
                    None => continue,
                };

                let synthetic_address = synthesize_socket_address(&public_encryption_key);

                if connections.contains_key(&synthetic_address) {
                    continue;
                }

                let (transmit_incoming, receive_incoming) = channel(1);
                connections.insert(synthetic_address.clone(), transmit_incoming);

                let (transmit_outgoing, receive_outgoing) = channel(1);

                let connections = connections.clone();
                let options = options.clone();
                tokio::spawn((|| async move {
                    let client_cfg = configure_client();
                    let mut endpoint_builder = Endpoint::builder();
                    endpoint_builder.default_client_config(client_cfg);

                    let (endpoint, _) =
                        match endpoint_builder.with_socket((transmit_outgoing, receive_incoming)) {
                            Ok(it) => it,
                            Err(_) => {
                                connections.remove(&synthetic_address);
                                return;
                            }
                        };
                    let connection = match endpoint.connect(&synthetic_address, "localhost") {
                        Ok(it) => it,
                        Err(_) => {
                            connections.remove(&synthetic_address);
                            return;
                        }
                    }
                    .await;

                    let crate::NewConnection { connection, .. } = match connection {
                        Ok(it) => it,
                        Err(_) => {
                            connections.remove(&synthetic_address);
                            return;
                        }
                    };

                    let (send, receive) = match connection.open_bi().await {
                        Ok(it) => it,
                        Err(_) => {
                            connections.remove(&synthetic_address);
                            return;
                        }
                    };

                    let stream = UnixStream::connect(&options.client_socket).await.unwrap();

                    let (reader, writer) = stream.split();

                    tokio::spawn(async move {
                        io::copy(reader, send).await.ok();
                    });

                    tokio::spawn(async move {
                        io::copy(receive, writer).await.ok();
                    });

                    endpoint.wait_idle().await;

                    connections.remove(&synthetic_address);
                })());

                let my_private_encryption_key = my_private_encryption_key.clone();
                tokio::spawn(async move {
                    while let Ok(outgoing) = receive_outgoing.recv().await {
                        let blob = outgoing.contents;

                        let mut message = Vec::new();

                        // Version byte set to 0
                        message.extend_from_slice(&[0u8]);

                        // Message type set to Packet
                        message.extend_from_slice(&[1u8]);

                        message.extend_from_slice(my_public_encryption_key.as_ref());

                        let encrypted_section = {
                            let mut encrypted_section = Vec::new();

                            let nonce = box_::gen_nonce();
                            encrypted_section.extend_from_slice(nonce.as_ref());

                            let ciphertext = box_::seal(
                                &blob,
                                &nonce,
                                &public_encryption_key,
                                &my_private_encryption_key,
                            );

                            encrypted_section.extend_from_slice(ciphertext.as_ref());

                            encrypted_section
                        };

                        message.extend_from_slice(encrypted_section.as_ref());

                        println!("{}", base64::encode(message));
                    }
                });
            }
            Packet => {
                let public_encryption_key = advance(box_::PUBLICKEYBYTES);

                let public_encryption_key = match public_encryption_key {
                    Some(it) => box_::PublicKey::from_slice(&it).unwrap(),
                    None => continue,
                };

                let nonce = advance(box_::NONCEBYTES);

                let nonce = match nonce {
                    Some(it) => box_::Nonce::from_slice(&it).unwrap(),
                    None => continue,
                };

                let encrypted_section = &blob[counter..];

                let packet_is_sent_to_server = (|| async {
                    let plaintext = box_::open(
                        &encrypted_section,
                        &nonce,
                        &public_encryption_key,
                        &my_server_private_encryption_key,
                    );

                    let plaintext = match plaintext {
                        Ok(it) => it,
                        Err(_) => return false,
                    };

                    let synthetic_address = synthesize_socket_address(&public_encryption_key);

                    map_synthetic_address_to_public_key
                        .insert(synthetic_address.clone(), public_encryption_key);

                    transmit_incoming_server
                        .send((plaintext, synthetic_address, None))
                        .await;

                    true
                })()
                .await;

                if packet_is_sent_to_server {
                    continue;
                }

                let plaintext = box_::open(
                    &encrypted_section,
                    &nonce,
                    &public_encryption_key,
                    &my_private_encryption_key,
                );

                let plaintext = match plaintext {
                    Ok(it) => it,
                    Err(_) => continue,
                };

                let synthetic_address = synthesize_socket_address(&public_encryption_key);

                match connections.get(&synthetic_address) {
                    Some(it) => {
                        it.send((plaintext, synthetic_address, None)).await;
                    }
                    None => continue,
                };
            }
        };
    }
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
