use std::{
    io,
    net::SocketAddr,
    task::{Context, Poll},
};

use async_std::sync::{Receiver, Sender};
use async_std::task;
use proto::{EcnCodepoint, Transmit};
use std::sync::{Arc, Mutex};

/// Tokio-compatible UDP socket with some useful specializations.
///
/// Unlike a standard tokio UDP socket, this allows ECN bits to be read and written on some
/// platforms.
#[derive(Debug)]
pub struct UdpSocket {
    socket: (
        Sender<Transmit>,
        Receiver<(Vec<u8>, SocketAddr, Option<EcnCodepoint>)>,
    ),
    recv_result: Arc<Mutex<Option<io::Result<(Vec<u8>, SocketAddr, Option<EcnCodepoint>)>>>>,
}

impl UdpSocket {
    pub fn from_std(
        socket: (
            Sender<Transmit>,
            Receiver<(Vec<u8>, SocketAddr, Option<EcnCodepoint>)>,
        ),
    ) -> UdpSocket {
        UdpSocket {
            socket,
            recv_result: Arc::new(Mutex::new(None)),
        }
    }

    pub fn send(&self, transmit: Transmit) {
        let sender = self.socket.0.clone();
        task::spawn(async move {
            sender.send(transmit).await;
        });
    }

    pub fn poll_recv(
        &self,
        cx: &mut Context,
    ) -> Poll<io::Result<(Vec<u8>, SocketAddr, Option<EcnCodepoint>)>> {
        match self.recv_result.lock().unwrap().take() {
            Some(it) => Poll::Ready(it),
            None => {
                let receiver = self.socket.1.clone();
                let recv_result = self.recv_result.clone();
                let waker = cx.waker().clone();
                task::spawn(async move {
                    *recv_result.lock().unwrap() = Some(match receiver.recv().await {
                        Ok(it) => Ok(it),
                        Err(_) => Err(io::Error::new(
                            io::ErrorKind::Other,
                            "connection terminated",
                        )),
                    });
                    waker.wake();
                });
                Poll::Pending
            }
        }
    }
}

/// Number of UDP packets to send at a time
///
/// Chosen somewhat arbitrarily; might benefit from additional tuning.
pub const BATCH_SIZE: usize = 32;
