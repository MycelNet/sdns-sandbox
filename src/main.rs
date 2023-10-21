use anyhow::Result;
use clap::Parser;
use structured_logger::async_json::new_writer;
use tokio::{
    net::UdpSocket,
    select,
    signal::unix::{signal, SignalKind},
    sync::watch,
};

use mycelnet_dns_protocol::{DnsPacketData, DnsRequest, DnsResponse};

use cli::Args;

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    structured_logger::Builder::with_level(args.log_level.as_str())
        .with_target_writer("*", new_writer(tokio::io::stdout()))
        .try_init()?;

    log::info!("Logger initialized");

    // Setup interrupt channel and spawn interrupt handler
    let (stop_tx, mut stop_rx) = watch::channel(());
    tokio::spawn(async move {
        let mut sigterm = signal(SignalKind::terminate()).unwrap();
        let mut sigint = signal(SignalKind::interrupt()).unwrap();
        loop {
            select! {
                _ = sigterm.recv() => log::info!("Recieved SIGTERM"),
                _ = sigint.recv() => log::info!("Recieved SIGINT"),
            };

            log::debug!("Sending interrupt message to worker");
            stop_tx.send(()).unwrap();
        }
    });

    log::info!("Starting server");
    let worker = tokio::spawn(async move {
        let server_addr = format!("{}:{}", args.server_addr, args.port);
        let socket = match UdpSocket::bind(&server_addr).await {
            Ok(socket) => {
                log::info!("Listening on {server_addr}");
                socket
            }
            Err(e) => {
                log::error!("Failed to bind socket to {server_addr}: {e}");
                return Err::<(), anyhow::Error>(e.into());
            }
        };

        loop {
            select! {
                biased;
                _ = stop_rx.changed() => {
                    log::info!("Interrupt received stopping server");
                    break Ok(());
                }
                _ = handle_request(&socket) => {}
            }
        }
    });

    // Wait for all worker tasks to finish
    worker.await??;

    log::info!("Server stopped");

    Ok(())
}

async fn handle_request(socket: &UdpSocket) -> Result<()> {
    let mut buf = [0; 1024];

    let (len, addr) = match socket.recv_from(&mut buf).await {
        Ok((len, addr)) => (len, addr),
        Err(e) => {
            log::error!("Failed to receive data: {e}");
            return Err(e.into());
        }
    };

    let data = &buf[..len];
    println!("Received {len} bytes from {addr}");

    let request = match DnsRequest::from_bytes(data, 0) {
        Ok(request) => {
            log::trace!("Received request: {request:?}");
            request
        }
        Err(e) => {
            log::error!("Failed to parse request: {e}");
            return Err(e);
        }
    };

    let response = match DnsResponse::from_request(&request) {
        Ok(response) => {
            log::trace!("Created response: {response:?}");
            response
        }
        Err(e) => {
            log::error!("Failed to create response: {e}");
            return Err(e);
        }
    };

    let response_bytes = match response.to_bytes() {
        Ok(response_bytes) => response_bytes,
        Err(e) => {
            log::error!("Failed to serialize response: {e}");
            return Err(e);
        }
    };

    match socket.send_to(response_bytes.as_slice(), addr).await {
        Ok(_) => {
            log::trace!("Sent response to {addr}: {response:?}");
        }
        Err(e) => {
            log::error!("Failed to send response: {e}");
            return Err(e.into());
        }
    };

    Ok(())
}
