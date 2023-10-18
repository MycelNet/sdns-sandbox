use anyhow::Result;
use mycelnet_dns_protocol::{DnsPacketData, DnsRequest, DnsResponse};
use tokio::net::UdpSocket;

#[tokio::main]
async fn main() -> Result<()> {
    let socket = UdpSocket::bind("0.0.0.0:5300").await?;
    let mut buf = [0; 1024];
    loop {
        let (len, addr) = socket.recv_from(&mut buf).await?;
        let data = &buf[..len];
        println!("Received {len} bytes from {addr}");

        let request = DnsRequest::from_bytes(data);

        println!("{request:?}");

        let response = DnsResponse::from_request(&request);

        println!("{response:?}");

        socket.send_to(response.to_bytes().as_slice(), addr).await?;
    }
}
