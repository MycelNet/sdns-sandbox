use clap::Parser;
use std::net::Ipv4Addr;

#[derive(Parser)]
#[command(version, author, about)]
pub struct Args {
    /// Logging level
    #[arg(
        short,
        long,
        env = "MY_DNS_LOG_LEVEL",
        value_name = "LEVEL",
        default_value = "info"
    )]
    pub log_level: log::LevelFilter,

    /// DNS server address
    #[arg(
        short,
        long,
        env = "MY_DNS_SERVER_ADDR",
        value_name = "ADDR",
        default_value = "0.0.0.0"
    )]
    pub server_addr: Ipv4Addr,

    /// DNS server port defaults to unprivileged port 5300
    #[arg(
        short,
        long,
        env = "MY_DNS_SERVER_PORT",
        value_name = "PORT",
        default_value = "5300"
    )]
    pub port: u16,
}
