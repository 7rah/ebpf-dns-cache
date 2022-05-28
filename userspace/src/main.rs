use futures::stream::StreamExt;
use probe::Event;
use redbpf::xdp;
use tracing::info;
use std::env;
use std::fmt::Display;
use std::fmt::Formatter;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::process;
use std::ptr;
use tokio::signal::ctrl_c;
use tracing::{error, Level};
use tracing_subscriber::FmtSubscriber;
use redbpf::load::Loader;
use std::net::Ipv4Addr;
use tokio_fd::AsyncFd;
use dns_parser::Builder;

use tokio::io::AsyncReadExt;
use dns_parser::Packet;

struct Connection {
    saddr: SocketAddr,
    daddr: SocketAddr,
}

impl From<Event> for Connection {
    fn from(event: Event) -> Self {
        let saddr = IpAddr::V4(Ipv4Addr::from(event.saddr));
        let daddr = IpAddr::V4(Ipv4Addr::from(event.daddr));
        let sport = event.sport;
        let dport = event.dport;

        Connection { saddr:SocketAddr::new(saddr, sport),daddr:SocketAddr::new(daddr, dport)}
    }
}

impl Display for Connection {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let saddr = self.saddr;
        let daddr = self.daddr;
        write!(f,"{saddr:?} -> {daddr:?}")
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    init();

    let mut loaded = Loader::load(probe_code()).map_err(|err| format!("{:?}", err)).unwrap();
    let fd = loaded.socket_filter_mut("dns_queries").unwrap().attach_socket_filter("wlo1").unwrap();
    let mut filter =  AsyncFd::try_from(fd).unwrap();
    

    let mut buf = vec![0; 2048];
    while let Ok(n) = filter.read(&mut buf).await {
        let ihl = (u8::from_be(buf[14]) & 0x0f) as usize;

        println!("{:x}", ihl);
        let udp_data = &buf[14+ihl*4+8..n];
        

        match Packet::parse(udp_data) {
            Ok(packet) => println!("{packet:?}"),
            Err(e) => println!("{e}"),
        }
    }



}


fn init() {
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::DEBUG)
        .finish();
    tracing::subscriber::set_global_default(subscriber).unwrap();
    if unsafe { libc::geteuid() != 0 } {
        error!("You must be root to use eBPF!");
        process::exit(1);
    }
}

fn probe_code() -> &'static [u8] {
    include_bytes!(
        "../../target/bpf/programs/dns_queries/dns_queries.elf"
    )
}