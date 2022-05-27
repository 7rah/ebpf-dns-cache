use futures::stream::StreamExt;
use probe::Event;
use redbpf::xdp;
use tracing::info;
use std::env;
use std::process;
use std::ptr;
use tokio::signal::ctrl_c;
use tracing::{error, Level};
use tracing_subscriber::FmtSubscriber;

use redbpf::load::Loader;
use redbpf::HashMap;

use std::net::Ipv4Addr;

#[tokio::main(flavor = "current_thread")]
async fn main() {
    init();

    let mut loaded = Loader::load(probe_code()).map_err(|err| format!("{:?}", err)).unwrap();
    let mut xdp = loaded.xdp_mut("dns_queries").unwrap();
    xdp.attach_xdp("wlo1", xdp::Flags::default()).unwrap();
    
    while let Some((_, events)) = loaded.events.next().await {
        for event in events {
            let event = unsafe {std::ptr::read_unaligned(event.as_ptr() as *const Event)};

            let saddr = Ipv4Addr::from(event.saddr);
            let daddr = Ipv4Addr::from(event.daddr);

            println!("{saddr:?}:{sport} -> {daddr:?}:{dport}",sport=event.sport,dport=event.dport);
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