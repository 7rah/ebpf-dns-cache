use dns_parser::rdata::{a, aaaa, cname};
use dns_parser::{Packet, RData};
use redbpf::load::Loader;
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use tokio::io::AsyncReadExt;
use tokio_fd::AsyncFd;
use tracing::{error, info, warn, Level};
use tracing_subscriber::FmtSubscriber;

struct Record {
    id: u16,
    saddr: SocketAddr,
    daddr: SocketAddr,
    questions: Vec<String>,
    answers: Vec<String>,
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    init();

    let mut loaded = Loader::load(probe_code())
        .map_err(|err| format!("{:?}", err))
        .unwrap();
    let fd = loaded
        .socket_filter_mut("dns_queries")
        .unwrap()
        .attach_socket_filter("wlo1")
        .unwrap();
    let mut filter = AsyncFd::try_from(fd).unwrap();

    let mut buf = vec![0; 2048];

    let mut map: HashMap<u16, Record> = HashMap::new();

    while let Ok(n) = filter.read(&mut buf).await {
        let ihl = (u8::from_be(buf[14]) & 0x0f) as usize;
        let saddr = u32::from_be_bytes(buf[26..30].try_into().unwrap());
        let saddr = Ipv4Addr::from(saddr);
        let daddr = u32::from_be_bytes(buf[30..34].try_into().unwrap());
        let daddr = Ipv4Addr::from(daddr);
        let sport = u16::from_be_bytes(buf[34..36].try_into().unwrap());
        let dport = u16::from_be_bytes(buf[36..38].try_into().unwrap());

        let saddr = SocketAddr::from(SocketAddrV4::new(saddr, sport));
        let daddr = SocketAddr::from(SocketAddrV4::new(daddr, dport));

        let data = &buf[14 + ihl * 4 + 8..n];

        match Packet::parse(data) {
            Ok(packet) => {
                let id = packet.header.id;

                if let std::collections::hash_map::Entry::Vacant(e) = map.entry(id) {
                    let domains: Vec<String> = packet
                        .questions
                        .iter()
                        .map(|x| x.qname.to_string())
                        .collect();
                    let answers = vec![];
                    let record = Record {
                        id,
                        saddr,
                        daddr,
                        questions: domains,
                        answers,
                    };
                    e.insert(record);
                    
                } else if !packet.answers.is_empty() {
                    let mut v: Vec<String> = Vec::new();
                    for ans in packet.answers {
                        let s = match ans.data {
                            RData::A(a::Record(ip)) => ip.to_string(),
                            RData::AAAA(aaaa::Record(ip)) => ip.to_string(),
                            RData::CNAME(cname::Record(name)) => name.to_string(),
                            _ => "".to_string(), // ignore
                        };
                        v.push(s);
                    }
                    let record = map.get_mut(&id).unwrap();

                    record.answers = v;

                    info!(
                        "{}  {} <--> {} {:?} {:?}",
                        record.id, record.saddr, record.daddr, record.questions, record.answers
                    );
                }
            }
            Err(e) => warn!("{e}"),
        }
    }
}

fn init() {
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .finish();
    tracing::subscriber::set_global_default(subscriber).unwrap();
    if unsafe { libc::geteuid() != 0 } {
        error!("You must be root to use eBPF!");
        std::process::exit(1);
    }
}

fn probe_code() -> &'static [u8] {
    include_bytes!("../../target/bpf/programs/dns_queries/dns_queries.elf")
}
