use dns_parser::rdata::{a, aaaa, cname};
use dns_parser::{Packet, RData};
use redbpf::load::Loader;
use std::collections::hash_map::DefaultHasher;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use tokio::io::AsyncReadExt;
use tokio_fd::AsyncFd;
use tracing::{error, info, warn, Level};
use tracing_subscriber::FmtSubscriber;

#[derive(Clone, Debug)]
#[allow(dead_code)]
struct Record {
    id: u16,
    saddr: SocketAddr,
    daddr: SocketAddr,
    questions: Vec<String>,
    answers: Vec<String>,
}

#[tokio::main]
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

    let mut match_map = HashMap::<(u16, u64), (Vec<String>, u16, SocketAddr, SocketAddr)>::new();
    let mut cache_map = HashMap::<Vec<String>, Record>::new();
    let mut total = 0;

    while let Ok(n) = filter.read(&mut buf).await {
        let (saddr, daddr, data) = parse_raw_packet(&buf[..n]);
        match Packet::parse(data) {
            Ok(packet) => {
                let id = (packet.header.id, hash(saddr) ^ hash(daddr));

                if let Some((questions, _, _, _)) = match_map.get(&id) {
                    let questions = questions.clone();
                    let answers = packet
                        .answers
                        .iter()
                        .map(|ans| match ans.data {
                            RData::A(a::Record(ip)) => ip.to_string(),
                            RData::AAAA(aaaa::Record(ip)) => ip.to_string(),
                            RData::CNAME(cname::Record(name)) => name.to_string(),
                            _ => "".to_string(), // ignore
                        })
                        .collect();

                    info!(
                        "{:?} {daddr} <--> {saddr}    {questions:?} {answers:?}",
                        id.0
                    );

                    let record = Record {
                        id: id.0,
                        saddr,
                        daddr,
                        questions: questions.clone(),
                        answers,
                    };
                    cache_map.insert(questions.clone(), record);

                    match_map.remove(&id);
                    let remain = match_map.len();
                    info!(
                        "total request:{total}   remain unmached: {remain}   loss: {:.2}%",
                        ((remain as f64) / (total as f64)) * 100f64
                    );
                } else {
                    let questions = packet
                        .questions
                        .iter()
                        .map(|q| q.qname.to_string())
                        .collect();
                    match_map.insert(id, (questions, id.0, saddr, daddr));
                    total += 1;
                }
            }
            Err(err) => warn!("parse packet err: {err}"),
        }
    }
}

fn parse_raw_packet(buf: &[u8]) -> (SocketAddr, SocketAddr, &[u8]) {
    let ihl = (u8::from_be(buf[14]) & 0x0f) as usize;
    let saddr = u32::from_be_bytes(buf[26..30].try_into().unwrap());
    let saddr = Ipv4Addr::from(saddr);
    let daddr = u32::from_be_bytes(buf[30..34].try_into().unwrap());
    let daddr = Ipv4Addr::from(daddr);
    let sport = u16::from_be_bytes(buf[34..36].try_into().unwrap());
    let dport = u16::from_be_bytes(buf[36..38].try_into().unwrap());

    let saddr = SocketAddr::from(SocketAddrV4::new(saddr, sport));
    let daddr = SocketAddr::from(SocketAddrV4::new(daddr, dport));

    let data = &buf[14 + ihl * 4 + 8..];

    (saddr, daddr, data)
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

fn hash<T>(obj: T) -> u64
where
    T: Hash,
{
    let mut hasher = DefaultHasher::new();
    obj.hash(&mut hasher);
    hasher.finish()
}
