#![no_std]
#![no_main]

use core::fmt::{self, Write};
use core::{mem, slice};
use memoffset::offset_of;
use probe::Addr;
use redbpf_probes::bindings::*;
use redbpf_probes::socket_filter::prelude::*;
use redbpf_probes::xdp::prelude::*;
use redbpf_probes::xdp::prelude::PerfMap;

program!(0xFFFFFFFE, "GPL");


#[map(link_section = "maps/log_events")]
static mut test_events: PerfMap<Addr> = PerfMap::with_max_entries(512);

#[socket_filter]
pub fn dns_queries(skb: SkBuff) -> SkBuffResult {
    let eth_len = mem::size_of::<ethhdr>();
    let eth_proto = skb.load::<__be16>(offset_of!(ethhdr, h_proto))? as u32;

    if eth_proto == ETH_P_IP {
        let mut ip_hdr = unsafe { mem::zeroed::<iphdr>() };
        ip_hdr._bitfield_1 = __BindgenBitfieldUnit::new([skb.load::<u8>(eth_len)?]);

        if ip_hdr.version() == 4 {
            let ip_len = ip_hdr.ihl() as usize * 4;
            let protocol = skb.load::<__u8>(eth_len + offset_of!(iphdr, protocol))? as u32;

            if protocol != IPPROTO_UDP {
                return Ok(SkBuffAction::Ignore);
            } else {
                let proto_len = mem::size_of::<udphdr>();
                let dns_qcount: u16 = skb.load(eth_len + ip_len + proto_len + 4)?;
                if dns_qcount == 1 {
                    return Ok(SkBuffAction::SendToUserspace);
                }
            }
        } else {
            return Ok(SkBuffAction::Ignore);
        };

        return Ok(SkBuffAction::Ignore);
    }
    Ok(SkBuffAction::Ignore)
}

#[xdp("test")]
pub fn p0f_extractor(ctx: XdpContext) -> XdpResult {
    let ip = unsafe{  *ctx.ip()? };

    if ip.protocol != u8::from_be(IPPROTO_UDP as u8){
        return Ok(XdpAction::Pass);
    }

    let payload = ctx.data()?;
    let payload = payload.slice(12)?;


    if (payload[4] != 0) | (payload[5] != u8::from_be(1)){
        return Ok(XdpAction::Pass);
    }

    let udp_header = ctx.transport()?;

    let saddr = ip.saddr;
    let daddr = ip.daddr;
    let sport = udp_header.source();
    let dport = udp_header.dest();
    let id = [payload[0],payload[1]];
    let id = u16::from_be_bytes(id);

    let addr = Addr{saddr,daddr,sport,dport,id};

    unsafe {
        test_events.insert(&ctx, &MapData::new(addr));
    }

    Ok(XdpAction::Pass)
}