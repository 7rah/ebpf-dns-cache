#![no_std]
#![no_main]
use core::mem::{self, MaybeUninit};

use memoffset::offset_of;
use probe::Event;
use redbpf_probes::bindings::*;
use redbpf_probes::helpers::ufmt::Formatter;
use redbpf_probes::kprobe::prelude::*;
use redbpf_probes::socket::SkBuff;
use redbpf_probes::socket_filter::prelude::*;
use redbpf_probes::sockmap::prelude::*;
use core::fmt::{self, Write};

program!(0xFFFFFFFE, "GPL");

#[socket_filter]
pub fn dns_queries(skb: SkBuff) -> SkBuffResult {
    let eth_len = mem::size_of::<ethhdr>();
    let eth_proto = skb.load::<__be16>(offset_of!(ethhdr, h_proto))? as u32;

    if eth_proto == ETH_P_IP {
        let mut ip_hdr = unsafe { mem::zeroed::<iphdr>() };
        ip_hdr._bitfield_1 = __BindgenBitfieldUnit::new([skb.load::<u8>(eth_len)?]);

        let (ip_len, proto) = if ip_hdr.version() == 4 {
            (
                ip_hdr.ihl() as usize * 4,
                skb.load::<__u8>(eth_len + offset_of!(iphdr, protocol))? as u32,
            )
        } else {
            (40, skb.load::<__u8>(eth_len + 6)? as u32)
        };

        let proto_len = if proto == IPPROTO_UDP {
            mem::size_of::<udphdr>()
        } else if proto == IPPROTO_TCP {
            mem::size_of::<tcphdr>()
        }else { 
            return Ok(SkBuffAction::Ignore);
        };


        let dns_qcount: u16 = skb.load(eth_len + ip_len + proto_len + 4)?;
        if dns_qcount == 1 {
            return Ok(SkBuffAction::SendToUserspace);

        }
    }

    /*
    if eth_proto != ETH_P_IP {
        return Ok(SkBuffAction::Ignore);
    }

    let ip_proto = skb.load::<__u8>(eth_len + offset_of!(iphdr, protocol))? as u32;
    if ip_proto != IPPROTO_UDP {
        return Ok(SkBuffAction::Ignore);
    }

    let mut ip_hdr = unsafe { mem::zeroed::<iphdr>() };
    ip_hdr._bitfield_1 = __BindgenBitfieldUnit::new([skb.load::<u8>(eth_len)?]);
    if ip_hdr.version() != 4 {
        return Ok(SkBuffAction::Ignore);
    }
    let ihl = ip_hdr.ihl() as usize;

    let dns_qcount: u16 = skb.load(eth_len + ihl * 4 + mem::size_of::<udphdr>() + 4)?;
    if dns_qcount == 1 {
        return Ok(SkBuffAction::SendToUserspace);
    }

    */
    Ok(SkBuffAction::Ignore)
}
