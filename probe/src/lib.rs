#![no_std]

use redbpf_probes::{xdp::XdpContext, net::Data};



#[repr(C)]
#[derive(Debug)]
pub struct Event {
    pub saddr: u32,
    pub daddr: u32,
    pub sport: u16, 
    pub dport: u16,
}