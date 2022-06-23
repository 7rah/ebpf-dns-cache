#![no_std]

#[repr(C)]
#[derive(Debug)]
pub struct Addr {
    pub saddr:u32,
    pub daddr:u32,
    pub sport:u16,
    pub dport:u16,
    pub id:u16
}