use aya_ebpf::{ macros::{map, xdp},maps::HashMap};

use crate::IpAddr;

#[repr(C)]
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub struct NetworkInterface {
    pub mac: [u8; 6],
    pub ifindex: u32,
    pub vlan_id: u16,
    pub eni_id: u32,
    pub ipv4: IpAddr,
    // pub ipv6: IpAddr,
    // pub ipv4_mask: u8,
    // pub ipv6_mask: u8,
    // pub subnet_id: u32,
    // pub private_ip: IpAddr,    
    // pub is_bare_metal: u8,
    // pub bm_vlan_id: u16,

    /// source_dst_check         1<<0
    /// is_sys_mod               1<<1
    /// is_need_mod_lvs_vip      1<<2
    pub flags: u8,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for NetworkInterface {}

#[cfg_attr(target_arch = "bpf", map)]
pub static mut LOCAL_ENDPOINT: HashMap<[u8; 6], NetworkInterface> = HashMap::<[u8; 6], NetworkInterface>::with_max_entries(1024,0);

#[cfg_attr(target_arch = "bpf", map)]
pub static mut LOCAL_ARP_ENDPOINT: HashMap<[u8; 4], NetworkInterface> = HashMap::<[u8; 4], NetworkInterface>::with_max_entries(1024,0);