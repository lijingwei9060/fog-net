use aya_ebpf::{
    macros::{map, xdp},
    maps::HashMap,
};

use super::MacAddr;

#[repr(C)]
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub struct NIC {
    pub mac: MacAddr,
    pub node_mac: MacAddr,
    pub ifindex: u32,
    pub vlan_id: u16,
    pub eni_id: u32,
    pub vm_id: u32,
    pub ipv4: [u8; 4],

    pub ipv6: [u8; 16],
    pub ipv4_mask: u8,
    pub ipv6_mask: u8,
    pub subnet_id: u32,
    pub vpc_id: u32,
    // pub private_ip: IpAddr,
    pub is_bare_metal: u8,
    pub bm_vlan_id: u16,

    /// source_dst_check         1<<0
    /// is_sys_mod               1<<1
    /// is_need_mod_lvs_vip      1<<2
    pub flags: u8,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for NIC {}

pub const LOCAL_ENDPOINT_CNT: u32 = 1024;
pub const ALL_ENDPOINT_CNT: u32 = 65535;

#[cfg_attr(target_arch = "bpf", map)]
pub static mut LOCAL_ENDPOINT: HashMap<MacAddr, NIC> =
    HashMap::<MacAddr, NIC>::with_max_entries(LOCAL_ENDPOINT_CNT, 0);

#[cfg_attr(target_arch = "bpf", map)]
pub static mut ALL_ENDPOINT: HashMap<MacAddr, NIC> =
    HashMap::<MacAddr, NIC>::with_max_entries(ALL_ENDPOINT_CNT, 0);

#[cfg_attr(target_arch = "bpf", map)]
pub static mut LOCAL_ARP_ENDPOINT: HashMap<[u8; 4], NIC> =
    HashMap::<[u8; 4], NIC>::with_max_entries(LOCAL_ENDPOINT_CNT, 0);

/// get nic by mac in local nics  
pub fn get_nic_in_local(mac: &MacAddr) -> Option<NIC> {
    unsafe { LOCAL_ENDPOINT.get(mac).copied() }
}

/// get nic by mac in all nics
pub fn get_nic(mac: &MacAddr) -> Option<NIC> {
    unsafe { ALL_ENDPOINT.get(mac).copied() }
}
