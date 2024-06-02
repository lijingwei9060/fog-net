use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};

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
    pub ipv4: Ipv4Addr,

    pub ipv6: Ipv6Addr,
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

/// Structure representing an IPv4 or IPv6 address, being used as the key
/// for the endpoints map.
#[repr(C)]
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub struct EndpointKey {
    pub ip: IpAddr,
    pub family: u8,
    pub key: u8,
    pub cluster_id: u16,
}
#[cfg(feature = "user")]
unsafe impl aya::Pod for EndpointKey {}

pub const ENDPOINT_KEY_IPV6: u8 = 2;
pub const ENDPOINT_KEY_IPV4: u8 = 1;
pub const V6_CACHE_KEY_LEN: u32 = 128;
pub const V4_CACHE_KEY_LEN: u32 = 32;

#[repr(C)]
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub struct RemoteEndpointInfo {
    pub sec_identity: u32,
    pub tunnel_endpoint: u32,
    pub pad: u16,
    pub key: u8,
    pub flag_skip_tunnel: u8,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for RemoteEndpointInfo {}

//#[cfg(target_arch = "bpf")]
pub mod map {
    use core::net::IpAddr;

    use aya_ebpf::{
        macros::map,
        maps::{HashMap, LpmTrie},
    };

    use crate::map::MacAddr;

    use super::{EndpointKey, RemoteEndpointInfo, NIC};

    pub const LOCAL_ENDPOINT_CNT: u32 = 1024;
    pub const ALL_ENDPOINT_CNT: u32 = 65535;

    #[map]
    pub static mut LOCAL_ENDPOINT: HashMap<MacAddr, NIC> =
        HashMap::<MacAddr, NIC>::with_max_entries(LOCAL_ENDPOINT_CNT, 0);

    #[map]
    pub static mut ALL_ENDPOINT: HashMap<MacAddr, NIC> =
        HashMap::<MacAddr, NIC>::with_max_entries(ALL_ENDPOINT_CNT, 0);

    #[map]
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

    pub const IPCACHE_MAP_SIZE: u32 = 512000;
    #[map]
    pub static mut IPCACHE_MAP: LpmTrie<EndpointKey, RemoteEndpointInfo> =
        LpmTrie::with_max_entries(IPCACHE_MAP_SIZE, 0);


    pub fn ipcache_lookup(ip: IpAddr, prefix: u32, cluster_id: u32) -> Option<u32>{
        let key = 
    }
}
