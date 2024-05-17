use core::net::IpAddr;
use aya_ebpf::{ macros::map, maps::HashMap};


#[repr(C)]
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub struct Subnet {
    pub vpc_id: u32,
    pub sb_id: u32,
    pub cidr: IpAddr,
    pub cidr_mask: u8,
    pub route_table_id: u32,
    pub network_acl_id: u32,
    pub micro_segmention: bool,
    pub gateway_ip: IpAddr,
    pub vlan_id: u16,
}
#[cfg(feature = "user")]
unsafe impl aya::Pod for Subnet{}


pub const SUBNET_CNT: u32 = 65535;

#[cfg_attr(target_arch = "bpf", map)]
pub static mut SUBNET_MAP: HashMap<u32, Subnet> = HashMap::<u32, Subnet>::with_max_entries(SUBNET_CNT,0);



