#![no_std]
pub mod endpoint;
use core::{fmt::Debug, hash::Hash};
pub const BPF_MAPS_CAPACITY: u32 = 1024;

/// VPC
#[repr(C)]
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub struct VPC {
    pub vpc_id: u32,
    pub dhcp_option_id: u32,
    pub route_table_id: u32,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for VPC{}

#[repr(C)]
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash, PartialOrd, Ord)]
pub enum IpAddr {
    V4([u8; 4]),
    V6([u8; 16]),
}

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

/// ACL rule
#[repr(C)]
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub struct ACLRule {
    pub acl_id: u32,
    pub rule_id: u32,
    pub protocol: u8,
    pub from_port: u16,
    pub to_port: u16,
    pub cidr: IpAddr,
    pub cidr_mask: u8,
    pub rule_action: u8,
    /// ingress   1<<0
    /// egress    1<<1
    pub direction: u8,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for ACLRule{}



