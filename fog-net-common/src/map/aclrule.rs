use core::net::IpAddr;

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


