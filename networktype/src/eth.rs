use core::mem;

use crate::{EtherType, Validate};

/// Ethernet header, which is present at the beginning of every Ethernet frame.
#[repr(C)]
#[derive(Debug, Copy, Clone, Default)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct EthHdr {
    /// Destination MAC address.
    pub dst_addr: [u8; 6],
    /// Source MAC address.
    pub src_addr: [u8; 6],
    /// Protocol which is encapsulated in the payload of the frame.
    pub ether_type: EtherType,
}

impl EthHdr {
    pub const LEN: usize = mem::size_of::<EthHdr>();
}


impl Validate for EthHdr {
    fn validate(&self) -> bool {
        self.ether_type == EtherType::Ipv4 || self.ether_type == EtherType::Ipv6
    }
}