use core::mem;

use crate::EtherType;

/// Ethernet header, which is present at the beginning of every Ethernet frame.
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
#[cfg_attr(features = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
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


