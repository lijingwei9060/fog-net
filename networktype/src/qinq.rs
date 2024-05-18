use core::mem;

use crate::{bitfield::BitfieldUnit, EtherType, Validate};

/// QinQHdr Ethernet header, which is present at the beginning of every Ethernet frame.
#[repr(C)]
#[derive(Debug, Copy, Clone)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct QinQHdr {
    /// Destination MAC address.
    pub dst_addr: [u8; 6],
    /// Source MAC address.
    pub src_addr: [u8; 6],
    pub service_tpid: u16,
    pub _bitfield_0: BitfieldUnit<[u8; 2usize]>,
    pub tpid: u16,
    pub _bitfield_1: BitfieldUnit<[u8; 2usize]>,
    /// Protocol which is encapsulated in the payload of the frame.
    pub ether_type: EtherType,
}

impl QinQHdr {
  pub const LEN: usize = mem::size_of::<QinQHdr>();
}


impl Validate for QinQHdr {
    fn validate(&self) -> bool {
        self.service_tpid == EtherType::QinQ as u16 && self.tpid == EtherType::VLAN as u16
    }
}