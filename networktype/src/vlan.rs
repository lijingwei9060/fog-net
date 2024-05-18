use core::mem;

use crate::{bitfield::BitfieldUnit, EtherType, Validate};

/// Vlan Ethernet header, which is present at the beginning of every Ethernet frame.
#[repr(C)]
#[derive(Debug, Copy, Clone, Default)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct VlanHdr {
    pub _bitfield_align_1: [u8; 0],
    /// tag control information
    pub tci: BitfieldUnit<[u8; 2usize]>,
    /// Protocol which is encapsulated in the payload of the frame.
    pub ether_type: EtherType,
}

impl VlanHdr {
    pub const LEN: usize = mem::size_of::<VlanHdr>();
    /// VLAN ID (VID), indicating the VLAN to which a frame belongs.
    ///
    /// 12bits
    ///
    /// The VLAN ID is in the range from 0 to 4095. The values 0 and 4095 are reserved, and therefore available VLAN IDs are in the range from 1 to 4094.
    #[inline]
    pub fn vid(&self) -> u16 {
        unsafe { mem::transmute(self.tci.get(0usize, 12u8) as u16) }
    }

    #[inline]
    pub fn set_vid(&mut self, val: u16) {
        unsafe {
            let val: u16 = mem::transmute(val);
            self.tci.set(0usize, 12u8, val as u64)
        }
    }

    /// Canonical Format Indicator (CFI), indicating whether a MAC address is encapsulated in canonical format over different transmission media.
    /// CFI is used to ensure compatibility between Ethernet and token ring networks.
    ///
    /// 1bit
    ///
    /// The value 0 indicates that the MAC address is encapsulated in canonical format,
    /// and the value 1 indicates that the MAC address is encapsulated in non-canonical format.
    /// The CFI field has a fixed value of 0 on Ethernet networks.
    #[inline]
    pub fn cfi(&self) -> u8 {
        unsafe { mem::transmute(self.tci.get(12usize, 1u8) as u8) }
    }

    #[inline]
    pub fn set_cfi(&mut self, val: u8) {
        unsafe {
            let val: u8 = mem::transmute(val);
            self.tci.set(12usize, 1u8, val as u64)
        }
    }

    /// Priority code point (PCP), indicating the 802.1p priority of a frame.
    ///
    /// 3bits
    ///
    /// The value is in the range from 0 to 7. A larger value indicates a higher priority.
    /// If congestion occurs, the switch sends packets with the highest priority first.
    #[inline]
    pub fn pcp(&self) -> u8 {
        unsafe { mem::transmute(self.tci.get(13usize, 3u8) as u8) }
    }

    #[inline]
    pub fn set_pcp(&mut self, val: u8) {
        unsafe {
            let val: u8 = mem::transmute(val);
            self.tci.set(13usize, 3u8, val as u64)
        }
    }
}

impl Validate for VlanHdr {
    fn validate(&self) -> bool {
        return true;
    }
}
