use core::mem;

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

/// Protocol which is encapsulated in the payload of the Ethernet frame.
/// 
/// According [EtherType](https://en.wikipedia.org/wiki/EtherType)
#[repr(u16)]
#[derive(PartialEq, Eq, Debug, Copy, Clone)]
#[cfg_attr(features = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub enum EtherType {
    Loop = 0x0060_u16.to_be(),
    Ipv4 = 0x0800_u16.to_be(),
    Arp = 0x0806_u16.to_be(),
    /// wake on lan
    WakeOnLan = 0x0842_u16.to_be(),
    /// Cisco Discovery Protocol
    CDP = 0x2000_u16.to_be(), 
    /// VLAN-tagged frame (IEEE 802.1Q) and Shortest Path Bridging IEEE 802.1aq with NNI compatibility
    VLAN = 0x8100_u16.to_be(),
    /// Simple Loop Prevention Protocol
    SLPP = 0x8102_u16.to_be(),
    /// Virtual Link Aggregation Control Protocol
    VLACP = 0x8103_u16.to_be(),
    /// Internet Protocol Version 6 
    Ipv6 = 0x86DD_u16.to_be(),
    MPLSUnicast = 0x8847_u16.to_be(),
    MPLSMulticast = 0x8848_u16.to_be(),
    /// Ethernet Slow Protocols such as the Link Aggregation Control Protocol (LACP)
    LACP = 0x8809_u16.to_be(),
    /// Service VLAN tag identifier (S-Tag) on Q-in-Q tunnel
    QinQ = 0x88A8_u16.to_be(),
    /// Link Layer Discovery Protocol 
    LLDP = 0x88CC_u16.to_be(),
    FibreChannel = 0x8906_u16.to_be(),
    /// RDMA over Converged Ethernet (RoCE)
    RoCE = 0x8915_u16.to_be(),
    LoopbackIeee8023 = 0x9000_u16.to_be(),
}
