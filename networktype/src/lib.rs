//! Rust structs representing network protocol headers (on Layer 2, 3 and 4).
//!
//! The crate is [no_std](https://docs.rust-embedded.org/book/intro/no-std.html),
//! which makes it a great fit for [eBPF](https://ebpf.io/) programs written
//! with [Aya](https://aya-rs.dev/).
//!
//! # Examples
//!
//! An example of an [XDP program](https://aya-rs.dev/book/start/) logging
//! information about addresses and ports for incoming packets:
//!
//! ```rust
//! use core::mem;
//!
//! use aya_bpf::{bindings::xdp_action, macros::xdp, programs::XdpContext};
//! use aya_log_ebpf::info;
//!
//! use network_types::{
//!     eth::{EthHdr, EtherType},
//!     ip::{Ipv4Hdr, IpProto},
//!     tcp::TcpHdr,
//!     udp::UdpHdr,
//! };
//!
//! #[xdp]
//! pub fn xdp_firewall(ctx: XdpContext) -> u32 {
//!     match try_xdp_firewall(ctx) {
//!         Ok(ret) => ret,
//!         Err(_) => xdp_action::XDP_PASS,
//!     }
//! }
//!
//! #[inline(always)]
//! unsafe fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
//!     let start = ctx.data();
//!     let end = ctx.data_end();
//!     let len = mem::size_of::<T>();
//!
//!     if start + offset + len > end {
//!         return Err(());
//!     }
//!
//!     Ok((start + offset) as *const T)
//! }
//!
//! fn try_xdp_firewall(ctx: XdpContext) -> Result<u32, ()> {
//!     let ethhdr: *const EthHdr = unsafe { ptr_at(&ctx, 0)? };
//!     match unsafe { *ethhdr }.ether_type {
//!         EtherType::Ipv4 => {}
//!         _ => return Ok(xdp_action::XDP_PASS),
//!     }
//!
//!     let ipv4hdr: *const Ipv4Hdr = unsafe { ptr_at(&ctx, EthHdr::LEN)? };
//!     let source_addr = u32::from_be(unsafe { *ipv4hdr }.src_addr);
//!
//!     let source_port = match unsafe { *ipv4hdr }.proto {
//!         IpProto::Tcp => {
//!             let tcphdr: *const TcpHdr =
//!                 unsafe { ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN) }?;
//!             u16::from_be(unsafe { *tcphdr }.source)
//!         }
//!         IpProto::Udp => {
//!             let udphdr: *const UdpHdr =
//!                 unsafe { ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN) }?;
//!             u16::from_be(unsafe { *udphdr }.source)
//!         }
//!         _ => return Err(()),
//!     };
//!
//!     info!(&ctx, "SRC IP: {}, SRC PORT: {}", source_addr, source_port);
//!
//!     Ok(xdp_action::XDP_PASS)
//! }
//! ```
//!
//! # Naming conventions
//!
//! When naming stucts and fields, we are trying to stick to the following
//! principles:
//!
//! * Use `CamelCase`, even for names which normally would be all uppercase
//!   (e.g. `Icmp` instead of `ICMP`). This is the convention used by the
//!   [std::net](https://doc.rust-lang.org/std/net/index.html) module.
//! * Where field names (specified by RFCs or other standards) contain spaces,
//!   replace them with `_`. In general, use `snake_case` for field names.
//! * Shorten the following verbose names:
//!   * `source` -> `src`
//!   * `destination` -> `dst`
//!   * `address` -> `addr`
//!
//! # Feature flags
//!
//! [Serde](https://serde.rs) support can be enabled through the `serde`
//! feature flag. It is intended to be used with binary serialization libraries
//! like [`bincode`](https://crates.io/crates/bincode) that leverage Serde's
//! infrastructure.
//!
//! Note that `no_std` support is lost when enabling Serde.

#![cfg_attr(not(feature = "std"), no_std)]

pub mod bitfield;
pub mod eth;
pub mod icmp;
pub mod ip;
pub mod qinq;
pub mod tcp;
pub mod udp;
pub mod vlan;
pub mod vxlan;

/// Protocol which is encapsulated in the payload of the Ethernet frame.
///
/// According [EtherType](https://en.wikipedia.org/wiki/EtherType)
#[repr(u16)]
#[derive(PartialEq, Eq, Debug, Copy, Clone)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub enum EtherType {
    Loop = 0x0060_u16.to_be(),
    Ipv4 = 0x0800_u16.to_be(),
    Arp = 0x0806_u16.to_be(),
    /// wake on lan
    WakeOnLan = 0x0842_u16.to_be(),
    /// Cisco Discovery Protocol
    CDP = 0x2000_u16.to_be(),
    /// Stream Reservation Protocol
    SRP = 0x22EA_u16.to_be(),
    /// Audio Video Transport Protocol
    AVTP = 0x22F0_u16.to_be(),
    /// IETF TRILL Protocol
    TRILL = 0x22F3_u16.to_be(),
    /// DEC MOP RC
    MOP = 0x6002_u16.to_be(),
    /// DECnet Phase IV, DNA Routing
    DECnet = 0x6003_u16.to_be(),
    DECLAT = 0x6004_u16.to_be(),
    /// Reverse Address Resolution Protocol
    RARP = 0x8035_u16.to_be(),
    AppleTalk = 0x809B_u16.to_be(),
    /// AppleTalk Address Resolution Protocol
    AARP = 0x80F3_u16.to_be(),
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

impl TryFrom<u16> for EtherType {
    type Error = ();
    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0x0060 => Ok(EtherType::Loop),
            0x0800 => Ok(EtherType::Ipv4),
            0x0806 => Ok(EtherType::Arp),
            0x0842 => Ok(EtherType::WakeOnLan),
            0x2000 => Ok(EtherType::CDP),
            0x22EA => Ok(EtherType::SRP),
            0x22F0 => Ok(EtherType::AVTP),
            0x22F3 => Ok(EtherType::TRILL),
            0x6002 => Ok(EtherType::MOP),
            0x6003 => Ok(EtherType::DECnet),
            0x6004 => Ok(EtherType::DECLAT),
            0x8035 => Ok(EtherType::RARP),
            0x809B => Ok(EtherType::AppleTalk),
            0x80F3 => Ok(EtherType::AARP),
            0x8100 => Ok(EtherType::VLAN),
            0x8102 => Ok(EtherType::SLPP),
            0x8103 => Ok(EtherType::VLACP),
            0x86DD => Ok(EtherType::Ipv6),
            0x8847 => Ok(EtherType::MPLSUnicast),
            0x8848 => Ok(EtherType::MPLSMulticast),
            0x8809 => Ok(EtherType::LACP),
            0x88A8 => Ok(EtherType::QinQ),
            0x88CC => Ok(EtherType::LLDP),
            0x8906 => Ok(EtherType::FibreChannel),
            0x8915 => Ok(EtherType::RoCE),
            0x9000 => Ok(EtherType::LoopbackIeee8023),
            _ => Err(()),
        }
    }
}

impl Default  for EtherType{
    fn default() -> Self {
        EtherType::Ipv4
    }
}

impl EtherType{
    pub fn is_vlan(&self) -> bool{
        self == &EtherType::VLAN || self == &EtherType::QinQ
    }
}
pub trait Validate {
    /// Returns true if the header is valid, false otherwise.
    fn validate(&self) -> bool;
}
