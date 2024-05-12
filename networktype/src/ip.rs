use core::mem;

use crate::bitfield::BitfieldUnit;

/// IP headers, which are present after the Ethernet header.
#[cfg_attr(features = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub enum IpHdr {
    V4(Ipv4Hdr),
    V6(Ipv6Hdr),
}

//// IPv4 header, which is present after the Ethernet header.
#[repr(C)]
#[derive(Debug, Copy, Clone)]
#[cfg_attr(features = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct Ipv4Hdr {
    pub _bitfield_align_1: [u8; 0],
    /// - Version: the first field tells us which IP version we are using, only IPv4 uses this header so you will always find decimal value 4 here.
    /// - Header Length: this 4 bit field tells us the length of the IP header in 32 bit increments.
    /// The minimum length of an IP header is 20 bytes so with 32 bit increments, you would see value of 5 here.
    /// The maximum value we can create with 4 bits is 15 so with 32 bit increments, that would be a header length of 60 bytes.
    /// This field is also called the Internet Header Length (IHL).
    pub _bitfield_1: BitfieldUnit<[u8; 1usize]>,
    /// Type of Service: this is used for QoS (Quality of Service).
    pub tos: u8,
    /// Total Length: this 16-bit field indicates the entire size of the IP packet (header and data) in bytes.
    /// The minimum size is 20 bytes (if you have no data) and the maximum size is 65,535 bytes, that’s the highest value you can create with 16 bits.
    pub tot_len: u16,
    /// Identification: If the IP packet is fragmented then each fragmented packet will use the same 16 bit identification number to identify to which IP packet they belong to.
    /// 如果数据包原始长度超过数据包所要经过的数据链路的最大传输单元（MTU），那么必须将数据包分段为更小的数据包。
    pub id: u16,
    /// IP Flags: These 3 bits are used for fragmentation:
    /// - The first bit is always set to 0.
    /// - The second bit is called the DF (Don’t Fragment) bit and indicates that this packet should not be fragmented.
    /// 当DF位被设置为1时，表示路由器不能对数据包进行分段处理。如果数据包由于不能被分段而未能被转发，那么路由器将丢弃该数据包并向源点发送错误消息。
    /// 这一功能可以在网络上用于测试MTU值。可以使用Ping工具可以对DF位进行设置测试。
    /// - The third bit is called the MF (More Fragments) bit and is set on all fragmented packets except the last one.
    ///
    /// Fragment Offset: this 13 bit field specifies the position of the fragment in the original fragmented IP packet.
    /// 以8个八位组为单位，用于指明分段起始点相对于报头起始点的偏移量。
    pub frag_off: u16,
    /// Time to Live: Everytime an IP packet passes through a router, the time to live field is decremented by 1.
    /// Once it hits 0 the router will drop the packet and sends an ICMP time exceeded message to the sender.
    /// The time to live field has 8 bits and is used to prevent packets from looping around forever (if you have a routing loop).
    /// Default to 64.
    pub ttl: u8,
    /// Protocol: this 8 bit field tells us which protocol is enapsulated in the IP packet, for example TCP has value 6 and UDP has value 17.
    pub proto: IpProto,
    /// Header Checksum: this 16 bit field is used to store a checksum of the header. The receiver can use the checksum to check if there are any errors in the header.
    /// 针对IP报头的纠错字段， 校验和不计算被封装的数据。
    pub check: u16,
    /// Source Address: here you will find the 32 bit source IP address.
    pub src_addr: u32,
    /// Destination Address: and here’s the 32 bit destination IP address.
    pub dst_addr: u32,
    // IP Option: this field is not used often, is optional and has a variable length based on the options that were used.
    // When you use this field, the value in the header length field will increase.
    // An example of a possible option is “source route” where the sender requests for a certain routing path.
    // 松散源路由选择（Loose Source Routing）——它给出了一连串路由器接口的IP地址序列。数据包必须沿着IP地址序列传送，但是允许在相继的两个地址之间跳过多台路由器。
    // 严格源路由选择（Strict Source Routing）——它也给出了一系列路由器接口的IP地址序列。不同于松散源路由选择，数据包必要严格按照路由转发。如果下一跳不再列表中，那么将会发生错误。
    // 记录路由（Record Route）——当数据包离开时为每台路由器提供空间记录数据包的出站接口地址，以便保存数据包经过的所有路由器的记录。记录路由选项提供了类似于路由追踪的功能，但是不同点在于这里记录了双向路径上的出站接口信息。
    // 时间戳（Timestamp）——除了每台路由器还会记录一个时间戳之外，时间戳选项十分类似于记录路由选项，这样数据包不仅可以知道自己到过哪里，而且还可以记录到达的时间。
    // 还可以在Option 字段内使用Linux 内核模块 TOA，tcp option address ，用来传递记录源ip地址，多用在网关转发时（LB等SDN网关上）；
    // 填充（Padding）——该字段通过在可选项字段后面添加0来补足32位，这样保证报头长度是32位的倍数。
}

impl Ipv4Hdr {
    pub const LEN: usize = mem::size_of::<Ipv4Hdr>();

    #[inline]
    pub fn ihl(&self) -> u8 {
        unsafe { mem::transmute(self._bitfield_1.get(0usize, 4u8) as u8) }
    }

    #[inline]
    pub fn set_ihl(&mut self, val: u8) {
        unsafe {
            let val: u8 = mem::transmute(val);
            self._bitfield_1.set(0usize, 4u8, val as u64)
        }
    }

    /// Version: the first field tells us which IP version we are using, only IPv4 uses this header so you will always find decimal value 4 here.
    /// - 0100表示IP版本4（IPv4）
    /// - 0110表示IP版本6（IPv6）
    #[inline]
    pub fn version(&self) -> u8 {
        unsafe { mem::transmute(self._bitfield_1.get(4usize, 4u8) as u8) }
    }

    #[inline]
    pub fn set_version(&mut self, val: u8) {
        unsafe {
            let val: u8 = mem::transmute(val);
            self._bitfield_1.set(4usize, 4u8, val as u64)
        }
    }

    #[inline]
    pub fn new_bitfield_1(ihl: u8, version: u8) -> BitfieldUnit<[u8; 1usize]> {
        let mut bitfield_unit: BitfieldUnit<[u8; 1usize]> = Default::default();
        bitfield_unit.set(0usize, 4u8, {
            let ihl: u8 = unsafe { mem::transmute(ihl) };
            ihl as u64
        });
        bitfield_unit.set(4usize, 4u8, {
            let version: u8 = unsafe { mem::transmute(version) };
            version as u64
        });
        bitfield_unit
    }
}

#[cfg(feature = "std")]
impl Ipv4Hdr {
    /// Returns the source address field. As network endianness is big endian, we convert it to host endianness.
    pub fn src_addr(&self) -> std::net::Ipv4Addr {
        std::net::Ipv4Addr::from(u32::from_be(self.src_addr))
    }

    /// Returns the destination address field. As network endianness is big endian, we convert it to host endianness.
    pub fn dst_addr(&self) -> std::net::Ipv4Addr {
        std::net::Ipv4Addr::from(u32::from_be(self.dst_addr))
    }

    /// Sets the source address field. As network endianness is big endian, we convert it from host endianness.
    pub fn set_src_addr(&mut self, src: std::net::Ipv4Addr) {
        self.src_addr = u32::from(src).to_be();
    }

    /// Sets the destination address field. As network endianness is big endian, we convert it from host endianness.
    pub fn set_dst_addr(&mut self, dst: std::net::Ipv4Addr) {
        self.dst_addr = u32::from(dst).to_be();
    }
}

#[repr(C)]
#[derive(Copy, Clone)]
#[cfg_attr(features = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct in6_addr {
    pub in6_u: in6_u,
}

#[repr(C)]
#[derive(Copy, Clone)]
#[cfg_attr(features = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub union in6_u {
    pub u6_addr8: [u8; 16usize],
    pub u6_addr16: [u16; 8usize],
    pub u6_addr32: [u32; 4usize],
}

#[repr(C)]
#[derive(Copy, Clone)]
#[cfg_attr(features = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct Ipv6Hdr {
    pub _bitfield_align_1: [u8; 0],
    /// Version (4-bits): Indicates version of Internet Protocol which contains bit sequence 0110.
    /// Traffic Class (8-bits): The Traffic Class field indicates class or priority of IPv6 packet which is similar to Service Field in IPv4 packet.
    /// It helps routers to handle the traffic based on the priority of the packet. If congestion occurs on the router then packets with the least priority will be discarded.
    /// As of now, only 4-bits are being used (and the remaining bits are under research), in which 0 to 7 are assigned to Congestion controlled traffic and 8 to 15 are assigned to Uncontrolled traffic.
    pub _bitfield_1: BitfieldUnit<[u8; 1usize]>,
    /// Flow Label (20-bits): Flow Label field is used by a source to label the packets belonging to the same flow
    /// in order to request special handling by intermediate IPv6 routers, such as non-default quality of service or
    /// real-time service. In order to distinguish the flow, an intermediate router can use the source address,
    /// a destination address, and flow label of the packets. Between a source and destination, multiple flows
    /// may exist because many processes might be running at the same time. Routers or Host that does not support the
    /// functionality of flow label field and for default router handling, flow label field is set to 0. While setting up
    /// the flow label, the source is also supposed to specify the lifetime of the flow.
    pub flow_label: [u8; 3usize],
    /// Payload Length (16-bits): It is a 16-bit (unsigned integer) field, indicates the total size of the payload which
    /// tells routers about the amount of information a particular packet contains in its payload. The payload Length field
    /// includes extension headers(if any) and an upper-layer packet. In case the length of the payload is greater
    /// than 65,535 bytes (payload up to 65,535 bytes can be indicated with 16-bits), then the payload length field
    /// will be set to 0 and the jumbo payload option is used in the Hop-by-Hop options extension header.
    pub payload_len: u16,
    /// Next Header (8-bits): Next Header indicates the type of extension header(if present) immediately following the IPv6
    /// header. Whereas In some cases it indicates the protocols contained within upper-layer packets, such as TCP, UDP.
    pub next_hdr: IpProto,
    /// Hop Limit (8-bits): Hop Limit field is the same as TTL in IPv4 packets. It indicates the maximum number of intermediate
    /// nodes IPv6 packet is allowed to travel. Its value gets decremented by one, by each node that forwards the packet and the
    /// packet is discarded if the value decrements to 0. This is used to discard the packets that are stuck in an infinite loop
    /// because of some routing error.
    pub hop_limit: u8,
    /// Source Address (128-bits): Source Address is the 128-bit IPv6 address of the original source of the packet.
    pub src_addr: in6_addr,
    /// Destination Address (128-bits): The destination Address field indicates the IPv6 address of the final destination(in most cases).
    /// All the intermediate nodes can use this information in order to correctly route the packet.
    pub dst_addr: in6_addr,
    // Extension Headers: In order to rectify the limitations of the IPv4 Option Field, Extension Headers are introduced in IP version 6.
    // The extension header mechanism is a very important part of the IPv6 architecture. The next Header field of IPv6 fixed header points
    // to the first Extension Header and this first extension header points to the second extension header and so on.
}

impl Ipv6Hdr {
    pub const LEN: usize = mem::size_of::<Ipv6Hdr>();

    #[inline]
    pub fn priority(&self) -> u8 {
        unsafe { mem::transmute(self._bitfield_1.get(0usize, 4u8) as u8) }
    }

    #[inline]
    pub fn set_priority(&mut self, val: u8) {
        unsafe {
            let val: u8 = mem::transmute(val);
            self._bitfield_1.set(0usize, 4u8, val as u64)
        }
    }

    #[inline]
    pub fn version(&self) -> u8 {
        unsafe { mem::transmute(self._bitfield_1.get(4usize, 4u8) as u8) }
    }

    #[inline]
    pub fn set_version(&mut self, val: u8) {
        unsafe {
            let val: u8 = mem::transmute(val);
            self._bitfield_1.set(4usize, 4u8, val as u64)
        }
    }

    #[inline]
    pub fn new_bitfield_1(priority: u8, version: u8) -> BitfieldUnit<[u8; 1usize]> {
        let mut bitfield_unit: BitfieldUnit<[u8; 1usize]> = Default::default();
        bitfield_unit.set(0usize, 4u8, {
            let priority: u8 = unsafe { mem::transmute(priority) };
            priority as u64
        });
        bitfield_unit.set(4usize, 4u8, {
            let version: u8 = unsafe { mem::transmute(version) };
            version as u64
        });
        bitfield_unit
    }
}

#[cfg(feature = "std")]
impl Ipv6Hdr {
    /// Returns the source address field. As network endianness is big endian, we convert it to host endianness.
    pub fn src_addr(&self) -> std::net::Ipv6Addr {
        std::net::Ipv6Addr::from(u128::from_be_bytes(unsafe { self.src_addr.in6_u.u6_addr8 }))
    }

    /// Returns the destination address field. As network endianness is big endian, we convert it to host endianness.
    pub fn dst_addr(&self) -> std::net::Ipv6Addr {
        std::net::Ipv6Addr::from(u128::from_be_bytes(unsafe { self.dst_addr.in6_u.u6_addr8 }))
    }

    /// Sets the source address field. As network endianness is big endian, we convert it from host endianness.
    pub fn set_src_addr(&mut self, src: std::net::Ipv6Addr) {
        self.src_addr = in6_addr {
            in6_u: in6_u {
                u6_addr8: u128::from(src).to_be_bytes(),
            },
        };
    }

    /// Sets the destination address field. As network endianness is big endian, we convert it from host endianness.
    pub fn set_dst_addr(&mut self, dst: std::net::Ipv6Addr) {
        self.dst_addr = in6_addr {
            in6_u: in6_u {
                u6_addr8: u128::from(dst).to_be_bytes(),
            },
        };
    }
}

/// Protocol which is encapsulated in the IPv4 packet.
/// <https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml>
#[repr(u8)]
#[derive(PartialEq, Eq, Debug, Copy, Clone)]
#[cfg_attr(features = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub enum IpProto {
    /// IPv6 Hop-by-Hop Option
    HopOpt = 0,
    /// Internet Control Message
    Icmp = 1,
    /// Internet Group Management
    Igmp = 2,
    /// Gateway-to-Gateway
    Ggp = 3,
    /// IPv4 encapsulation
    Ipv4 = 4,
    /// Stream
    Stream = 5,
    /// Transmission Control
    Tcp = 6,
    /// CBT
    Cbt = 7,
    /// Exterior Gateway Protocol
    Egp = 8,
    /// Any private interior gateway (used by Cisco for their IGRP)
    Igp = 9,
    /// BBN RCC Monitoring
    BbnRccMon = 10,
    /// Network Voice Protocol
    NvpII = 11,
    /// PUP
    Pup = 12,
    /// ARGUS
    Argus = 13,
    /// EMCON
    Emcon = 14,
    /// Cross Net Debugger
    Xnet = 15,
    /// Chaos
    Chaos = 16,
    /// User Datagram
    Udp = 17,
    /// Multiplexing
    Mux = 18,
    /// DCN Measurement Subsystems
    DcnMeas = 19,
    /// Host Monitoring
    Hmp = 20,
    /// Packet Radio Measurement
    Prm = 21,
    /// XEROX NS IDP
    Idp = 22,
    /// Trunk-1
    Trunk1 = 23,
    /// Trunk-2
    Trunk2 = 24,
    /// Leaf-1
    Leaf1 = 25,
    /// Leaf-2
    Leaf2 = 26,
    /// Reliable Data Protocol
    Rdp = 27,
    /// Internet Reliable Transaction
    Irtp = 28,
    /// ISO Transport Protocol Class 4
    Tp4 = 29,
    /// Bulk Data Transfer Protocol
    Netblt = 30,
    /// MFE Network Services Protocol
    MfeNsp = 31,
    /// MERIT Internodal Protocol
    MeritInp = 32,
    /// Datagram Congestion Control Protocol
    Dccp = 33,
    /// Third Party Connect Protocol
    ThirdPartyConnect = 34,
    /// Inter-Domain Policy Routing Protocol
    Idpr = 35,
    /// XTP
    Xtp = 36,
    /// Datagram Delivery Protocol
    Ddp = 37,
    /// IDPR Control Message Transport Proto
    IdprCmtp = 38,
    /// TP++ Transport Protocol
    TpPlusPlus = 39,
    /// IL Transport Protocol
    Il = 40,
    /// IPv6 encapsulation
    Ipv6 = 41,
    /// Source Demand Routing Protocol
    Sdrp = 42,
    /// Routing Header for IPv6
    Ipv6Route = 43,
    /// Fragment Header for IPv6
    Ipv6Frag = 44,
    /// Inter-Domain Routing Protocol
    Idrp = 45,
    /// Reservation Protocol
    Rsvp = 46,
    /// General Routing Encapsulation
    Gre = 47,
    /// Dynamic Source Routing Protocol
    Dsr = 48,
    /// BNA
    Bna = 49,
    /// Encap Security Payload
    Esp = 50,
    /// Authentication Header
    Ah = 51,
    /// Integrated Net Layer Security TUBA
    Inlsp = 52,
    /// IP with Encryption
    Swipe = 53,
    /// NBMA Address Resolution Protocol
    Narp = 54,
    /// IP Mobility
    Mobile = 55,
    /// Transport Layer Security Protocol using Kryptonet key management
    Tlsp = 56,
    /// SKIP
    Skip = 57,
    /// Internet Control Message Protocol for IPv6
    Ipv6Icmp = 58,
    /// No Next Header for IPv6
    Ipv6NoNxt = 59,
    /// Destination Options for IPv6
    Ipv6Opts = 60,
    /// Any host internal protocol
    AnyHostInternal = 61,
    /// CFTP
    Cftp = 62,
    /// Any local network
    AnyLocalNetwork = 63,
    /// SATNET and Backroom EXPAK
    SatExpak = 64,
    /// Kryptolan
    Kryptolan = 65,
    /// MIT Remote Virtual Disk Protocol
    Rvd = 66,
    /// Internet Pluribus Packet Core
    Ippc = 67,
    /// Any distributed file system
    AnyDistributedFileSystem = 68,
    /// SATNET Monitoring
    SatMon = 69,
    /// VISA Protocol
    Visa = 70,
    /// Internet Packet Core Utility
    Ipcv = 71,
    /// Computer Protocol Network Executive
    Cpnx = 72,
    /// Computer Protocol Heart Beat
    Cphb = 73,
    /// Wang Span Network
    Wsn = 74,
    /// Packet Video Protocol
    Pvp = 75,
    /// Backroom SATNET Monitoring
    BrSatMon = 76,
    /// SUN ND PROTOCOL-Temporary
    SunNd = 77,
    /// WIDEBAND Monitoring
    WbMon = 78,
    /// WIDEBAND EXPAK
    WbExpak = 79,
    /// ISO Internet Protocol
    IsoIp = 80,
    /// VMTP
    Vmtp = 81,
    /// SECURE-VMTP
    SecureVmtp = 82,
    /// VINES
    Vines = 83,
    /// Transaction Transport Protocol
    Ttp = 84,
    /// NSFNET-IGP
    NsfnetIgp = 85,
    /// Dissimilar Gateway Protocol
    Dgp = 86,
    /// TCF
    Tcf = 87,
    /// EIGRP
    Eigrp = 88,
    /// OSPFIGP
    Ospfigp = 89,
    /// Sprite RPC Protocol
    SpriteRpc = 90,
    /// Locus Address Resolution Protocol
    Larp = 91,
    /// Multicast Transport Protocol
    Mtp = 92,
    /// AX.25 Frames
    Ax25 = 93,
    /// IP-within-IP Encapsulation Protocol
    Ipip = 94,
    /// Mobile Internetworking Control Pro.
    Micp = 95,
    /// Semaphore Communications Sec. Pro.
    SccSp = 96,
    /// Ethernet-within-IP Encapsulation
    Etherip = 97,
    /// Encapsulation Header
    Encap = 98,
    /// Any private encryption scheme
    AnyPrivateEncryptionScheme = 99,
    /// GMTP
    Gmtp = 100,
    /// Ipsilon Flow Management Protocol
    Ifmp = 101,
    /// PNNI over IP
    Pnni = 102,
    /// Protocol Independent Multicast
    Pim = 103,
    /// ARIS
    Aris = 104,
    /// SCPS
    Scps = 105,
    /// QNX
    Qnx = 106,
    /// Active Networks
    ActiveNetworks = 107,
    /// IP Payload Compression Protocol
    IpComp = 108,
    /// Sitara Networks Protocol
    Snp = 109,
    /// Compaq Peer Protocol
    CompaqPeer = 110,
    /// IPX in IP
    IpxInIp = 111,
    /// Virtual Router Redundancy Protocol
    Vrrp = 112,
    /// PGM Reliable Transport Protocol
    Pgm = 113,
    /// Any 0-hop protocol
    AnyZeroHopProtocol = 114,
    /// Layer Two Tunneling Protocol
    L2tp = 115,
    /// D-II Data Exchange (DDX)
    Ddx = 116,
    /// Interactive Agent Transfer Protocol
    Iatp = 117,
    /// Schedule Transfer Protocol
    Stp = 118,
    /// SpectraLink Radio Protocol
    Srp = 119,
    /// UTI
    Uti = 120,
    /// Simple Message Protocol
    Smp = 121,
    /// Simple Multicast Protocol
    Sm = 122,
    /// Performance Transparency Protocol
    Ptp = 123,
    /// ISIS over IPv4
    IsisOverIpv4 = 124,
    /// FIRE
    Fire = 125,
    /// Combat Radio Transport Protocol
    Crtp = 126,
    /// Combat Radio User Datagram
    Crudp = 127,
    /// SSCOPMCE
    Sscopmce = 128,
    /// IPLT
    Iplt = 129,
    /// Secure Packet Shield
    Sps = 130,
    /// Private IP Encapsulation within IP
    Pipe = 131,
    /// Stream Control Transmission Protocol
    Sctp = 132,
    /// Fibre Channel
    Fc = 133,
    /// RSVP-E2E-IGNORE
    RsvpE2eIgnore = 134,
    /// Mobility Header
    MobilityHeader = 135,
    /// Lightweight User Datagram Protocol
    UdpLite = 136,
    /// MPLS-in-IP
    Mpls = 137,
    /// MANET Protocols
    Manet = 138,
    /// Host Identity Protocol
    Hip = 139,
    /// Shim6 Protocol
    Shim6 = 140,
    /// Wrapped Encapsulating Security Payload
    Wesp = 141,
    /// Robust Header Compression
    Rohc = 142,
    /// Ethernet in IPv4
    EthernetInIpv4 = 143,
    /// AGGFRAG encapsulation payload for ESP
    Aggfrag = 144,
    /// Use for experimentation and testing
    Test1 = 253,
    /// Use for experimentation and testing
    Test2 = 254,
    /// Reserved
    Reserved = 255,
}

#[cfg(test)]
mod tests {

    #[cfg(feature = "std")]
    #[test]
    fn test_v4() {
        use core::mem;
        use std::net::Ipv4Addr;

        use crate::ip::Ipv4Hdr;

        let expected_header_bytes = [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 127, 0, 0, 1, 127, 0, 0, 2,
        ];

        let ipv4_header: Ipv4Hdr = unsafe {
            mem::transmute::<[u8; Ipv4Hdr::LEN], _>(expected_header_bytes.try_into().unwrap())
        };
        assert_eq!(ipv4_header.src_addr(), Ipv4Addr::new(127, 0, 0, 1));
        assert_eq!(ipv4_header.dst_addr(), Ipv4Addr::new(127, 0, 0, 2));

        let mut header_bytes = [0u8; 20];
        let ipv4_header: *mut Ipv4Hdr = &mut header_bytes as *mut _ as *mut _;
        unsafe {
            (*ipv4_header).set_src_addr(Ipv4Addr::new(127, 0, 0, 1));
            (*ipv4_header).set_dst_addr(Ipv4Addr::new(127, 0, 0, 2));
        }

        let ipv4_header: Ipv4Hdr =
            unsafe { mem::transmute::<[u8; Ipv4Hdr::LEN], _>(header_bytes.try_into().unwrap()) };
        assert_eq!(ipv4_header.src_addr(), Ipv4Addr::new(127, 0, 0, 1));
        assert_eq!(ipv4_header.dst_addr(), Ipv4Addr::new(127, 0, 0, 2));

        assert_eq!(expected_header_bytes, header_bytes);
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_v6() {
        use core::mem;
        use std::net::Ipv6Addr;

        use crate::ip::Ipv6Hdr;

        let expected_header_bytes = [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
        ];

        let ipv6_header: Ipv6Hdr = unsafe {
            mem::transmute::<[u8; Ipv6Hdr::LEN], _>(expected_header_bytes.try_into().unwrap())
        };
        assert_eq!(
            ipv6_header.src_addr(),
            Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0)
        );
        assert_eq!(
            ipv6_header.dst_addr(),
            Ipv6Addr::new(2, 0, 0, 0, 0, 0, 0, 1)
        );

        let mut header_bytes = [0u8; 40];
        let ipv6_header: *mut Ipv6Hdr = &mut header_bytes as *mut _ as *mut _;
        unsafe {
            (*ipv6_header).set_src_addr(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0));
            (*ipv6_header).set_dst_addr(Ipv6Addr::new(2, 0, 0, 0, 0, 0, 0, 1));
        }

        let ipv6_header: Ipv6Hdr =
            unsafe { mem::transmute::<[u8; Ipv6Hdr::LEN], _>(header_bytes.try_into().unwrap()) };
        assert_eq!(
            ipv6_header.src_addr(),
            Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0)
        );
        assert_eq!(
            ipv6_header.dst_addr(),
            Ipv6Addr::new(2, 0, 0, 0, 0, 0, 0, 1)
        );

        assert_eq!(expected_header_bytes, header_bytes);
    }
}
