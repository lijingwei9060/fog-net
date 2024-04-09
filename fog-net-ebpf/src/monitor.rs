#![no_std]
#![no_main]

use core::mem;

use aya_ebpf::{bindings::xdp_action, macros::xdp, programs::XdpContext};
use aya_log_ebpf::info;
use network_types::{
    eth::EthHdr,
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

#[xdp]
pub fn fog_net(ctx: XdpContext) -> u32 {
    match try_fog_net(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

fn try_fog_net(ctx: XdpContext) -> Result<u32, ()> {
    info!(&ctx, "received a packet");
    let ethhdr: *const EthHdr = ptr_at(&ctx, 0)?;
    let ingress_iface = unsafe { (*ctx.ctx).ingress_ifindex };
    // let egress_iface = unsafe { (*ctx.ctx).egress_ifindex };
    let src_mac = unsafe { (*ethhdr).src_addr };
    let dst_mac = unsafe { (*ethhdr).dst_addr };
    let ethtype = unsafe { (*ethhdr).ether_type };

    info!(
        &ctx,
        "iface:{}  smac:{:mac} dmac:{:mac} type",
        ingress_iface,        
        src_mac,
        dst_mac            
    );
    // match ethtype {
    //     network_types::eth::EtherType::Loop => {
    //         info!(
    //             &ctx,
    //             "iface:{} eface:{} smac:{:mac} dmac:{:mac} type: loop",
    //             ingress_iface,
    //             egress_iface,
    //             src_mac,
    //             dst_mac
    //         );
    //     }
    //     network_types::eth::EtherType::Ipv4 => {
    //         let ipv4hdr: *const Ipv4Hdr = ptr_at(&ctx, EthHdr::LEN)?;
    //         let source_addr = u32::from_be(unsafe { (*ipv4hdr).src_addr });
    //         let dst_addr = u32::from_be(unsafe { (*ipv4hdr).dst_addr });

    //         let (proto, sport, dport) = match unsafe { (*ipv4hdr).proto } {
    //             IpProto::Tcp => {
    //                 let tcphdr: *const TcpHdr = ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
    //                 let sport = u16::from_be(unsafe { (*tcphdr).source });
    //                 let dport = u16::from_be(unsafe { (*tcphdr).dest });
    //                 ("tcp", sport, dport)
    //             }
    //             IpProto::Udp => {
    //                 let udphdr: *const UdpHdr = ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
    //                 let sport = u16::from_be(unsafe { (*udphdr).source });
    //                 let dport = u16::from_be(unsafe { (*udphdr).dest });
    //                 ("udp", sport, dport)
    //             }
    //             _ => return Err(()),
    //         };
    //         info!(
    //             &ctx,
    //             "iface:{} eface:{} smac:{:mac} dmac:{:mac} type:ipv4 proto:{} {:i}:{} {:i}:{}",
    //             ingress_iface,
    //             egress_iface,
    //             src_mac,
    //             dst_mac,
    //             proto,
    //             source_addr,
    //             sport,
    //             dst_addr,
    //             dport,
    //         );
    //     }
    //     network_types::eth::EtherType::Arp => {
    //         info!(
    //             &ctx,
    //             "iface:{} eface:{} smac:{:mac} dmac:{:mac} type: loop",
    //             ingress_iface,
    //             egress_iface,
    //             src_mac,
    //             dst_mac
    //         );
    //     }
    //     // network_types::eth::EtherType::Ipv6 => todo!(),
    //     // network_types::eth::EtherType::FibreChannel => todo!(),
    //     // network_types::eth::EtherType::Infiniband => todo!(),
    //     // network_types::eth::EtherType::LoopbackIeee8023 => todo!(),

    //     _=> {},
    // }

    Ok(xdp_action::XDP_PASS)
}

#[inline(always)]
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}
