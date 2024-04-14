#![no_std]
#![no_main]

use core::mem::{self, size_of};

use aya_ebpf::{
    bindings::xdp_action,
    helpers::{bpf_csum_diff, bpf_redirect},
    macros::xdp,
    programs::XdpContext,
};
use aya_log_ebpf::info;
use network_types::{
    eth::EthHdr,
    ip::{IpProto, Ipv4Hdr},
};

use fog_net_common::endpoint::LOCAL_ARP_ENDPOINT;

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

#[xdp]
pub fn fog_net(ctx: XdpContext) -> u32 {
    match arp_redirect(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

fn arp_redirect(ctx: XdpContext) -> Result<u32, u32> {
    let ethhdr: *const EthHdr = ptr_at(&ctx, 0).ok_or(xdp_action::XDP_PASS)?;
    let src_mac = unsafe { (*ethhdr).src_addr };
    let dst_mac = unsafe { (*ethhdr).dst_addr };

    if network_types::eth::EtherType::Ipv4 == unsafe { (*ethhdr).ether_type } {
        let ipv4hdr = ptr_at_mut::<Ipv4Hdr>(&ctx, EthHdr::LEN).ok_or(xdp_action::XDP_PASS)?;
        let source_addr = u32::from_be(unsafe { (*ipv4hdr).src_addr });
        let dst_addr = u32::from_be(unsafe { (*ipv4hdr).dst_addr });

        info!(
            &ctx,
            "{:mac}{:i} {:mac}:{:i}", src_mac, source_addr, dst_mac, dst_addr
        );
        if unsafe { (*ipv4hdr).proto } == IpProto::Icmp {
            match unsafe { LOCAL_ARP_ENDPOINT.get(&[0, 0, 0, 0]) } {
                Some(nic) => {
                    unsafe {
                        (*ipv4hdr).dst_addr = u32::from_le_bytes([127, 0, 0, 1]);
                        (*ipv4hdr).src_addr = u32::from_le_bytes([127, 0, 0, 1]);
                    }
                    unsafe { (*ipv4hdr).check = 0 };                  
                    let full_cksum = unsafe {
                        bpf_csum_diff(
                            mem::MaybeUninit::zeroed().assume_init(),
                            0,
                            ipv4hdr as *mut _,
                            Ipv4Hdr::LEN as u32,
                            0,
                        )  as u64
                    };

                    unsafe { (*ipv4hdr).check = csum_fold_helper(full_cksum) };
                    
                    return Ok(unsafe { bpf_redirect(nic.ifindex, 0) as u32 });
                }
                _ => return Ok(xdp_action::XDP_PASS),
            }
        }
    }
    Ok(xdp_action::XDP_PASS)
}

#[inline(always)]
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Option<*const T> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return None;
    }

    Some((start + offset) as *const T)
}

#[inline(always)]
fn ptr_at_mut<T>(ctx: &XdpContext, offset: usize) -> Option<*mut T> {
    let ptr = ptr_at::<T>(ctx, offset)?;
    Some(ptr as *mut T)
}

// Converts a checksum into u16
#[inline(always)]
pub fn csum_fold_helper(mut csum: u64) -> u16 {
    for _i in 0..4 {
        if (csum >> 16) > 0 {
            csum = (csum & 0xffff) + (csum >> 16);
        }
    }
    !(csum as u16)
}
