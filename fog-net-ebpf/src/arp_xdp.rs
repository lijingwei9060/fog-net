#![no_std]
#![no_main]

use core::mem;

use aya_ebpf::{
    bindings::xdp_action,
    helpers::{bpf_csum_diff, bpf_redirect},
    macros::xdp,
    programs::XdpContext,
};
use aya_log_ebpf::info;
use networktype::{
    eth::EthHdr,
    ip::{IpProto, Ipv4Hdr},
};

use fog_net_common::{ctx::xdp::{ptr_at, ptr_at_mut, tracing_packet}, map::endpoint::map::LOCAL_ARP_ENDPOINT, utils::csum_fold_helper};


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
    unsafe { tracing_packet(&ctx); }
    let ethhdr: *const EthHdr = ptr_at(&ctx, 0).ok_or(xdp_action::XDP_PASS)?;
    let src_mac = unsafe { (*ethhdr).src_addr };
    let dst_mac = unsafe { (*ethhdr).dst_addr };

    if networktype::EtherType::Ipv4 == unsafe { (*ethhdr).ether_type } {
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

                    // xdp_stats_record_action(&ctx, xdp_action::XDP_REDIRECT);
                    
                    return Ok(unsafe { bpf_redirect(nic.ifindex, 0) as u32 });
                }
                _ => {
                    // xdp_stats_record_action(&ctx, xdp_action::XDP_PASS);
                    return Ok(xdp_action::XDP_PASS);
                }
            }
        }
    }
    Ok(xdp_action::XDP_PASS)
}


