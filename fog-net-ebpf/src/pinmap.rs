#![no_std]
#![no_main]

use core::mem;

use aya_ebpf::{bindings::xdp_action, helpers::bpf_redirect, macros::{map, xdp}, maps::HashMap, programs::XdpContext};
use aya_log_ebpf::info;
use fog_net_common::map::endpoint::NIC;
use networktype::eth::EthHdr;

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}


#[map]
static MAC_NIC: HashMap<[u8;6], NIC> = HashMap::<[u8;6], NIC>::with_max_entries(10000, 0);

#[xdp]
pub fn fog_net(ctx: XdpContext) -> u32 {
    match try_fog_net(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

fn try_fog_net(ctx: XdpContext) -> Result<u32, ()> {
    let ethhdr: *const EthHdr = unsafe { ptr_at(&ctx, 0)? };
    let dst_mac = unsafe {(*ethhdr).dst_addr};
    match unsafe { redirect_to(&(*ethhdr).dst_addr)}{
        Some(ifindex) => {
            info!(&ctx, "redirect {:mac} to {}", dst_mac, ifindex);
            let ret = unsafe { bpf_redirect(ifindex, 0) };
            Ok(ret as u32)
        },
        None => {
            Ok(xdp_action::XDP_PASS)
        }
    }
    
}


fn redirect_to(mac: &[u8;6]) -> Option<u32>{
    unsafe { MAC_NIC.get(mac) }.map(|nic|nic.ifindex)
}

#[inline(always)]
unsafe fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    let ptr = (start + offset) as *const T;
    Ok(&*ptr)
}