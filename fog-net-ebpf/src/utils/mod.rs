use core::mem;


#[cfg(feature = "xdp")]
use aya_ebpf::programs::XdpContext;
#[cfg(not(feature = "xdp"))]
use aya_ebpf::programs::TcContext;
use networktype::{eth::EthHdr, vlan::VlanHdr, EtherType};

pub mod tc;
pub mod xdp;
pub mod vlan;

// Converts a checksum into u16
#[inline(always)]
#[allow(dead_code)]
pub fn csum_fold_helper(mut csum: u64) -> u16 {
    for _i in 0..4 {
        if (csum >> 16) > 0 {
            csum = (csum & 0xffff) + (csum >> 16);
        }
    }
    !(csum as u16)
}

#[inline(always)]
#[allow(dead_code)]
pub fn ptr_at<T>(
    #[cfg(feature = "xdp")] ctx: &XdpContext,
    #[cfg(not(feature = "xdp"))] ctx: &TcContext,
    offset: usize,
) -> Option<*const T> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return None;
    }

    Some((start + offset) as *const T)
}

#[inline(always)]
#[allow(dead_code)]
pub fn ptr_at_mut<T>(
    #[cfg(feature = "xdp")] ctx: &XdpContext,
    #[cfg(not(feature = "xdp"))] ctx: &TcContext,
    offset: usize,
) -> Option<*mut T> {
    let ptr = ptr_at::<T>(ctx, offset)?;
    Some(ptr as *mut T)
}


#[inline(always)]
#[allow(dead_code)]
pub fn parse_l2_header(
    ctx: &XdpContext
) -> Option<EtherType> {
    let ethtype:  u16 =  unsafe {  *ptr_at(ctx, EthHdr::LEN - 2)? };
    // is valid ethertype
    match EtherType::try_from(ethtype){
        Ok(ethertype) => return Some(ethertype),
        Err(_) => (),
    }

    let vlantype: u16 =  unsafe {  *ptr_at(ctx, VlanHdr::LEN - 2)? };
    // is valid ethertype
    match EtherType::try_from(vlantype){
        Ok(vlantype) => return Some(vlantype),
        Err(_) => (),
    }


    Some(EtherType::Arp)
}