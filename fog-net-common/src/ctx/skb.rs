use core::mem;

use aya_ebpf::programs::TcContext;
use networktype::{eth::EthHdr, ip::{Ipv4Hdr, Ipv6Hdr}, EtherType};


#[inline(always)]
pub fn ptr_at<T>(ctx: &TcContext, offset: usize) -> Option<*const T> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return None;
    }

    Some((start + offset) as *const T)
}

#[inline(always)]
pub fn ptr_at_mut<T>(ctx: &TcContext, offset: usize) -> Option<*mut T> {
    let ptr = ptr_at::<T>(ctx, offset)?;
    Some(ptr as *mut T)
}

#[inline(always)]
pub fn parse_l2_header(ctx: &TcContext) -> Option<EtherType> {
    ptr_at::<EthHdr>(ctx, 0).map(|e| unsafe { (*e).ether_type })
}

#[inline(always)]
pub fn parse_ipv4_header(ctx: &TcContext) -> Option<&Ipv4Hdr> {
    let ether_type = parse_l2_header(ctx)?;
    match ether_type {
        EtherType::Ipv4 => ptr_at::<Ipv4Hdr>(ctx, EthHdr::LEN).map(|e| unsafe { &(*e) }),
        _ => None,
    }
}

#[inline(always)]
pub fn parse_ipv6_header(ctx: &TcContext) -> Option<&Ipv6Hdr> {
    let ether_type = parse_l2_header(ctx)?;
    match ether_type {
        EtherType::Ipv6 => ptr_at::<Ipv6Hdr>(ctx, EthHdr::LEN).map(|e| unsafe { &(*e) }),
        _ => None,
    }
}

/// get metadata
pub fn ctx_load_meta(ctx: &TcContext, offset: u32) -> u32{
  let offset = offset as usize % unsafe { (*ctx.skb.skb).cb}.len();
  // 第n个元素
  unsafe { (*ctx.skb.skb).cb[offset]}
}

/// unused
#[inline(always)]
pub fn bpf_clear_meta(_ctx: &TcContext){

}