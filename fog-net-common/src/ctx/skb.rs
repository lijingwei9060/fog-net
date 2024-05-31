use core::mem;

use aya_ebpf::programs::TcContext;
use networktype::{
    eth::EthHdr,
    ip::{Ipv4Hdr, Ipv6Hdr},
    EtherType,
};

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
#[inline(always)]
pub fn ctx_load_meta(ctx: &TcContext, offset: usize) -> u32 {
    let offset = offset % unsafe { (*ctx.skb.skb).cb }.len();
    // 第n个元素
    unsafe { (*ctx.skb.skb).cb[offset] }
}

/// get metadata
#[inline(always)]
pub fn ctx_store_meta(ctx: &TcContext, offset: usize, datum: u32) {
    let offset = offset % unsafe { (*ctx.skb.skb).cb }.len();
    // 第n个元素
    unsafe {
        (*ctx.skb.skb).cb[offset] = datum;
    }
}

pub fn ctx_full_len(ctx: &TcContext) -> u64 {
    ctx.len() as u64
}

/// unused
#[inline(always)]
pub fn bpf_clear_meta(ctx: &mut TcContext) {
    for i in ctx.cb_mut() {
        *i = 0;
    }

    unsafe {
        (*ctx.skb.skb).tc_classid = 0;
    }
}
