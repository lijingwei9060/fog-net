use core::mem::{self, size_of};

use aya_ebpf::{
    bindings::xdp_action::{self, XDP_TX},
    helpers::{bpf_redirect, bpf_xdp_adjust_head, bpf_xdp_adjust_meta, bpf_xdp_get_buff_len},
    macros::map,
    maps::PerCpuArray,
    programs::XdpContext,
    EbpfContext,
};
use networktype::{eth::EthHdr, vlan::VlanHdr, EtherType};

use crate::perf::MetaInfo;

#[inline(always)]
pub fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Option<*const T> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return None;
    }

    Some((start + offset) as *const T)
}

#[inline(always)]
pub fn ptr_at_mut<T>(ctx: &XdpContext, offset: usize) -> Option<*mut T> {
    let ptr = ptr_at::<T>(ctx, offset)?;
    Some(ptr as *mut T)
}

/// 转发数据包
pub fn ctx_redirect(ctx: &XdpContext, ifindex: u32, flags: u32) -> u32 {
    if unsafe { *ctx.ctx }.ingress_ifindex == ifindex {
        return XDP_TX;
    }
    unsafe { bpf_redirect(ifindex, flags as u64) as u32 }
}

/// peer间转发
pub fn ctx_redirect_peer(_ctx: &XdpContext, _ifindex: u32, _flags: u32) -> u32 {
    /* bpf_redirect_peer() is available only in TC BPF. */
    unimplemented!();
}

/// ctx长度
pub fn ctx_full_len(ctx: &XdpContext) -> u64 {
    unsafe { bpf_xdp_get_buff_len(ctx.as_ptr() as *mut _)}
}

#[map]
pub static mut CILIUM_XDP_SCRATCH: PerCpuArray<u32> = PerCpuArray::<u32>::with_max_entries(1, 0);

/// store metadata
pub fn ctx_store_meta(_ctx: &XdpContext, _offset: usize, datum: u32) {
    unsafe {
        let d = CILIUM_XDP_SCRATCH.get_ptr_mut(0).unwrap();
        *d = datum;
    }
}

/// get metadata
pub fn ctx_load_meta(_ctx: &XdpContext, _offset: usize) -> u32 {
    unsafe {
        let d = CILIUM_XDP_SCRATCH.get_ptr_mut(0).unwrap();
        *d
    }
}

/// load and clean metadata
pub fn ctx_load_and_clear_meta(ctx: &XdpContext, offset: usize) -> u32 {
    let re = ctx_load_meta(ctx, offset);
    ctx_store_meta(ctx, offset, 0);
    re
}

/// get ether type
pub fn ctx_get_protocol(ctx: &XdpContext) -> Option<networktype::EtherType> {
    ptr_at::<EthHdr>(ctx, 0).map(|f| (unsafe { *f }).ether_type)
}

pub fn ctx_get_ifindex(ctx: &XdpContext) -> u32 {
    unsafe { *ctx.ctx }.ingress_ifindex
}

pub fn ctx_get_ingress_ifindex(ctx: &XdpContext) -> u32 {
    unsafe { *ctx.ctx }.ingress_ifindex
}

#[inline(always)]
pub fn meta_at<T>(ctx: &XdpContext, offset: usize) -> Option<*const T> {
    let start = ctx.metadata();
    let end = ctx.metadata_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return None;
    }

    Some((start + offset) as *const T)
}

#[inline(always)]
pub fn meta_at_mut<T>(ctx: &XdpContext, offset: usize) -> Option<*mut T> {
    let ptr = meta_at::<T>(ctx, offset)?;
    Some(ptr as *mut T)
}

#[inline(always)]
pub fn parse_l2_header(ctx: &XdpContext) -> Option<EtherType> {
    ptr_at::<EthHdr>(ctx, 0).map(|e| unsafe { (*e).ether_type })
}

/// Pops the outermost VLAN tag off the packet. Returns the popped VLAN ID on
/// success or negative errno on failure.
pub unsafe fn vlan_tag_pop(ctx: &mut XdpContext) -> Result<u16, ()> {
    let eth_hdr = ptr_at::<EthHdr>(ctx, 0);
    if eth_hdr.is_none() {
        return Err(());
    }
    let eth_hdr = eth_hdr.unwrap();
    if !(unsafe { *eth_hdr }).ether_type.is_vlan() {
        return Err(());
    }
    let vlan_hdr = ptr_at::<VlanHdr>(ctx, EthHdr::LEN);
    if vlan_hdr.is_none() {
        return Err(());
    }
    let vlan_hdr = vlan_hdr.unwrap();
    let vid = (unsafe { *vlan_hdr }).vid();
    let proto = (unsafe { *vlan_hdr }).ether_type;
    let eth_copy = unsafe { *eth_hdr };

    /* Actually adjust the head pointer */
    // todo(casoul): for tc?
    if bpf_xdp_adjust_head(ctx.as_ptr() as *mut _, VlanHdr::LEN as i32) != 0 {
        return Err(());
    }

    let eth_hdr = ptr_at_mut::<EthHdr>(ctx, 0);
    if eth_hdr.is_none() {
        return Err(());
    }
    (*eth_hdr.unwrap()).ether_type = proto;
    (*eth_hdr.unwrap()).src_addr = eth_copy.src_addr;
    (*eth_hdr.unwrap()).dst_addr = eth_copy.dst_addr;

    Ok(vid)
}

/// Pushes a new VLAN tag after the Ethernet header. Returns 0 on success,
/// -1 on failure.
pub unsafe fn vlan_tag_push(ctx: &mut XdpContext, vid: u16) -> Result<(), ()> {
    let eth_hdr = ptr_at::<EthHdr>(ctx, 0);
    if eth_hdr.is_none() {
        return Err(());
    }

    let eth_hdr = eth_hdr.unwrap();
    let vlan_proto = match (*eth_hdr).ether_type {
        EtherType::VLAN => EtherType::QinQ,
        _ => EtherType::VLAN,
    };
    let h_proto = (*eth_hdr).ether_type;
    // copy eth header
    let eth_copy = *eth_hdr;

    /* Actually adjust the head pointer */
    // todo(casoul): for tc?
    if bpf_xdp_adjust_head(ctx.as_ptr() as *mut _, 0 - VlanHdr::LEN as i32) != 0 {
        return Err(());
    }

    let eth_hdr = ptr_at_mut::<EthHdr>(ctx, 0);
    if eth_hdr.is_none() {
        return Err(());
    }
    let eth_hdr = eth_hdr.unwrap();
    (*eth_hdr).src_addr = eth_copy.src_addr;
    (*eth_hdr).dst_addr = eth_copy.dst_addr;
    (*eth_hdr).ether_type = vlan_proto;

    let vlan_hdr = ptr_at_mut::<VlanHdr>(ctx, EthHdr::LEN);
    if vlan_hdr.is_none() {
        return Err(());
    }
    let vlan_hdr = vlan_hdr.unwrap();
    (*vlan_hdr).set_vid(vid);
    (*vlan_hdr).ether_type = h_proto;

    Ok(())
}

pub unsafe fn tracing_packet(ctx: &XdpContext) -> aya_ebpf::bindings::xdp_action::Type {
    //  Reserve space in-front of data pointer for our meta info.
    // * (Notice drivers not supporting data_meta will fail here!)
    if bpf_xdp_adjust_meta(ctx.as_ptr() as *mut _, 0 - size_of::<MetaInfo>() as i32) != 0 {
        // some thing wrong happened
        return xdp_action::XDP_DROP;
    }
    let meta = meta_at_mut::<MetaInfo>(ctx, 0);

    if meta.is_none() {
        return xdp_action::XDP_DROP;
    }

    (*meta.unwrap()).set_traing(true);

    return xdp_action::XDP_PASS;
}


/// clear meta
#[inline(always)]
pub fn bpf_clear_meta(_ctx: &mut XdpContext){

}