#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::{TC_ACT_PIPE, TC_ACT_SHOT},
    macros::classifier,
    programs::TcContext,
};
use aya_log_ebpf::info;
use fog_net_common::{constant::DROP_INVALID, ctx::skb::parse_ipv4_header, trace::TraceCtx};
use networktype::{eth::EthHdr, EtherType};

/// Attachment/entry point is ingress for veth.
/// It corresponds to packets leaving the container.
#[classifier]
pub fn cil_from_container(ctx: TcContext) -> i32 {
    // protocol verify
    // let sec_label: u32 = SECLABEL;
    // bpf_clear_meta(ctx);
	// reset_queue_mapping(ctx);

    // 1. tracing
    // 2. eth validate => DROP_UNSUPPORTED_L2
    // 3. 
    // ipv4 => 3.1.
    // ipv6 => 
    // arp  => 

    // 3.1. 
    // edt_set_aggregate(ctx, LXC_ID);
    // ip fragment && 不支持 => DROP_FRAG_NOSUPPORT
    // mac ip validate => DROP_INVALID_SIP
    // igmp => mcast_ipv4_handle_igmp
    // 目标是多播地址 => ?
    // 查找目标IP、分配双向连接跟踪表空间、连接状态、hairpin、dsr
    // 
    match try_tc_ingress(ctx) {
        Ok(ret) => ret,
        Err(_) => TC_ACT_SHOT,
    }
}


#[classifier]
pub fn tc_egress(ctx: TcContext) -> i32 {
    match try_tc_ingress(ctx) {
        Ok(ret) => ret,
        Err(_) => TC_ACT_SHOT,
    }
}

fn try_tc_ingress(ctx: TcContext) -> Result<i32, ()> {
    let meta = 0;
    let len = ctx.len();

    let ethhdr: EthHdr = ctx.load(0).map_err(|_| ())?;
    info!(&ctx, "{:x}{:x}{:x}{:x}{:x}{:x}", ethhdr.dst_addr[0], ethhdr.dst_addr[1], ethhdr.dst_addr[2], ethhdr.dst_addr[3], ethhdr.dst_addr[4], ethhdr.dst_addr[5]);
    match ethhdr.ether_type {
        EtherType::Ipv4 => {}
        _ => return Ok(TC_ACT_PIPE),
    }

    let data = (unsafe { *ctx.skb.skb }).mark;
    info!(&ctx, "{} {} {}", meta, data, len);

    Ok(TC_ACT_PIPE)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

const MAC_ADDR: [u32; 6] = [0u32,0,0,0,0,0]; // host mac address
pub fn handle_ipv4_from_lxc(ctx: &TcContext, dst: u32) -> Result<(), i32>{

    let mut trace = TraceCtx::default();
    
    let mut has_l4_header = false; // 对于一些特殊的数据包可能没有4层头，只有IP层
    let mut from_l7lb = false;
    let mut cluster_id = 0u64; // vpc_id

    let ipv4 = parse_ipv4_header(ctx).ok_or(DROP_INVALID)?;
    let hair_flow = ipv4.has_l4_header(); //endpoint wants to access itself via service IP

    // 查询remote endpoint


    Ok(())

}