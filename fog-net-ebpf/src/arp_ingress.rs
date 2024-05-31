#![no_std]
#![no_main]

use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use aya_ebpf::{
    bindings::{TC_ACT_OK, TC_ACT_PIPE, TC_ACT_SHOT},
    macros::classifier,
    programs::TcContext,
};
use fog_net_common::{
    constant::common::{DROP_FRAG_NOSUPPORT, DROP_INVALID, DROP_UNKNOWN_L3, DROP_UNSUPPORTED_L2, TRACE_PAYLOAD_LEN},
    ctx::Context,
    map::endpoint::NIC,
    trace::{
        send_trace_notify, TracePoint, TraceReason, TRACE_EP_ID_UNKNOWN, TRACE_IFINDEX_UNKNOWN,
    },
};
use networktype::EtherType;

const ENABLE_IPV4_FRAGMENTS: bool = true;
const ENABLE_MULTICAST: bool = true;
const ENABLE_NODEPORT: bool = true;

// this is me, the tc classifier working for
// regenerate this nic when nic modified
const WHOAMI: NIC = NIC {
    mac: [0xfe, 0x00, 0x25, 0x93, 0x2F, 0x01],
    node_mac: [0x00, 0x15, 0x5d, 0x88, 0xc3, 0xbc],
    ifindex: 7,
    vlan_id: 0,
    eni_id: 10086,
    vm_id: 10086,
    ipv4: Ipv4Addr::new(172, 22, 76, 156),
    ipv6: Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1),
    ipv4_mask: 20,
    ipv6_mask: 0,
    subnet_id: 10000,
    vpc_id: 10000,
    is_bare_metal: 0,
    bm_vlan_id: 0,
    flags: 0,
};

/// Attachment/entry point is ingress for veth.
/// It corresponds to packets leaving the container.
#[classifier]
pub fn cil_from_container(ctx: TcContext) -> i32 {
    // protocol verify
    // let sec_label: u32 = SECLABEL;

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

    match try_from_container(Context::Skb(ctx)) {
        Ok(ret) => ret,
        Err(_r) => {
            // return send_drop_notify_ext(ctx, sec_label, UNKNOWN_ID,
            //     TRACE_EP_ID_UNKNOWN, ret, ext_err,
            //     CTX_ACT_DROP, METRIC_EGRESS);
            TC_ACT_SHOT
        }
    }
}

fn try_from_container(mut ctx: Context) -> Result<i32, i32> {
    let sec_label = WHOAMI.eni_id;
    let vm_id = WHOAMI.vm_id;
    let ethtype = ctx.parse_l2_header().ok_or(DROP_UNSUPPORTED_L2)?;
    ctx.bpf_clear_meta();
    ctx.reset_queue_mapping();

    send_trace_notify(
        &ctx,
        TracePoint::TRACE_FROM_LXC,
        sec_label,
        0,
        IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
        TRACE_EP_ID_UNKNOWN,
        TRACE_IFINDEX_UNKNOWN as u32,
        TraceReason::TRACE_REASON_UNKNOWN,
        TRACE_PAYLOAD_LEN as u32,
    );

    match ethtype {
        EtherType::Ipv4 => {
            ctx.edt_set_aggregate(vm_id);
        }
        EtherType::Arp => {
            //  ifdef ENABLE_ARP_PASSTHROUGH
            // 	case bpf_htons(ETH_P_ARP):
            // 		ret = CTX_ACT_OK;
            // 		break;
            // #elif defined(ENABLE_ARP_RESPONDER)
            // 	case bpf_htons(ETH_P_ARP):
            // 		ret = tail_call_internal(ctx, CILIUM_CALL_ARP, &ext_err);
            // 		break;
            return Ok(TC_ACT_OK);
        }

        EtherType::Ipv6 => {
            ctx.edt_set_aggregate(vm_id);
        }
        _ => {
            return Err(DROP_UNKNOWN_L3);
        }
    }

    Ok(TC_ACT_PIPE)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

pub fn handle_ipv4(mut ctx: Context) -> Result<i32, i32> {
    let ip = ctx.parse_ipv4_header().ok_or(DROP_INVALID)?;
    if ip.is_fragment() && !ENABLE_IPV4_FRAGMENTS {
        /* If IPv4 fragmentation is disabled
         * AND a IPv4 fragmented packet is received,
         * then drop the packet.
         */

        return Err(DROP_FRAG_NOSUPPORT);
    }

    let daddr = Ipv4Addr::from(ip.dst_addr);
    if daddr.is_broadcast() && ENABLE_MULTICAST{
        // 查询多播表,如果有这个多播地址,进行多播处理的尾调CILIUM_CALL_MULTICAST_EP_DELIVERY
    }
    Ok(TC_ACT_OK)
}
