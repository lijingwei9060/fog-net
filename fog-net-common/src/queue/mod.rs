//! 每个包（skb）打上一个最早离开时间（Earliest Departure Time, EDT），也就是最早可以发送的时间戳。
//! 用时间轮调度器（timing-wheel scheduler）替换原来的出向缓冲队列（qdisc queue）。
use aya_ebpf::{bindings::TC_ACT_OK, programs::TcContext};
use networktype::EtherType;

use crate::ctx::skb::parse_l2_header;

#[repr(C)]
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub struct EdtInfo {
    pub bps: u64,
    pub t_last: u64,
    pub t_horizon_drop: u64,
    pub pad: [u64; 4],
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for EdtInfo {}

/// workaround for GH-18311
#[inline(always)]
pub fn reset_queue_mapping(ctx: &TcContext) {
    /* Workaround for GH-18311 where veth driver might have recorded
     * veth's RX queue mapping instead of leaving it at 0. This can
     * cause issues on the phys device where all traffic would only
     * hit a single TX queue (given veth device had a single one and
     * mapping was left at 1). Reset so that stack picks a fresh queue.
     * Kernel fix is at 710ad98c363a ("veth: Do not record rx queue
     * hint in veth_xmit").
     */
    unsafe { *ctx.skb.skb }.queue_mapping = 0;
}

/* From XDP layer, we neither go through an egress hook nor qdisc
 * from here, hence nothing to be set.
 */
#[inline(always)]
pub fn edt_set_aggregate(ctx: &TcContext, aggregate: u32) {
    /* 16 bit as current used aggregate, and preserved in host ns. */
    unsafe { (*ctx.skb.skb).queue_mapping = aggregate };
}

#[inline(always)]
pub fn edt_get_aggregate(ctx: &TcContext) -> u32 {
    let aggregate = unsafe { (*ctx.skb.skb).queue_mapping };

    /* We need to reset queue mapping here such that new mapping will
     * be performed based on skb hash. See netdev_pick_tx().
     */
    unsafe {
        (*ctx.skb.skb).queue_mapping = 0;
    }

    return aggregate;
}

#[inline(always)]
pub fn edt_sched_departure(ctx: &TcContext) -> Result<(), i32> {
    let ether_type = parse_l2_header(ctx).ok_or(TC_ACT_OK)?;

    if ether_type != EtherType::Ipv4 && ether_type != EtherType::Ipv6 {
        return Err(TC_ACT_OK);
    }

    let edt_id = edt_get_aggregate(ctx);

    // 没有设置
    if edt_id == 0 {
        return Err(TC_ACT_OK);
    }
		// todo: edt.h 查看THROTTLE_MAP
    Ok(())
}

//#[cfg(target_arch = "bpf")]
pub mod map {
    use aya_ebpf::{macros::map, maps::HashMap};

    use super::EdtInfo;

    pub const THROTTLE_MAP_SIZE: u32 = 65536;

    #[map]
    pub static mut THROTTLE_MAP: HashMap<u32, EdtInfo> =
        HashMap::<u32, EdtInfo>::with_max_entries(THROTTLE_MAP_SIZE, 0);
}
