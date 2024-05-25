//! 每个包（skb）打上一个最早离开时间（Earliest Departure Time, EDT），也就是最早可以发送的时间戳。
//! 用时间轮调度器（timing-wheel scheduler）替换原来的出向缓冲队列（qdisc queue）。
use aya_ebpf::{
    bindings::{TC_ACT_OK, TC_ACT_SHOT},
    helpers::bpf_ktime_get_ns,
    programs::TcContext,
};
use networktype::EtherType;

use crate::ctx::skb::parse_l2_header;

use self::map::{get_mut_throttle_map_by_id, THROTTLE_MAP};
/// 每秒钟有多少ns
pub const NSEC_PER_SEC: u64 = 1000_000_000;

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

/// 从物理网卡发出的时候进行带宽管理，也可以是从overlay发出的时候进行带宽管理。
#[inline(always)]
pub fn edt_sched_departure(ctx: &TcContext) -> Result<(), i32> {
    let ether_type = parse_l2_header(ctx).ok_or(TC_ACT_OK)?; // 不认识的2层包，发

    if ether_type != EtherType::Ipv4 && ether_type != EtherType::Ipv6 {
        // 3层既不是ipv4也不是ipv6，发
        return Err(TC_ACT_OK);
    }

    let edt_id = edt_get_aggregate(ctx);

    // 没有设置
    if edt_id == 0 {
        // 数据包没有设置edt规则，发
        return Err(TC_ACT_OK);
    }
    let info = get_mut_throttle_map_by_id(&edt_id).ok_or(TC_ACT_OK)?; // 没有带宽规则，发

    // 设置数据包的edt时间
    let now = unsafe { bpf_ktime_get_ns() };
    let mut t = unsafe { (*ctx.skb.skb).tstamp };
    if t < now {
        t = now;
    }
    // 这个数据包根据长度可以接受的延迟时间，单位ns
    let delay = (ctx.len() as u64 * NSEC_PER_SEC / info.bps) as u64;
    let t_next = info.t_last + delay;

    if t_next <= t {
        // 时间都过去了，现在还没有发出去，抓紧发吧
        info.t_last = t; // 现在就发
        return Err(TC_ACT_OK); // 别忙活了，现在就发
    }

    /* FQ implements a drop horizon, see also 39d010504e6b ("net_sched:
     * sch_fq: add horizon attribute"). However, we explicitly need the
     * drop horizon here to i) avoid having t_last messed up and ii) to
     * potentially allow for per aggregate control.
     */
    /* This patch adds a configurable horizon (default: 10 seconds),
     * and a configurable policy when a packet is beyond the horizon
     * at enqueue() time
     */

    if t_next - now >= info.t_horizon_drop {
        return Err(TC_ACT_SHOT);
    }
    // 在t_horizon_drop时间内的数据包，标记时间
    info.t_last = t_next;

    // 对于包的时间戳 skb->tstamp，内核根据包的方向（RX/TX）不同而使用的两种时钟源：
    // Ingress 使用 CLOCK_TAI (TAI: international atomic time)
    // Egress 使用 CLOCK_MONOTONIC（也是 FQ 使用的时钟类型）
    // ref: https://cloud.tencent.com/developer/article/1907476
    unsafe {
        (*ctx.skb.skb).tstamp = t_next;
    }
    return Err(TC_ACT_OK);
}

//#[cfg(target_arch = "bpf")]
pub mod map {
    use aya_ebpf::{macros::map, maps::HashMap};

    use super::EdtInfo;

    pub const THROTTLE_MAP_SIZE: u32 = 65536;

    #[map]
    pub static mut THROTTLE_MAP: HashMap<u32, EdtInfo> =
        HashMap::<u32, EdtInfo>::with_max_entries(THROTTLE_MAP_SIZE, 0);

    #[inline(always)]
    pub fn get_throttle_map_by_id(id: u32) -> Option<EdtInfo> {
        unsafe { THROTTLE_MAP.get(&id).copied() }
    }

    pub fn get_mut_throttle_map_by_id(id: &u32) -> Option<&mut EdtInfo> {
        unsafe { THROTTLE_MAP.get_ptr_mut(&id).map(|p| &mut (*p)) }
    }
}
