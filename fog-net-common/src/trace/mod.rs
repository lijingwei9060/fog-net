use core::{
    hash,
    net::{IpAddr, Ipv4Addr},
};

use aya_ebpf::EbpfContext;

use crate::{
    constant::{common::NOTIFY_CAPTURE_VER, i::EVENT_SOURCE},
    ctx::Context,
};

use self::metrics::map::update_trace_metrics;

pub mod metrics;

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[allow(non_camel_case_types)]
pub enum TracePoint {
    TRACE_TO_LXC = 0,
    TRACE_TO_PROXY,
    TRACE_TO_HOST,
    TRACE_TO_STACK,
    TRACE_TO_OVERLAY,
    TRACE_FROM_LXC,
    TRACE_FROM_PROXY,
    TRACE_FROM_HOST,
    TRACE_FROM_STACK,
    TRACE_FROM_OVERLAY,
    TRACE_FROM_NETWORK,
    TRACE_TO_NETWORK,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[allow(non_camel_case_types)]
pub enum TraceReason {
    TRACE_REASON_POLICY = CTStatus::CT_NEW as u8,
    TRACE_REASON_CT_ESTABLISHED = CTStatus::CT_ESTABLISHED as u8,
    TRACE_REASON_CT_REPLY = CTStatus::CT_REPLY as u8,
    TRACE_REASON_CT_RELATED = CTStatus::CT_RELATED as u8,
    TRACE_REASON_CT_REOPENED = CTStatus::CT_REOPENED as u8,
    TRACE_REASON_UNKNOWN,
    TRACE_REASON_SRV6_ENCAP,
    TRACE_REASON_SRV6_DECAP,
    TRACE_REASON_ENCRYPT_OVERLAY,
    /// Note: TRACE_REASON_ENCRYPTED is used as a mask. Beware if you add
    /// new values below it, they would match with that mask.
    TRACE_REASON_ENCRYPTED = 0x80,
}

/// value is tagged with reason
#[inline(always)]
pub fn is_trace_reason(v: u8, reason: TraceReason) -> bool {
    v & (reason as u8) > 0
}

/* metrics reasons for forwarding packets and other stats.
 * If reason is larger than below then this is a drop reason and
 * value corresponds to -(DROP_*), see above.
 *
 * These are shared with pkg/monitor/api/drop.go.
 * When modifying any of the below, those files should also be updated.
 */
#[repr(i16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[allow(non_camel_case_types)]
pub enum Reason {
    REASON_FORWARDED = 0,
    REASON_PLAINTEXT = 3,
    REASON_DECRYPT = 4,
    REASON_LB_NO_BACKEND_SLOT = 5,
    REASON_LB_NO_BACKEND = 6,
    REASON_LB_REVNAT_UPDATE = 7,
    REASON_LB_REVNAT_STALE = 8,
    REASON_FRAG_PACKET = 9,
    REASON_FRAG_PACKET_UPDATE = 10,
    REASON_MISSED_CUSTOM_CALL = 11,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[allow(non_camel_case_types)]
pub enum CTDir {
    CT_EGRESS = 0,
    CT_INGRESS,
    CT_SERVICE,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[allow(non_camel_case_types)]
pub enum CTStatus {
    CT_NEW = 0,
    CT_ESTABLISHED,
    CT_REPLY,
    CT_RELATED,
    CT_REOPENED,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct TraceCtx {
    pub reason: TraceReason,
    /// Monitor length for number of bytes to forward in trace message. 0 means do not monitor.
    pub monitor: u32,
}

impl Default for TraceCtx {
    fn default() -> Self {
        Self {
            reason: TraceReason::TRACE_REASON_UNKNOWN,
            monitor: 0,
        }
    }
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[allow(non_camel_case_types)]
pub enum CiliumNotifyType {
    CILIUM_NOTIFY_UNSPEC = 0,
    CILIUM_NOTIFY_DROP,
    CILIUM_NOTIFY_DBG_MSG,
    CILIUM_NOTIFY_DBG_CAPTURE,
    CILIUM_NOTIFY_TRACE,
    CILIUM_NOTIFY_POLICY_VERDICT,
    CILIUM_NOTIFY_CAPTURE,
    CILIUM_NOTIFY_TRACE_SOCK,
}

#[repr(C, align(8))]
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct TraceNotify {
    pub r#type: u8,
    pub subtype: u8,
    pub source: u16,
    pub hash: u32,
    pub len_orig: u32, /* Length of original packet */
    pub len_cap: u16,  /* Length of captured bytes */
    pub version: u16,  /* Capture header version */
    pub src_label: u32,
    pub dst_label: u32,
    pub dst_id: u16,
    pub reason: u8,
    pub ipv6: u8,
    pub ifindex: u32,
    pub orig_ip: IpAddr,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for TraceNotify {}

/// Trace aggregation levels.
#[repr(u8)]
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq, PartialOrd, Ord)]
#[allow(non_camel_case_types)]
pub enum TraceLevel {
    TRACE_AGGREGATE_NONE = 0,      /* Trace every packet on rx & tx */
    TRACE_AGGREGATE_RX = 1,        /* Hide trace on packet receive */
    TRACE_AGGREGATE_ACTIVE_CT = 3, /* Ratelimit active connection traces */
}

/// todo: Set the level of aggregation for monitor events in the datapath
pub const MONITOR_AGGREGATION: u8 = 0;

#[inline(always)]
pub fn emit_trace_notify(obs_point: TracePoint, monitor: u32) -> bool {
    if MONITOR_AGGREGATION >= TraceLevel::TRACE_AGGREGATE_RX as u8 {
        match obs_point {
            TracePoint::TRACE_FROM_LXC
            | TracePoint::TRACE_FROM_PROXY
            | TracePoint::TRACE_FROM_HOST
            | TracePoint::TRACE_FROM_STACK
            | TracePoint::TRACE_FROM_OVERLAY
            | TracePoint::TRACE_FROM_NETWORK => return false,
            _ => {}
        }
    }
    /*
     * Ignore sample when aggregation is enabled and 'monitor' is set to 0.
     * Rate limiting (trace message aggregation) relies on connection tracking,
     * so if there is no CT information available at the observation point,
     * then 'monitor' will be set to 0 to avoid emitting trace notifications
     * when aggregation is enabled (the default).
     */
    if MONITOR_AGGREGATION >= TraceLevel::TRACE_AGGREGATE_ACTIVE_CT as u8 && monitor == 0 {
        return false;
    }

    return true;
}

pub const TRACE_PAYLOAD_LEN: u64 = 128;
pub const TRACE_EP_ID_UNKNOWN: u16 = 0;
pub const TRACE_IFINDEX_UNKNOWN: u16 = 0;/* Linux kernel doesn't use ifindex 0 */
pub fn send_trace_notify(
    ctx: &Context,
    obs_point: TracePoint,
    src: u32,
    dst: u32,
    orig_ip: IpAddr,
    dst_id: u16,
    ifindex: u32,
    reason: TraceReason,
    monitor: u32,
) {
    let ctx_len = ctx.ctx_full_len(); //ctx len
    let cap_len = u64::min(
        if monitor > 0 {
            monitor as u64
        } else {
            TRACE_PAYLOAD_LEN
        },
        ctx_len,
    );

    update_trace_metrics(ctx_len, obs_point, reason as u8);

    // 如果不需要trace就结束了
    if !emit_trace_notify(obs_point, monitor) {
        return;
    }

    let msg = TraceNotify {
        r#type: CiliumNotifyType::CILIUM_NOTIFY_TRACE as u8,
        subtype: obs_point as u8,
        source: EVENT_SOURCE, // HOST_EP_ID / LXC_ID
        hash: ctx.get_hash_recalc(),
        src_label: src,
        dst_label: dst,
        dst_id,
        reason: reason as u8,
        ifindex,
        len_orig: ctx_len as u32,
        len_cap: cap_len as u16,
        version: NOTIFY_CAPTURE_VER,
        ipv6: if orig_ip.is_ipv6() { 1 } else { 0 },
        orig_ip,
    };

    ctx.ctx_trace_event_output(cap_len as u32, &msg);
}
