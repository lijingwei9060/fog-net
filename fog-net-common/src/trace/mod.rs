use core::net::IpAddr;

use aya_ebpf::EbpfContext;

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
    DROP_UNUSED1 = -130, /* unused */
    DROP_UNUSED2 = -131, /* unused */
    DROP_INVALID_SIP = -132,
    DROP_POLICY = -133,
    DROP_INVALID = -134,
    DROP_CT_INVALID_HDR = -135,
    DROP_FRAG_NEEDED = -136,
    DROP_CT_UNKNOWN_PROTO = -137,
    DROP_UNUSED4 = -138, /* unused */
    DROP_UNKNOWN_L3 = -139,
    DROP_MISSED_TAIL_CALL = -140,
    DROP_WRITE_ERROR = -141,
    DROP_UNKNOWN_L4 = -142,
    DROP_UNKNOWN_ICMP_CODE = -143,
    DROP_UNKNOWN_ICMP_TYPE = -144,
    DROP_UNKNOWN_ICMP6_CODE = -145,
    DROP_UNKNOWN_ICMP6_TYPE = -146,
    DROP_NO_TUNNEL_KEY = -147,
    DROP_UNUSED5 = -148, /* unused */
    DROP_UNUSED6 = -149, /* unused */
    DROP_UNKNOWN_TARGET = -150,
    DROP_UNROUTABLE = -151,
    DROP_UNUSED7 = -152, /* unused */
    DROP_CSUM_L3 = -153,
    DROP_CSUM_L4 = -154,
    DROP_CT_CREATE_FAILED = -155,
    DROP_INVALID_EXTHDR = -156,
    DROP_FRAG_NOSUPPORT = -157,
    DROP_NO_SERVICE = -158,
    DROP_UNSUPP_SERVICE_PROTO = -159,
    DROP_NO_TUNNEL_ENDPOINT = -160,
    DROP_NAT_46X64_DISABLED = -161,
    DROP_EDT_HORIZON = -162,
    DROP_UNKNOWN_CT = -163,
    DROP_HOST_UNREACHABLE = -164,
    DROP_NO_CONFIG = -165,
    DROP_UNSUPPORTED_L2 = -166,
    DROP_NAT_NO_MAPPING = -167,
    DROP_NAT_UNSUPP_PROTO = -168,
    DROP_NO_FIB = -169,
    DROP_ENCAP_PROHIBITED = -170,
    DROP_INVALID_IDENTITY = -171,
    DROP_UNKNOWN_SENDER = -172,
    DROP_NAT_NOT_NEEDED = -173, /* Mapped as drop code, though drop not necessary. */
    DROP_IS_CLUSTER_IP = -174,
    DROP_FRAG_NOT_FOUND = -175,
    DROP_FORBIDDEN_ICMP6 = -176,
    DROP_NOT_IN_SRC_RANGE = -177,
    DROP_PROXY_LOOKUP_FAILED = -178,
    DROP_PROXY_SET_FAILED = -179,
    DROP_PROXY_UNKNOWN_PROTO = -180,
    DROP_POLICY_DENY = -181,
    DROP_VLAN_FILTERED = -182,
    DROP_INVALID_VNI = -183,
    DROP_INVALID_TC_BUFFER = -184,
    DROP_NO_SID = -185,
    DROP_MISSING_SRV6_STATE = -186, /* unused */
    DROP_NAT46 = -187,
    DROP_NAT64 = -188,
    DROP_POLICY_AUTH_REQUIRED = -189,
    DROP_CT_NO_MAP_FOUND = -190,
    DROP_SNAT_NO_MAP_FOUND = -191,
    DROP_INVALID_CLUSTER_ID = -192,
    DROP_DSR_ENCAP_UNSUPP_PROTO = -193,
    DROP_NO_EGRESS_GATEWAY = -194,
    DROP_UNENCRYPTED_TRAFFIC = -195,
    DROP_TTL_EXCEEDED = -196,
    DROP_NO_NODE_ID = -197,
    DROP_RATE_LIMITED = -198,
    DROP_IGMP_HANDLED = -199,
    DROP_IGMP_SUBSCRIBED = -200,
    DROP_MULTICAST_HANDLED = -201,
    DROP_HOST_NOT_READY = -202,
    DROP_EP_NOT_READY = -203,
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

pub fn send_trace_notify<C: EbpfContext>(
    ctx: &C,
    obs_point: TracePoint,
    src: u32,
    dst: u32,
    dst_id: u16,
    ifindex: u32,
    reason: TraceReason,
    monitor: u32,
) {
	let ctx_len =  15u64; //ctx len
	let cap_len = u64::min( if monitor > 0 {
		monitor as u64
	} else{
		TRACE_PAYLOAD_LEN
	}, ctx_len);

	update_trace_metrics(ctx_len, obs_point, reason as u8);

	// 如果不需要trace就结束了
	if !emit_trace_notify(obs_point, monitor){
		return ;
	}

	let msg = TraceNotify{
		r#type: CILIUM_NOTIFY_TRACE,
		subtype: obs_point,
		source: Event_source,
		hash: get_hash_recalc,
		src_label: src,
		dst_label: dst,
		dst_id,
		reason: reason as u8,
		ifindex,
	};
}
