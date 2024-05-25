use super::CTDir;

/// Cilium metrics direction for dropping/forwarding packet
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[allow(non_camel_case_types)]
pub enum MetricDir {
    METRIC_INGRESS = 0,
    METRIC_EGRESS,
    METRIC_SERVICE,
}

#[inline(always)]
pub fn ct_to_metrics_dir(ct_dir: CTDir) -> MetricDir {
    match ct_dir {
        CTDir::CT_EGRESS => MetricDir::METRIC_EGRESS,
        CTDir::CT_INGRESS => MetricDir::METRIC_INGRESS,
        CTDir::CT_SERVICE => MetricDir::METRIC_SERVICE,
    }
}
#[repr(C)]
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct MetricKey {
    pub reason: u8,        /* 0: forwarded, >0 dropped */
    pub dir: MetricDir,    /* 1: ingress 2: egress */
    pub reserved: [u8; 6], /* reserved for future extension */
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct MetricValue {
    pub count: u64,
    pub bytes: u64,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for MetricKey {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for MetricValue {}

//#[cfg(target_arch = "bpf")]
pub mod map {
    use aya_ebpf::macros::map;
    use aya_ebpf::maps::PerCpuHashMap;

    use crate::trace::{is_trace_reason, Reason, TracePoint, TraceReason};

    use super::{MetricDir, MetricKey, MetricValue};
    pub const METRICS_MAP_SIZE: u32 = 65536;

    #[map]
    pub static mut METRICS_MAP: PerCpuHashMap<MetricKey, MetricValue> =
        PerCpuHashMap::<MetricKey, MetricValue>::with_max_entries(METRICS_MAP_SIZE, 0);

    #[inline(always)]
    pub fn update_trace_metrics(len: u64, obs_point: TracePoint, reason: u8) {
        match obs_point {
            TracePoint::TRACE_TO_LXC => {
                update_metrics(len, MetricDir::METRIC_INGRESS, Reason::REASON_FORWARDED);
            }
            TracePoint::TRACE_TO_HOST
            | TracePoint::TRACE_TO_STACK
            | TracePoint::TRACE_TO_OVERLAY
            | TracePoint::TRACE_TO_NETWORK => {
                update_metrics(len, MetricDir::METRIC_EGRESS, Reason::REASON_FORWARDED);
            }
            TracePoint::TRACE_FROM_HOST
            | TracePoint::TRACE_FROM_STACK
            | TracePoint::TRACE_FROM_OVERLAY
            | TracePoint::TRACE_FROM_NETWORK => {
                if is_trace_reason(reason, TraceReason::TRACE_REASON_ENCRYPTED) {
                    update_metrics(len, MetricDir::METRIC_INGRESS, Reason::REASON_DECRYPT);
                } else {
                    update_metrics(len, MetricDir::METRIC_INGRESS, Reason::REASON_PLAINTEXT);
                }
            }
            _ => {
                /* TRACE_FROM_LXC, i.e endpoint-to-endpoint delivery is handled
                 * separately in ipv*_local_delivery() where we can bump an egress
                 * forward. It could still be dropped but it would show up later as an
                 * ingress drop, in that scenario.
                 *
                 * TRACE_{FROM,TO}_PROXY are not handled in datapath. This is because
                 * we have separate L7 proxy "forwarded" and "dropped" (ingress/egress)
                 * counters in the proxy layer to capture these metrics.
                 */
            }
        }
    }

    /* update_metrics
     * @direction:	1: Ingress 2: Egress
     * @reason:	reason for forwarding or dropping packet.
     *		reason is 0 if packet is being forwarded, else reason
     *		is the drop error code.
     * Update the metrics map.
     */
    fn update_metrics(bytes: u64, dir: MetricDir, reason: Reason) {
        let key = MetricKey {
            reason: reason as u8,
            dir,
            reserved: [0, 0, 0, 0, 0, 0],
        };

        unsafe {
            match METRICS_MAP.get_ptr_mut(&key) {
                Some(p) => {
                    (*p).bytes += bytes;
                    (*p).count += 1;
                }
                None => {
                    let v = MetricValue { count: 1, bytes };
                    let _ = METRICS_MAP.insert(&key, &v, 0);
                }
            }
        }
    }
}

