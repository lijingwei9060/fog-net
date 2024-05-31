//#[cfg(target_arch = "bpf")]
pub mod map {
    use aya_ebpf::{macros::map, maps::PerfEventArray};

    use crate::trace::TraceNotify;

    pub const EVENTS_MAP_CNT: u32 = 1000;
    #[map]
    pub static mut TRACE_EVENTS_MAP: PerfEventArray<TraceNotify> =
        PerfEventArray::<TraceNotify>::with_max_entries(EVENTS_MAP_CNT, 0); 
}
