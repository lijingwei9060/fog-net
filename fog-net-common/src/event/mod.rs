//#[cfg(target_arch = "bpf")]
pub mod map {
  use aya_ebpf::{macros::map, maps::PerfEventArray};

  pub const EVENTS_MAP_CNT:u32 = 1000;
  #[map]
    pub static mut EVENTS_MAP: PerfEventArray::<u32> = PerfEventArray::<u32>::with_max_entries(EVENTS_MAP_CNT, 0);
}