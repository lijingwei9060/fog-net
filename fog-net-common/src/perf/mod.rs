
#[repr(C)]
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq, Default)]
pub struct DataRec{
  pub rx_packets: u64,
  pub rx_bytes: u64,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for DataRec {}


// #[map]
// pub static mut XDP_STAT_MAP: PerCpuArray<DataRec> = PerCpuArray::<DataRec>::with_max_entries(XDP_REDIRECT + 1, 0);

// #[allow(dead_code)]
// pub fn  xdp_stats_record_action(ctx: &XdpContext, action: aya_ebpf::bindings::xdp_action::Type) {
//     unsafe {
//         let action = action % (XDP_REDIRECT + 1);
//         let map = XDP_STAT_MAP.get_ptr_mut(action).unwrap();
        
//         (*map).rx_packets += 1;
//         (*map).rx_bytes += (ctx.data_end() - ctx.data() )as u64;
//     }
// }

#[repr(C, align(4))]
#[derive(Debug, Clone, Copy)]
pub struct MetaInfo{
  pub mark: u32,
}

impl MetaInfo{
  pub fn new(mark: u32)-> Self{
    MetaInfo{
      mark,
    }
  }

  pub fn set_traing(&mut self, v: bool){
    if v{
      self.mark |= 1 << 31;
    }else{
      self.mark &= !(1 << 31);
    }
  }
}

