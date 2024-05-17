use aya_ebpf::programs::TcContext;

/// get metadata
pub fn ctx_load_meta(ctx: &TcContext, offset: u32) -> u32{
  let offset = offset as usize % unsafe { (*ctx.skb.skb).cb}.len();
  // 第n个元素
  unsafe { (*ctx.skb.skb).cb[offset]}
}