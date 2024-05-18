use aya_ebpf::programs::TcContext;

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
