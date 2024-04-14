use aya_ebpf::programs::XdpContext;
use networktype::{eth::EthHdr, ip::IpHdr};


/// Pops the outermost VLAN tag off the packet. Returns the popped VLAN ID on
/// success or negative errno on failure.
pub fn vlan_tag_pop(ctx: &mut XdpContext) -> Result<(),()>{
  Ok(())
}

/// Pushes a new VLAN tag after the Ethernet header. Returns 0 on success,
/// -1 on failure.
pub fn vlan_tag_push(ctx: &mut XdpContext) -> Result<(),()>{
  Ok(())
}




/// Swaps destination and source MAC addresses inside an Ethernet header
pub fn swap_src_dst_mac(hdr: &mut EthHdr) -> Result<(),()>{
  Ok(())
}

/// Swaps destination and source IP addresses inside an IP header
pub fn swap_src_dst_ip(hdr: &mut IpHdr) -> Result<(),()>{
  Ok(())
}

