use aya_ebpf::{helpers::bpf_xdp_adjust_head, programs::XdpContext, EbpfContext};
use networktype::{
    eth::EthHdr,
    ip::IpHdr,
    vlan::{self, VlanHdr},
    EtherType,
};

use super::{ptr_at, ptr_at_mut};

/// Pops the outermost VLAN tag off the packet. Returns the popped VLAN ID on
/// success or negative errno on failure.
#[allow(dead_code)]
pub unsafe fn vlan_tag_pop(ctx: &mut XdpContext) -> Result<u16, ()> {
    let eth_hdr = ptr_at::<EthHdr>(ctx, 0);
    if eth_hdr.is_none() {
        return Err(());
    }
    let eth_hdr = eth_hdr.unwrap();
    if !(unsafe { *eth_hdr }).ether_type.is_vlan() {
        return Err(());
    }
    let vlan_hdr = ptr_at::<VlanHdr>(ctx, EthHdr::LEN);
    if vlan_hdr.is_none() {
        return Err(());
    }
    let vlan_hdr = vlan_hdr.unwrap();
    let vid = (unsafe { *vlan_hdr }).vid();
    let proto = (unsafe { *vlan_hdr }).ether_type;
    let eth_copy = unsafe { *eth_hdr };

    /* Actually adjust the head pointer */
    // todo(casoul): for tc?
    if bpf_xdp_adjust_head(ctx.as_ptr() as *mut _, VlanHdr::LEN as i32) != 0 {
        return Err(());
    }

    let eth_hdr = ptr_at_mut::<EthHdr>(ctx, 0);
    if eth_hdr.is_none() {
        return Err(());
    }
    (*eth_hdr.unwrap()).ether_type = proto;
    (*eth_hdr.unwrap()).src_addr = eth_copy.src_addr;
    (*eth_hdr.unwrap()).dst_addr = eth_copy.dst_addr;

    Ok(vid)
}

/// Pushes a new VLAN tag after the Ethernet header. Returns 0 on success,
/// -1 on failure.
#[allow(dead_code)]
pub unsafe fn vlan_tag_push(ctx: &mut XdpContext, vid: u16) -> Result<(), ()> {
    let eth_hdr = ptr_at::<EthHdr>(ctx, 0);
    if eth_hdr.is_none() {
        return Err(());
    }

    let eth_hdr = eth_hdr.unwrap();
    let vlan_proto = match (*eth_hdr).ether_type {
        EtherType::VLAN => EtherType::QinQ,
        _ => EtherType::VLAN,
    };
    let h_proto = (*eth_hdr).ether_type;
    // copy eth header
    let eth_copy = *eth_hdr;

    /* Actually adjust the head pointer */
    // todo(casoul): for tc?
    if bpf_xdp_adjust_head(ctx.as_ptr() as *mut _, 0 - VlanHdr::LEN as i32) != 0 {
        return Err(());
    }

    let eth_hdr = ptr_at_mut::<EthHdr>(ctx, 0);
    if eth_hdr.is_none() {
        return Err(());
    }
    let eth_hdr = eth_hdr.unwrap();
    (*eth_hdr).src_addr = eth_copy.src_addr;
    (*eth_hdr).dst_addr = eth_copy.dst_addr;
    (*eth_hdr).ether_type = vlan_proto;

    let vlan_hdr = ptr_at_mut::<VlanHdr>(ctx, EthHdr::LEN);
    if vlan_hdr.is_none() {
        return Err(());
    }
    let vlan_hdr = vlan_hdr.unwrap();
    (*vlan_hdr).set_vid(vid);
    (*vlan_hdr).ether_type = h_proto;

    Ok(())
}

/// Swaps destination and source MAC addresses inside an Ethernet header
#[allow(dead_code)]
pub fn swap_src_dst_mac(hdr: &mut EthHdr) -> Result<(), ()> {
    let swp = (hdr.dst_addr, hdr.src_addr);
    hdr.dst_addr = swp.1;
    hdr.src_addr = swp.0;
    Ok(())
}

/// Swaps destination and source IP addresses inside an IP header
#[allow(dead_code)]
pub fn swap_src_dst_ip(hdr: &mut IpHdr) -> Result<(), ()> {
    match hdr {
        IpHdr::V4(hdr) => {
            let swp = (hdr.dst_addr, hdr.src_addr);
            hdr.dst_addr = swp.1;
            hdr.src_addr = swp.0;
        }
        IpHdr::V6(hdr) => {
            let swp = (hdr.dst_addr, hdr.src_addr);
            hdr.dst_addr = swp.1;
            hdr.src_addr = swp.0;
        }
    }

    Ok(())
}
