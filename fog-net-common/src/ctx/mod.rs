use core::mem::{self, size_of};

use aya_ebpf::{
    bindings::{bpf_func_id::BPF_FUNC_perf_event_output, BPF_F_CURRENT_CPU},
    helpers::bpf_perf_event_output,
    programs::{TcContext, XdpContext},
    EbpfContext,
};
use networktype::{
    eth::EthHdr,
    ip::{IpHdr, Ipv4Hdr, Ipv6Hdr},
    EtherType,
};

use crate::{event::map::TRACE_EVENTS_MAP, queue::edt_set_aggregate, trace::TraceNotify};

pub mod skb;
pub mod xdp;

/// Swaps destination and source MAC addresses inside an Ethernet header
pub fn swap_src_dst_mac(hdr: &mut EthHdr) -> Result<(), ()> {
    let swp = (hdr.dst_addr, hdr.src_addr);
    hdr.dst_addr = swp.1;
    hdr.src_addr = swp.0;
    Ok(())
}

/// Swaps destination and source IP addresses inside an IP header
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

// Updates the TCP connection's state based on the current phase and the incoming packet's header.
// It returns true if the state transitioned to a different phase.
// Ref: https://en.wikipedia.org/wiki/File:Tcp_state_diagram.png and
// http://www.tcpipguide.com/free/t_TCPConnectionTermination-2.htm
// #[inline(always)]
// pub fn process_tcp_state_transition(hdr: &TcpHdr, state: &mut TCPState) -> bool {
//     let fin = hdr.fin() == 1;
//     let ack = hdr.ack() == 1;
//     match state {
//         TCPState::Established => {
//             // At the Established state, a FIN packet moves the state to FinWait1.
//             if fin {
//                 *state = TCPState::FinWait1;
//                 return true;
//             }
//         }
//         TCPState::FinWait1 => {
//             // At the FinWait1 state, a packet with both the FIN and ACK bits set
//             // moves the state to TimeWait.
//             if fin && ack {
//                 *state = TCPState::TimeWait;
//                 return true;
//             }
//             // At the FinWait1 state, a FIN packet moves the state to Closing.
//             if fin {
//                 *state = TCPState::Closing;
//                 return true;
//             }
//             // At the FinWait1 state, an ACK packet moves the state to FinWait2.
//             if ack {
//                 *state = TCPState::FinWait2;
//                 return true;
//             }
//         }
//         TCPState::FinWait2 => {
//             // At the FinWait2 state, an ACK packet moves the state to TimeWait.
//             if ack {
//                 *state = TCPState::TimeWait;
//                 return true;
//             }
//         }
//         TCPState::Closing => {
//             // At the Closing state, an ACK packet moves the state to TimeWait.
//             if ack {
//                 *state = TCPState::TimeWait;
//                 return true;
//             }
//         }
//         TCPState::TimeWait => {
//             if ack {
//                 *state = TCPState::Closed;
//                 return true;
//             }
//         }
//         TCPState::Closed => {}
//     }
//     false
// }

// Modifies the map tracking TCP connections based on the current state
// of the TCP connection and the incoming TCP packet's header.
// #[inline(always)]
// pub fn update_tcp_conns(
//     hdr: &TcpHdr,
//     client_key: &ClientKey,
//     lb_mapping: &mut LoadBalancerMapping,
// ) -> Result<(), i64> {
//     if let Some(ref mut tcp_state) = lb_mapping.tcp_state {
//         let transitioned = process_tcp_state_transition(hdr, tcp_state);
//         if let TCPState::Closed = tcp_state {
//             unsafe {
//                 return LB_CONNECTIONS.remove(client_key);
//             }
//         }
//         // If the connection has not reached the Closed state yet, but it did transition to a new state,
//         // then record the new state.
//         if transitioned {
//             unsafe {
//                 return LB_CONNECTIONS.insert(client_key, lb_mapping, 0_u64);
//             }
//         }
//     }
//     Ok(())
// }

pub enum Context {
    Xdp(XdpContext),
    Skb(TcContext),
}

impl EbpfContext for Context {
    fn as_ptr(&self) -> *mut core::ffi::c_void {
        match self {
            Context::Xdp(a) => a.as_ptr(),
            Context::Skb(a) => a.as_ptr(),
        }
    }
}

impl Context {
    #[inline(always)]
    pub fn ptr_at<T>(&self, offset: usize) -> Option<*const T> {
        let (start, end) = match self {
            Context::Xdp(x) => (x.data(), x.data()),
            Context::Skb(s) => (s.data(), s.data()),
        };

        ptr_at(start, end, offset)
    }

    #[inline(always)]
    pub fn ptr_at_mut<T>(&self, offset: usize) -> Option<*mut T> {
        let (start, end) = match self {
            Context::Xdp(x) => (x.data(), x.data()),
            Context::Skb(s) => (s.data(), s.data()),
        };
        ptr_at_mut(start, end, offset)
    }

    #[inline(always)]
    pub fn parse_l2_header(&self) -> Option<EtherType> {
        self.ptr_at::<EthHdr>(0).map(|e| unsafe { (*e).ether_type })
    }

    #[inline(always)]
    pub fn parse_ipv4_header(&self) -> Option<&Ipv4Hdr> {
        let ether_type = self.parse_l2_header()?;
        match ether_type {
            EtherType::Ipv4 => self
                .ptr_at::<Ipv4Hdr>(EthHdr::LEN)
                .map(|e| unsafe { &(*e) }),
            _ => None,
        }
    }

    #[inline(always)]
    pub fn parse_ipv6_header(&self) -> Option<&Ipv6Hdr> {
        let ether_type = self.parse_l2_header()?;
        match ether_type {
            EtherType::Ipv6 => self
                .ptr_at::<Ipv6Hdr>(EthHdr::LEN)
                .map(|e| unsafe { &(*e) }),
            _ => None,
        }
    }

    /// get metadata
    #[inline(always)]
    pub fn ctx_load_meta(&self, offset: usize) -> u32 {
        match self {
            Context::Xdp(x) => xdp::ctx_load_meta(x, offset),
            Context::Skb(s) => skb::ctx_load_meta(s, offset),
        }
    }

    #[inline(always)]
    pub fn ctx_store_meta(&self, offset: usize, datum: u32) {
        match self {
            Context::Xdp(x) => xdp::ctx_store_meta(x, offset, datum),
            Context::Skb(s) => skb::ctx_store_meta(s, offset, datum),
        }
    }

    #[inline(always)]
    pub fn ctx_full_len(&self) -> u64 {
        match self {
            Context::Xdp(x) => xdp::ctx_full_len(x),
            Context::Skb(s) => skb::ctx_full_len(s),
        }
    }

    /// output trace event
    #[inline(always)]
    pub fn ctx_trace_event_output(&self, cap_len: u32, data: &TraceNotify) {
        unsafe {
            TRACE_EVENTS_MAP.output_at_index(self, BPF_F_CURRENT_CPU as u32, data, cap_len);
        }
    }

    pub fn get_hash_recalc(&self) -> u32 {
        match self {
            Context::Xdp(_) => 0,
            Context::Skb(s) => unsafe { (*s.skb.skb).hash },
        }
    }

    #[inline(always)]
    pub fn bpf_clear_meta(&mut self) {
        match self {
            Context::Xdp(x) => xdp::bpf_clear_meta(x),
            Context::Skb(s) => skb::bpf_clear_meta(s),
        }
    }

    /// workaround for GH-18311
    #[inline(always)]
    pub fn reset_queue_mapping(&self) {
        /* Workaround for GH-18311 where veth driver might have recorded
         * veth's RX queue mapping instead of leaving it at 0. This can
         * cause issues on the phys device where all traffic would only
         * hit a single TX queue (given veth device had a single one and
         * mapping was left at 1). Reset so that stack picks a fresh queue.
         * Kernel fix is at 710ad98c363a ("veth: Do not record rx queue
         * hint in veth_xmit").
         */
        match self {
            Context::Xdp(_) => {}
            Context::Skb(s) => unsafe { *s.skb.skb }.queue_mapping = 0,
        }
    }

    pub fn edt_set_aggregate(&self, aggregate: u32) {
        match self {
            Context::Xdp(_) => {}
            Context::Skb(s) => edt_set_aggregate(s, aggregate),
        }
    }
}

#[inline(always)]
fn ptr_at<T>(start: usize, end: usize, offset: usize) -> Option<*const T> {
    let len = mem::size_of::<T>();
    if start + offset + len > end {
        return None;
    }
    Some((start + offset) as *const T)
}

#[inline(always)]
fn ptr_at_mut<T>(start: usize, end: usize, offset: usize) -> Option<*mut T> {
    let ptr = ptr_at::<T>(start, end, offset)?;
    Some(ptr as *mut T)
}
