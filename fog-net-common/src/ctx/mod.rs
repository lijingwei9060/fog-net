use networktype::{eth::EthHdr, ip::IpHdr};

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
