use anyhow::Context;
use aya::{
    include_bytes_aligned,
    maps::HashMap,
    programs::{Xdp, XdpFlags},
    Ebpf,
};
use aya_log::EbpfLogger;
use clap::Parser;
use fog_net::{get_map_mac_nic, MAC_NIC, MAP_PATH};
use fog_net_common::map::endpoint::NIC;
use log::{debug, info, warn};
use std::{net::{Ipv4Addr, Ipv6Addr}, path::Path};
use tokio::signal;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "eth0")]
    iface: String,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::parse();

    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {}", ret);
    }

    let path_mac_nic = Path::new(MAP_PATH).join(MAC_NIC);

    if path_mac_nic.exists() {
        let mut map_mac_nic = get_map_mac_nic()?;
        info!("Waiting for Ctrl-C...");
        signal::ctrl_c().await?;
        info!("Exiting...");
    } else {
        // This will include your eBPF object file as raw bytes at compile-time and load it at
        // runtime. This approach is recommended for most real-world use cases. If you would
        // like to specify the eBPF program at runtime rather than at compile-time, you can
        // reach for `Bpf::load_file` instead.

        #[cfg(debug_assertions)]
        let mut bpf = Ebpf::load(include_bytes_aligned!(
            "../../../target/bpfel-unknown-none/debug/arp_xdp"
        ))?;
        #[cfg(not(debug_assertions))]
        let mut bpf = Ebpf::load(include_bytes_aligned!(
            "../../../target/bpfel-unknown-none/release/arp_xdp"
        ))?;
        if let Err(e) = EbpfLogger::init(&mut bpf) {
            // This can happen if you remove all log statements from your eBPF program.
            warn!("failed to initialize eBPF logger: {}", e);
        }
        let program: &mut Xdp = bpf.program_mut("fog_net").unwrap().try_into()?;
        program.load()?;
        program.attach(&opt.iface, XdpFlags::SKB_MODE)
        .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;
        let mut map_mac_nic: HashMap<_, [u8; 4], NIC> =
            HashMap::try_from(bpf.map_mut("LOCAL_ARP_ENDPOINT").unwrap())?;

        let nic = NIC {
            mac: [0, 0, 0, 0, 0, 0],
            ifindex: 8,
            vlan_id: 0,
            eni_id: 0,
            ipv4: Ipv4Addr::new(0, 0, 0, 0),
            flags: 0,
            node_mac: [0, 0, 0, 0, 0, 0],
            vm_id: 10086,
            ipv6: Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1),
            ipv4_mask: 20,
            ipv6_mask: 0,
            subnet_id: 10000,
            vpc_id: 10086,
            is_bare_metal: 0,
            bm_vlan_id: 0,
        };
        map_mac_nic.insert([0, 0, 0, 0], nic, 0)?;

        info!("Waiting for Ctrl-C...");
        signal::ctrl_c().await?;
        info!("Exiting...");
    }

    Ok(())
}
