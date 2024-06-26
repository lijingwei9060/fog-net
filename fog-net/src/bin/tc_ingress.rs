use aya::{include_bytes_aligned, programs::{tc, SchedClassifier, TcAttachType}, Ebpf};
use aya_log::EbpfLogger;
use log::{info, warn};
use tokio::signal;



#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
  env_logger::init();

  // This will include your eBPF object file as raw bytes at compile-time and load it at
  // runtime. This approach is recommended for most real-world use cases. If you would
  // like to specify the eBPF program at runtime rather than at compile-time, you can
  // reach for `Bpf::load_file` instead.
  #[cfg(debug_assertions)]
  let mut bpf = Ebpf::load(include_bytes_aligned!(
      "../../../target/bpfel-unknown-none/debug/arp_ingress"
  ))?;
  #[cfg(not(debug_assertions))]
  let mut bpf = Ebpf::load(include_bytes_aligned!(
      "../../../target/bpfel-unknown-none/debug/arp_ingress"
  ))?;
  if let Err(e) = EbpfLogger::init(&mut bpf) {
      // This can happen if you remove all log statements from your eBPF program.
      warn!("failed to initialize eBPF logger: {}", e);
  }
  // error adding clsact to the interface if it is already added is harmless
  // the full cleanup can be done with 'sudo tc qdisc del dev eth0 clsact'.
  let _ = tc::qdisc_add_clsact("vpc-25932F01-1");
  let program: &mut SchedClassifier =
      bpf.program_mut("tc_ingress").unwrap().try_into()?;
  program.load()?;
  program.attach("vpc-25932F01-1", TcAttachType::Ingress)?;



  info!("Waiting for Ctrl-C...");
  signal::ctrl_c().await?;
  info!("Exiting...");

  Ok(())   
}