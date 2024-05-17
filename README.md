# fog-net

## Prerequisites

1. Install bpf-linker: `cargo install bpf-linker`

## Build eBPF

```bash
cargo xtask build-ebpf
```

To perform a release build you can use the `--release` flag.
You may also change the target architecture with the `--target` flag.

## Build Userspace

```bash
cargo build
```

## Run

```bash
RUST_LOG=info cargo xtask run
```

## demo

```shell
sudo ip link add vpc-25932F01 type veth peer name vpc-25932F01-1
sudo ifconfig vpc-25932F01 hw ether fe:00:25:93:2F:01 up
sudo ifconfig vpc-25932F01-1 hw ether d0:00:25:93:2F:01 up

sudo tcpdump -e -ni vpc-25932F01-1 -vvv
```