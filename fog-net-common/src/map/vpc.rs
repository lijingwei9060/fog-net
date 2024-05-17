use aya_ebpf::{ macros::map, maps::HashMap};

/// VPC
#[repr(C)]
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub struct VPC {
    pub vpc_id: u32,
    pub dhcp_option_id: u32,
    pub route_table_id: u32,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for VPC{}





pub const VPC_CNT: u32 = 65535;

#[cfg_attr(target_arch = "bpf", map)]
pub static mut VPC_MAP: HashMap<u32, VPC> = HashMap::<u32, VPC>::with_max_entries(VPC_CNT,0);


/// get vpc by id
#[inline(always)]  
pub fn get_vpc(id: u32) -> Option<VPC>{
  unsafe { VPC_MAP.get(&id).copied() }
}