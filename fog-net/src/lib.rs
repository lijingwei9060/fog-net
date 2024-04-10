use std::path::Path;

use aya::maps::{HashMap, Map, MapData, MapError};
use fog_net_common::endpoint::NetworkInterface;

pub const MAP_PATH: &str = "/sys/fs/bpf/";
pub const MAC_NIC: &str = "map_mac_nic";

pub fn get_map_mac_nic() -> Result<aya::maps::HashMap<MapData, [u8; 6], NetworkInterface>, MapError>{
   let bpf_map = Path::new(MAP_PATH); 
   HashMap::try_from(Map::HashMap(MapData::from_pin(bpf_map.join(MAC_NIC))?))
}

