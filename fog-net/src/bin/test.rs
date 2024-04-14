

fn main(){
  let i = 0xb8ba;
  println!("{:x}", csum(i, u32::from_be_bytes([127,0,0,1])));
  println!("{:x}", csum(i, u32::from_be_bytes([127,0,0,1])));
}


fn csum(csum: u16, addend: u32) -> u16 {
  let mut csum = ! csum;
  let mut csum = csum as u32;
  csum += addend;
  csum = (csum >> 16) + (csum & 0xffff);
  csum += csum >> 16;
  csum as u16
}