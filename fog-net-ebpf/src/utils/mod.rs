pub mod xdp;
pub mod tc;

// Converts a checksum into u16
#[inline(always)]
pub fn csum_fold_helper(mut csum: u64) -> u16 {
    for _i in 0..4 {
        if (csum >> 16) > 0 {
            csum = (csum & 0xffff) + (csum >> 16);
        }
    }
    !(csum as u16)
}