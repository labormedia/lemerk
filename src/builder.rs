use hex_literal::hex;
use crate::{
    LeMerkLevel,
    crypto::{
        data_hash,
        hash_visit
    },
};

struct LeMerkBuilder{
    // Level's length of the Merkle Tree.
    depth_length: usize,
    // Cipher block size in bytes.
    block_size: usize,
}

impl Default for LeMerkBuilder {
    fn default() -> Self {
        LeMerkBuilder {
            depth_length: 1,
            block_size: 32,
        }
    }
}

impl LeMerkBuilder {
    pub fn with_depth_length(&mut self, depth_length: usize) {
        self.depth_length = depth_length;
    }
    pub fn with_block_size(&mut self, block_size: usize) {
        self.block_size = block_size;
    }
}

#[test]
fn hex_representation() {
    let hex: [u8;32] = hex!("abababababababababababababababababababababababababababababababab");
    assert_eq!(hex, [171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171])
}