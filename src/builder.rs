use hex_literal::hex;
use crate::{
    LeMerkLevel,
    crypto::{
        data_hash,
        hash_visit
    },
    data::{
        Index,
        IndexError,
        DepthOffset,
    },
};

struct LeMerkBuilder<const BLOCK_SIZE: usize>{
    // Level's length of the Merkle Tree.
    depth_length: usize,
    // An initial block data to instantiate the merkle tree.
    initial_block: [u8; BLOCK_SIZE],
}

enum LeMerkBuilderError {
    Overflow,
}

impl From<IndexError> for LeMerkBuilderError {
    fn from(value: IndexError) -> LeMerkBuilderError {
        match value {
            IndexError::IndexOverflow => LeMerkBuilderError::Overflow,
            _ => panic!("Unexpected error"),
        }
    }
}

impl<const BLOCK_SIZE: usize> Default for LeMerkBuilder<BLOCK_SIZE> {
    fn default() -> Self {
        LeMerkBuilder {
            depth_length: 1,
            initial_block: [0_u8;BLOCK_SIZE],
        }
    }
}

impl<const BLOCK_SIZE: usize> LeMerkBuilder<BLOCK_SIZE> {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn with_depth_length(&mut self, depth_length: usize) {
        self.depth_length = depth_length;
    }
    pub fn with_initial_block(&mut self, initial_block: [u8;BLOCK_SIZE]) {
        self.initial_block = initial_block;
    }
    pub fn try_build(&self) -> Result<(), LeMerkBuilderError>{
        let depth_length = self.depth_length;
        let max_index: Index = DepthOffset::new(depth_length+1,0).try_into()?;
        let flat_tree: Vec<Index> = Vec::with_capacity(max_index.get_index());
        let flat_hash_tree: Vec<[u8; BLOCK_SIZE]> = flat_tree.iter().map(|_| { self.initial_block.clone() }).collect();
        Ok(())
    }
}

#[test]
fn hex_representation() {
    let hex: [u8;32] = hex!("abababababababababababababababababababababababababababababababab");
    assert_eq!(hex, [171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171])
}