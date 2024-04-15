use hex_literal::hex;
use crate::{
    LeMerkTree,
    LeMerkLevel,
    crypto::{
        data_hash,
        hash_visit
    },
    data::{
        Index,
        DepthOffset,
    },
    VirtualNode,
    error::LeMerkBuilderError,
};

struct LeMerkBuilder<const BLOCK_SIZE: usize>{
    // Level's length of the Merkle Tree.
    depth_length: usize,
    // An initial block data to instantiate the merkle tree.
    initial_block: [u8; BLOCK_SIZE],
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
    pub fn with_depth_length(mut self, depth_length: usize) -> Self {
        self.depth_length = depth_length;
        self
    }
    pub fn with_initial_block(mut self, initial_block: [u8;BLOCK_SIZE]) -> Self {
        self.initial_block = initial_block;
        self
    }
    pub fn try_build(&self) -> Result<LeMerkTree<BLOCK_SIZE>, LeMerkBuilderError>{
        let depth_length = self.depth_length;
        let max_index: Index = DepthOffset::new(depth_length+1,0).try_into()?;
        let flat_hash_tree: LeMerkLevel<BLOCK_SIZE> = LeMerkLevel::from((0..max_index.get_index()).map(|_| { self.initial_block }).collect());
        Ok(
            LeMerkTree {
                depth_length,
                max_index,
                flat_hash_tree,
            }
        )
    }
}

#[test]
fn hex_representation() {
    let hex: [u8;32] = hex!("abababababababababababababababababababababababababababababababab");
    assert_eq!(hex, [171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171])
}

#[test]
fn builder_initial_block() {
    const SIZE: usize = 32;
    let mut builder: LeMerkBuilder<SIZE> = LeMerkBuilder::<SIZE>::new();
    let tree: LeMerkBuilder<SIZE> = builder
        .with_depth_length(3)
        .with_initial_block([1_u8;SIZE]);
    assert_eq!(
        tree.initial_block,
        [1_u8;SIZE]
    );
}

#[test]
fn build_zero_merkletree() {
    const SIZE: usize = 32;
    let mut builder: LeMerkBuilder<SIZE> = LeMerkBuilder::<SIZE>::new();
    let tree: LeMerkTree<SIZE> = builder
        .with_depth_length(0)
        .with_initial_block([0_u8;SIZE])
        .try_build()
        .expect("Unexpected build.");
    assert_eq!(
        tree,
        LeMerkTree::<SIZE> {
            depth_length: 0,
            max_index: Index::from(1),
            flat_hash_tree: LeMerkLevel::<SIZE>::from([[0_u8;SIZE]].to_vec()),
        }
    );
}