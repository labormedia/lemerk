use sha3;
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

pub struct LeMerkBuilder<const BLOCK_SIZE: usize>{
    // Level's length of the Merkle Tree.
    max_depth: usize,
    // An initial block data to instantiate the merkle tree.
    initial_block: [u8; BLOCK_SIZE],
}

impl<const BLOCK_SIZE: usize> Default for LeMerkBuilder<BLOCK_SIZE> {
    fn default() -> Self {
        LeMerkBuilder {
            max_depth: 1,
            initial_block: [0_u8;BLOCK_SIZE],
        }
    }
}

impl<const BLOCK_SIZE: usize> LeMerkBuilder<BLOCK_SIZE> {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn with_max_depth(mut self, max_depth: usize) -> Self {
        self.max_depth = max_depth;
        self
    }
    pub fn with_depth_length(mut self, depth_length: usize) -> Self {
        if depth_length > 0 {
            self.max_depth = depth_length - 1;
        } else {
            self.max_depth = 0;
        };
        self
    }
    pub fn with_initial_block(mut self, initial_block: [u8;BLOCK_SIZE]) -> Self {
        self.initial_block = initial_block;
        self
    }
    pub fn try_build<D: sha3::Digest>(&self) -> Result<LeMerkTree<BLOCK_SIZE>, LeMerkBuilderError>{
        let max_depth = self.max_depth;
        let hash_tree_data_length: Index = Index::try_from(DepthOffset::from((max_depth+1,0)))?;
        let max_index: Index = Index::from(hash_tree_data_length.get_index() - 1);
        let mut hash_tree_data: Vec<[u8; BLOCK_SIZE]> = vec![[0_u8;BLOCK_SIZE]; hash_tree_data_length.get_index() ];
        let mut depth_index = max_depth + 1;
        let mut allocating_block_buffer = self.initial_block; 
        let mut initial_index = 0;
        while depth_index > 0 {
            depth_index -= 1;
            let allocation_size = 2_usize.checked_pow(depth_index as u32).ok_or(LeMerkBuilderError::BadPow)?;
            let allocating_block = allocating_block_buffer.clone();
            let _: Vec<_> = (0..allocation_size)
                .map(|i| { 
                    hash_tree_data[i + initial_index]= allocating_block;
                })
                .collect();
            initial_index += allocation_size;
            hash_visit::<D>(&allocating_block, &allocating_block, &mut allocating_block_buffer);
        };
        let flat_hash_tree: LeMerkLevel<BLOCK_SIZE> = LeMerkLevel::from(hash_tree_data);
        Ok(
            LeMerkTree {
                max_depth,
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
        .with_max_depth(3)
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
        .with_max_depth(0)
        .with_initial_block([0_u8;SIZE])
        .try_build::<sha3::Sha3_256>()
        .expect("Unexpected build.");
    assert_eq!(
        tree,
        LeMerkTree::<SIZE> {
            max_depth: 0,
            max_index: Index::from(0),
            flat_hash_tree: LeMerkLevel::<SIZE>::from([[0_u8;SIZE]].to_vec()),
        }
    );
}

#[test]
fn build_initial_value_merkletree() {
    const SIZE: usize = 32;
    let mut builder: LeMerkBuilder<SIZE> = LeMerkBuilder::<SIZE>::new();
    let tree: LeMerkTree<SIZE> = builder
        .with_max_depth(1)
        .with_initial_block(hex!("abababababababababababababababababababababababababababababababab"))
        .try_build::<sha3::Sha3_256>()
        .expect("Unexpected build.");
    assert_eq!(
        tree,
        LeMerkTree::<SIZE> {
            max_depth: 1,
            max_index: Index::from(2),
            flat_hash_tree: LeMerkLevel::<SIZE>::from(
                [
                    [171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171], 
                    [171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171], 
                    [105, 159, 201, 79, 241, 236, 131, 241, 171, 245, 49, 3, 14, 50, 64, 3, 231, 117, 130, 152, 40, 22, 69, 36, 95, 124, 105, 132, 37, 165, 224, 231]]
                .to_vec()
            ),
        }
    );
    assert_eq!(
        tree.get_root().unwrap(),
        [105, 159, 201, 79, 241, 236, 131, 241, 171, 245, 49, 3, 14, 50, 64, 3, 231, 117, 130, 152, 40, 22, 69, 36, 95, 124, 105, 132, 37, 165, 224, 231],
    );
}

#[test]
fn build_merkletree_depth_20() {
    const SIZE: usize = 32;
    let mut builder: LeMerkBuilder<SIZE> = LeMerkBuilder::<SIZE>::new();
    let tree: LeMerkTree<SIZE> = builder
        .with_depth_length(20)
        .with_initial_block(hex!("abababababababababababababababababababababababababababababababab"))
        .try_build::<sha3::Sha3_256>()
        .expect("Unexpected build.");
    assert_eq!(
        tree.get_root().unwrap(),
        hex!("d4490f4d374ca8a44685fe9471c5b8dbe58cdffd13d30d9aba15dd29efb92930"), 
    );
}