/// LeMerk is a custom Merkle Tree implemention.
use core::iter::Iterator;
// Crypto helpers.
mod crypto;
// LeMerk tree builder pattern.
pub mod builder;
// Tree data elements
mod data;
use data::{
    CipherBlock,
    Index,
};

// Memory layout for a single layer of blocks. This is used for the expansion of the levels in the builder 
// and the final flatten expansion of the whole tree, in a single layer indexed by the struct implementation.
struct LeMerkLevel(Vec<CipherBlock>);

// Memory layout for a LeMerk Tree.
struct LeMerkTree {
    // Level's length of the Merkle Tree.
    depth_length: usize,
    // Cipher block size in bytes.
    block_size: usize,
    // Maximum possible Index
    max_index: Index,
    // A flatten representation of the whole tree.
    flat_hash_tree: LeMerkLevel,
}

struct Node {
    data_hash: CipherBlock,
    index: Index,
    ancestor: Option<Index>,
}

impl Default for Node {
    fn default() -> Self {
        Node {
            data_hash: [0_u8;32],
            index: Index::from(0_usize),
            ancestor: None,
        }
    }
}

impl Iterator for Node {
    type Item = Node;
    fn next(&mut self) -> Option<Self::Item> {
        Some(Node::default())
    }
}