/// LeMerk is a custom Merkle Tree implemention.
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
struct LeMerkLevel<const LEVEL_LENGTH: usize>([CipherBlock;LEVEL_LENGTH]);

// Memory layout for a LeMerk Tree.
struct LeMerkTree<const NODES_LENGTH: usize> {
    // Level's length of the Merkle Tree.
    depth_length: usize,
    // Cipher block size in bytes.
    block_size: usize,
    // Maximum possible Index
    max_index: Index,
    // A flatten representation of the whole tree.
    flat_hash_tree: LeMerkLevel<NODES_LENGTH>,
}

struct Node {
    data_hash: CipherBlock,
    index: Index,
    ancestor: Index,
    binary_successors: (Index, Index),
}