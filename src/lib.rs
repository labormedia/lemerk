/// LeMerk is a custom Merkle Tree implemention.
use sha3;
use hex_literal::hex;
use core::iter::Iterator;
// Crypto helpers.
mod crypto;
use crypto::hash_visit;
// LeMerk tree builder pattern.
pub mod builder;
// Tree data elements
mod data;
use data::{
    CipherBlock,
    Index,
    DepthOffset,
};
pub mod error;
use error::*;
mod traits;
use traits::SizedTree;

// Memory layout for a single layer of blocks. This is used for the expansion of the levels in the builder 
// and the final flatten expansion of the whole tree, in a single layer indexed by the struct implementation.
#[derive(PartialEq, Debug, Clone)]
struct LeMerkLevel<const CIPHER_BLOCK_SIZE: usize>(Vec<[u8; CIPHER_BLOCK_SIZE]>);

impl<const CIPHER_BLOCK_SIZE: usize> LeMerkLevel<CIPHER_BLOCK_SIZE> {
    fn get_cipher_block_mut_ref(&mut self, value: Index) -> Result<&mut [u8; CIPHER_BLOCK_SIZE], LeMerkLevelError>{
        let index_usize = value.get_index();
        if index_usize < self.0.len() {
            Ok(&mut self.0[index_usize])
        } else {
            Err(LeMerkLevelError::Overflow)
        }
    }
    fn get_cipher_block(&self, index: Index) -> Result<[u8; CIPHER_BLOCK_SIZE], LeMerkLevelError>{
        let index_usize = index.get_index();
        if index_usize < self.0.len() {
            Ok(self.0[index_usize])
        } else {
            Err(LeMerkLevelError::Overflow)
        }
    }
    fn from(vector: Vec<[u8; CIPHER_BLOCK_SIZE]>) -> LeMerkLevel<CIPHER_BLOCK_SIZE> {
        LeMerkLevel::<CIPHER_BLOCK_SIZE>(vector)
    }
    fn len(&self) -> usize {
        self.0.len()
    }
}

impl<const CIPHER_BLOCK_SIZE: usize> Iterator for LeMerkLevel<CIPHER_BLOCK_SIZE> {
    type Item = LeMerkLevel<CIPHER_BLOCK_SIZE>;
    fn next(&mut self) -> Option<LeMerkLevel<CIPHER_BLOCK_SIZE>> {
        let level_length = self.len();
        if level_length.checked_rem(2) == Some(1) {
            None
        } else {
            Some(LeMerkLevel::<CIPHER_BLOCK_SIZE>::from(
                (0..level_length.checked_div(2)?)
                    .map(|i| Index::from(i*2))
                    .map(|i| { 
                        let left = self.get_cipher_block(i).unwrap(); // TODO : make this unwrap infallible
                        let right = self.get_cipher_block(i.incr()).unwrap();
                        let mut output = [0_u8; CIPHER_BLOCK_SIZE];
                        hash_visit::<sha3::Sha3_256>(&left,&right, &mut output);
                        output
                    }) 
                    .collect()
            ))
        }
    }
    // fn fold<B, F>(self, init: B, f: F) -> B
    // where
    //     Self: Sized,
    //     F: FnMut(B, Self::Item) -> B
    // {
    //     init
    // }
}

// Memory layout for a LeMerk Tree.
#[derive(PartialEq, Debug)]
struct LeMerkTree<const CIPHER_BLOCK_SIZE: usize> {
    // Level's length of the Merkle Tree.
    max_depth: usize,
    // Maximum possible Index
    max_index: Index,
    // A flatten representation of the whole tree.
    flat_hash_tree: LeMerkLevel<CIPHER_BLOCK_SIZE>,
}

#[derive(Debug, PartialEq)]
struct VirtualNode<const CIPHER_BLOCK_SIZE: usize> {
    // data_hash: [u8; CIPHER_BLOCK_SIZE],
    // Zero based index. This is designed to be implemented for a flat_hash_tree as LeMerkLevel representation of an entire tree.
    index: Index,
    // Index in the flat hash tree representaion.
    flat_tree_index: usize,
    // Option wrapping the index of the ancestor, None if there's no ancestor (root). 
    ancestor: Option<Index>,
    left_successor: Option<Index>,
    right_successor: Option<Index>
}

// VirtualNode is a data structure designed to be used in the context of a LeMerkTree.
// A LeMerkTree will use this data structure to build the virtual paths to the data contained in the flatten hash tree.
// As it is meant to be used in the context of a LeMerkTree, its methods are private.
impl<const CIPHER_BLOCK_SIZE: usize> VirtualNode<CIPHER_BLOCK_SIZE> {
    fn get_index(&self) -> Index {
        self.index
    }
    fn get_ancestor(&self) -> Result<Option<Index>, IndexError> {
        if self.get_index() == Index::from(0) { return Ok(None) }; // Index 0's ancestor is None.
        let index = self.index.get_index();
        let be_ancestor = index
            .checked_sub(1).ok_or(IndexError::IndexBadSubstraction)?
            .checked_div(2).ok_or(IndexError::IndexBadDivision)?;
        let ancestor: Option<Index> = if be_ancestor < index { Some(Index::from(be_ancestor)) } else { None };
        Ok(ancestor)
    }
    // Gets a Result with an Option to the index value of the binary pair to the ancestor of the node.
    // If the original index of the VirtualNode is 0 returns Some(None).
    fn get_pair_to_ancestor(&self) -> Result<Option<Index>, IndexError> {
        if Index::from(1) == self.get_index().checked_rem(2)? {
            Ok(Some(self.get_index().incr())) // if odd then increment.
        } else {
            if self.get_index() == Index::from(0) {
                Ok(None) // if index is 0, there's None pairs to ancestor
            } else {
                Ok(Some(self.get_index().try_decr()?)) // if even then decrement.
            }
        }
    }
    fn get_sucessors_indexes(&self) -> (Option<Index>, Option<Index>) {
        (self.left_successor, self.right_successor)
    }
    fn is_sucessor(&self, other: &VirtualNode<CIPHER_BLOCK_SIZE>) -> bool {
        let (left, right) = self.get_sucessors_indexes();
        if left == Some(other.get_index()) || right == Some(other.get_index()) {
            true
        } else {
            false
        }
    }
    fn is_ancestor(&self, other: &VirtualNode<CIPHER_BLOCK_SIZE>) -> bool {
        if Ok(Some(other.get_index())) == self.get_ancestor() {
            true
        } else {
            false
        }
    }
}

impl<const CIPHER_BLOCK_SIZE: usize> LeMerkTree<CIPHER_BLOCK_SIZE> {
    pub fn get_virtual_node_by_depth_offset(&mut self, value: DepthOffset) -> Result<VirtualNode<CIPHER_BLOCK_SIZE>, LeMerkTreeError> {
        let index = Index::try_from(value)?;
        self.get_virtual_node_by_index(index)
    }
    pub fn get_virtual_node_by_index(&self, index: Index) -> Result<VirtualNode<CIPHER_BLOCK_SIZE>, LeMerkTreeError> {
        if index > self.max_index { return Err(LeMerkTreeError::Overflow); };
        let flat_tree_index = index.to_flat_hash_tree_index(self).ok_or(IndexError::IndexOverflow)?;
        let depth_offset = DepthOffset::try_from(index)?;
        let ancestor = if index.get_index() == 0 {
                None 
            } else {
                Some(Index::from(
                    index.get_index()
                        .checked_sub(1).ok_or(IndexError::IndexBadSubstraction)?
                        .checked_div(2).ok_or(LeMerkTreeError::BadDivision)?
                    )
                )
            };
        let (left_successor, right_successor) = if depth_offset.get_depth() > 62 {
                (None, None)
            } else {
                let double_index = index.get_index()
                    .checked_mul(2).ok_or(LeMerkTreeError::BadMultiplication)?;
                (
                    Some(Index::from(
                        double_index
                            .checked_add(1).ok_or(LeMerkTreeError::BadAddition)?
                    )),
                    Some(Index::from(
                        double_index
                            .checked_add(2).ok_or(LeMerkTreeError::BadAddition)?
                    )),
                )
            };
        Ok(
            VirtualNode {
                // data_hash: self.flat_hash_tree.get_cipher_block(index)?,
                index,
                flat_tree_index,
                ancestor,
                left_successor,
                right_successor,
            }
        )
    }
    pub fn get_level_by_depth_index(&self, depth: usize) -> Result<LeMerkLevel<CIPHER_BLOCK_SIZE>, LeMerkTreeError> {
        let max_index = self.max_index.get_index();
        if depth > self.max_depth {
            Err(LeMerkTreeError::Overflow)
        } else {
            let initial_index = max_index + 1 - 2_usize.checked_pow(depth as u32 + 1).ok_or(LeMerkTreeError::BadPow)?.checked_sub(1).ok_or(LeMerkTreeError::BadSubstraction)?;
            let level_size = 2_usize.checked_pow(depth as u32).ok_or(LeMerkTreeError::BadPow)?;
            let ending_index = initial_index + level_size;
            Ok(LeMerkLevel::from(
                self.flat_hash_tree.0[initial_index..ending_index].to_vec()
            ))
        }
    }
    pub fn get_leaves_indexes(&self) -> Vec<Index> {
        let max_depth = self.get_max_depth();
        let cardinality = 2_usize.pow(max_depth as u32)-1;
        (0..=cardinality)
            .map(
                |offset| {
                    cardinality + offset
                }
            )
            .map( |index_usize| {
                Index::from(index_usize)
            })
            .collect()
    }
    pub fn get_leaves_virtual_nodes(&self) -> Vec<VirtualNode<CIPHER_BLOCK_SIZE>> {
        self.get_leaves_indexes()
            .into_iter()
            .map(
                |index| {
                    self.get_virtual_node_by_index(index).expect("Wrong assumptions.")
                }
            )
            .collect()
    }
    pub fn get_root_data(&self) -> Result<[u8; CIPHER_BLOCK_SIZE], LeMerkTreeError> {
        Ok(self.flat_hash_tree.get_cipher_block(self.max_index)?)
    }
    // Calculates the node's values in place.
    fn recalculate(&mut self, index:Index) {
        todo!()
    }
}

impl<const CIPHER_BLOCK_SIZE: usize> SizedTree for &LeMerkTree<CIPHER_BLOCK_SIZE> {
    fn get_max_index(&self) -> usize {
        self.max_index.get_index()
    }
    fn get_max_depth(&self) -> usize {
        self.max_depth
    }
}

#[test]
fn next_level_depth_1() {
    const SIZE: usize = 32;
    let mut level: LeMerkLevel<SIZE> = LeMerkLevel::from(vec![[0_u8;SIZE]; 2]);
    let next_level = level.next().expect("Wrong assumptions.");
    assert_eq!(
        LeMerkLevel::from(
            [[7, 15, 161, 171, 111, 204, 85, 126, 209, 77, 66, 148, 31, 25, 103, 105, 48, 72, 85, 30, 185, 4, 42, 141, 10, 5, 122, 251, 215, 94, 129, 224]].to_vec()
        ), 
        next_level
    );
}

#[test]
fn next_level_depth_2() {
    const SIZE: usize = 32;
    let mut level: LeMerkLevel<SIZE> = LeMerkLevel::from(vec![[0_u8;SIZE]; 4]);
    let mut next_level = level.next().expect("Wrong assumptions.");
    let root = next_level.next().expect("Wrong assumptions.");
    assert_eq!(
        LeMerkLevel::from(
            [
                [7, 15, 161, 171, 111, 204, 85, 126, 209, 77, 66, 148, 31, 25, 103, 105, 48, 72, 85, 30, 185, 4, 42, 141, 10, 5, 122, 251, 215, 94, 129, 224],
                [7, 15, 161, 171, 111, 204, 85, 126, 209, 77, 66, 148, 31, 25, 103, 105, 48, 72, 85, 30, 185, 4, 42, 141, 10, 5, 122, 251, 215, 94, 129, 224]
            ].to_vec()
        ), 
        next_level
    );
    assert_eq!(
        LeMerkLevel::from(
            [
                [83, 218, 176, 66, 48, 138, 183, 1, 176, 115, 237, 212, 209, 76, 86, 84, 161, 247, 13, 33, 11, 103, 14, 242, 136, 201, 174, 234, 156, 74, 69, 48]
            ].to_vec()
        ), 
        root
    );
}

#[test]
fn merkletree_depth_20_levels_0_1() {
    const SIZE: usize = 32;
    let mut builder: builder::LeMerkBuilder<SIZE> = builder::LeMerkBuilder::<SIZE>::new();
    let mut tree: LeMerkTree<SIZE> = builder
        .with_depth_length(20)
        .with_initial_block(hex!("abababababababababababababababababababababababababababababababab"))
        .try_build::<sha3::Sha3_256>()
        .expect("Unexpected build.");
    assert_eq!(
        tree.get_root_data().unwrap(),
        hex!("d4490f4d374ca8a44685fe9471c5b8dbe58cdffd13d30d9aba15dd29efb92930"), 
    );
    let mut level_0 = tree.get_level_by_depth_index(0).unwrap();
    assert!(level_0.len() == 1);
    assert_eq!(
        level_0.get_cipher_block_mut_ref(Index::from(0)).unwrap(),
        &mut hex!("d4490f4d374ca8a44685fe9471c5b8dbe58cdffd13d30d9aba15dd29efb92930"),
    );
    let mut level_1 = tree.get_level_by_depth_index(1).unwrap();
    assert_eq!(level_1.len(), 2);
    let left = level_1.get_cipher_block(Index::from(0)).unwrap();
    let right = level_1.get_cipher_block(Index::from(1)).unwrap();
    assert_eq!(
        left,
        [244_u8, 96, 234, 249, 100, 250, 60, 212, 18, 150, 230, 14, 253, 191, 109, 215, 223, 84, 156, 120, 12, 63, 185, 67, 46, 23, 132, 168, 157, 248, 67, 2],
    );
    assert_eq!(
        right,
        [244_u8, 96, 234, 249, 100, 250, 60, 212, 18, 150, 230, 14, 253, 191, 109, 215, 223, 84, 156, 120, 12, 63, 185, 67, 46, 23, 132, 168, 157, 248, 67, 2],
    );
    let mut output = [0_u8; SIZE];
    hash_visit::<sha3::Sha3_256>(&left, &right, &mut output);
    assert_eq!(
        output,
        hex!("d4490f4d374ca8a44685fe9471c5b8dbe58cdffd13d30d9aba15dd29efb92930")
    )
}

#[test]
fn get_last_and_pre_last_levels_from_tree_depth_20() {
    const SIZE: usize = 32;
    let tree_depth_length = 20;
    let last_level_depth_index = 19;
    let pre_last_level_depth_index = 18;
    let mut builder: builder::LeMerkBuilder<SIZE> = builder::LeMerkBuilder::<SIZE>::new();
    let mut tree: LeMerkTree<SIZE> = builder
        .with_depth_length(tree_depth_length)
        .with_initial_block(hex!("abababababababababababababababababababababababababababababababab"))
        .try_build::<sha3::Sha3_256>()
        .expect("Unexpected build.");
    let mut pre_last_level = tree.get_level_by_depth_index(pre_last_level_depth_index).unwrap();
    let mut last_level = tree.get_level_by_depth_index(last_level_depth_index).unwrap();  // Max depth index for a LeMerkTree of depth length K is (K - 1).
    assert_eq!(
        pre_last_level.len(),
        2_usize.pow(pre_last_level_depth_index as u32)
    );
    assert_eq!(
        last_level.len(),
        2_usize.pow(last_level_depth_index as u32)
    );
    let next_to_last_level = last_level.clone().next().unwrap();
    assert_eq!(pre_last_level, next_to_last_level);
    assert_eq!(last_level, LeMerkLevel::from(vec![hex!("abababababababababababababababababababababababababababababababab");2_usize.pow(last_level_depth_index as u32)]));
    assert_ne!(last_level, LeMerkLevel::from(vec![hex!("ababababababaffbabababababababababababababababababababababababab");2_usize.pow(last_level_depth_index as u32)]));
}

#[test]
#[should_panic]
fn get_level_by_depth_index_greater_than_max_depth_index_should_fail() {
    const SIZE: usize = 32;
    let mut builder: builder::LeMerkBuilder<SIZE> = builder::LeMerkBuilder::<SIZE>::new();
    let mut tree: LeMerkTree<SIZE> = builder
        .with_depth_length(20)
        .with_initial_block(hex!("abababababababababababababababababababababababababababababababab"))
        .try_build::<sha3::Sha3_256>()
        .expect("Unexpected build.");
    let mut level_20 = tree.get_level_by_depth_index(20).unwrap();  // Max depth index for a LeMerkTree of depth length K is (K - 1).
}

#[test]
fn examine_virtual_nodes_for_tree_depth_length_28() {
    const SIZE: usize = 32;
    let tree_depth_length = 28;
    let mut builder: builder::LeMerkBuilder<SIZE> = builder::LeMerkBuilder::<SIZE>::new();
    let mut tree: LeMerkTree<SIZE> = builder
        .with_depth_length(tree_depth_length)
        .with_initial_block([0_u8; SIZE])
        .try_build::<sha3::Sha3_256>()
        .expect("Unexpected build.");
    (1..=(&tree).get_max_depth()) // Node 0's ancestor panics when unwrapped.
        .for_each(
            |node_index| {
                let virtual_node = tree.get_virtual_node_by_index(Index::from(node_index)).unwrap();
                let virtual_node_ancestor = tree.get_virtual_node_by_index(virtual_node.get_ancestor().unwrap().unwrap()).unwrap();
                let (left_successor_index, right_successor_index) = virtual_node.get_sucessors_indexes();
                let virtual_node_left_successor = tree.get_virtual_node_by_index(left_successor_index.unwrap().into()).unwrap();
                let virtual_node_right_successor = tree.get_virtual_node_by_index(right_successor_index.unwrap().into()).unwrap();
                assert!(virtual_node_ancestor.is_sucessor(&virtual_node));
                assert!(virtual_node.is_ancestor(&virtual_node_ancestor));
                assert_ne!(virtual_node_left_successor, virtual_node_right_successor);
                assert_eq!(virtual_node_left_successor.get_ancestor(), virtual_node_right_successor.get_ancestor());
                assert_eq!(virtual_node_left_successor.get_pair_to_ancestor().unwrap().unwrap(), virtual_node_right_successor.get_index());
                assert_eq!(virtual_node_right_successor.get_pair_to_ancestor().unwrap().unwrap(), virtual_node_left_successor.get_index());
                assert!(virtual_node_left_successor.is_ancestor(&virtual_node));
                assert!(virtual_node_right_successor.is_ancestor(&virtual_node));
                assert!(virtual_node.is_sucessor(&virtual_node_left_successor));
                assert!(virtual_node.is_sucessor(&virtual_node_right_successor));
            }
        );
    
    {   // tests for node 0;
        let virtual_node = tree.get_virtual_node_by_index(Index::from(0)).unwrap();
        assert_eq!(virtual_node.get_ancestor(), Ok(None));
        let (left_successor_index, right_successor_index) = virtual_node.get_sucessors_indexes();
        let virtual_node_left_successor = tree.get_virtual_node_by_index(left_successor_index.unwrap().into()).unwrap();
        let virtual_node_right_successor = tree.get_virtual_node_by_index(right_successor_index.unwrap().into()).unwrap();
        assert_ne!(virtual_node_left_successor, virtual_node_right_successor);
        assert_eq!(virtual_node_left_successor.get_ancestor(), virtual_node_right_successor.get_ancestor());
        assert!(virtual_node_left_successor.is_ancestor(&virtual_node));
        assert!(virtual_node_right_successor.is_ancestor(&virtual_node));
        assert!(virtual_node.is_sucessor(&virtual_node_left_successor));
        assert!(virtual_node.is_sucessor(&virtual_node_right_successor));
    }
}

#[test]
fn leaf_of_one_node_tree() {
    let tree_depth_length = 1;
    const SIZE: usize = 32;
    let mut builder: builder::LeMerkBuilder<SIZE> = builder::LeMerkBuilder::<SIZE>::new();
    let mut tree: LeMerkTree<SIZE> = builder
        .with_depth_length(tree_depth_length)
        .with_initial_block([0_u8; SIZE])
        .try_build::<sha3::Sha3_256>()
        .expect("Unexpected build.");
}

#[test]
#[should_panic(expected = "LengthShouldBeGreaterThanZero")]
fn building_tree_length_0_should_panic() {
    let tree_depth_length = 0;
    const SIZE: usize = 32;
    let mut builder: builder::LeMerkBuilder<SIZE> = builder::LeMerkBuilder::<SIZE>::new();
    let mut tree: LeMerkTree<SIZE> = builder
        .with_depth_length(tree_depth_length)
        .with_initial_block([0_u8; SIZE])
        .try_build::<sha3::Sha3_256>()
        .unwrap();
}

#[test]
fn building_tree_length_1_has_one_leaf() {
    let tree_depth_length = 1;
    const SIZE: usize = 32;
    let mut builder: builder::LeMerkBuilder<SIZE> = builder::LeMerkBuilder::<SIZE>::new();
    let mut tree: LeMerkTree<SIZE> = builder
        .with_depth_length(tree_depth_length)
        .with_initial_block([0_u8; SIZE])
        .try_build::<sha3::Sha3_256>()
        .expect("Unexpected build.");
    let leaves = tree.get_leaves_indexes();
    assert_eq!(leaves.len(), 1);
    assert_eq!(leaves[0], Index::from(0));
}

#[test]
fn building_tree_length_2_has_three_leaves() {
    let tree_depth_length = 2;
    const SIZE: usize = 32;
    let mut builder: builder::LeMerkBuilder<SIZE> = builder::LeMerkBuilder::<SIZE>::new();
    let mut tree: LeMerkTree<SIZE> = builder
        .with_depth_length(tree_depth_length)
        .with_initial_block([0_u8; SIZE])
        .try_build::<sha3::Sha3_256>()
        .expect("Unexpected build.");
    let leaves = tree.get_leaves_indexes();
    assert_eq!(leaves.len(), 2);
    assert_eq!(leaves, vec![Index::from(1),Index::from(2)]);
}