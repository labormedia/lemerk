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

struct VirtualNode<'a, const CIPHER_BLOCK_SIZE: usize> {
    data_hash: &'a mut [u8; CIPHER_BLOCK_SIZE],
    // Zero based index. This is designed to be implemented for a flat_hash_tree as LeMerkLevel representation of an entire tree.
    index: Index,
    // Option wrapping the index of the ancestor, None if there's no ancestor (root). 
    ancestor: Option<Index>,
    left_successor: Option<Index>,
    right_successor: Option<Index>
}

impl<'a, const CIPHER_BLOCK_SIZE: usize> VirtualNode<'a, CIPHER_BLOCK_SIZE> {
    fn get_index(&self) -> Index {
        self.index
    }
    fn get_ancestor(&self) -> Result<Option<Index>, IndexError> {
        let index = self.index.get_index();
        let be_ancestor = index.checked_div(2).ok_or(IndexError::IndexBadDivision)?;
        let ancestor: Option<Index> = if be_ancestor < index { Some(Index::from(be_ancestor)) } else { None };
        Ok(ancestor)
    }
    fn get_pair_to_ancestor(&self) -> Result<Option<Index>, IndexError> {
        if let remainder = self.get_index().checked_rem(2)? {
            assert!(remainder.get_index() == 1_usize);
            Ok(Some(self.get_index().try_decr()?))
        } else {
            if self.get_index() == Index::from(0) { // Index 
                Ok(None)
            } else {
                Ok(Some(self.get_index().incr()))
            }
        }
    } 
}

impl<const CIPHER_BLOCK_SIZE: usize> LeMerkTree<CIPHER_BLOCK_SIZE> {
    fn get_node_by_depth_offset(&mut self, value: DepthOffset) -> Result<VirtualNode<CIPHER_BLOCK_SIZE>, LeMerkTreeError> {
        let index = Index::try_from(value)?;
        self.get_node_by_index(index)
    }
    fn get_node_by_index(&mut self, index: Index) -> Result<VirtualNode<CIPHER_BLOCK_SIZE>, LeMerkTreeError> {
        if index > self.max_index { return Err(LeMerkTreeError::Overflow); }
        let be_ancestor = index.get_index().checked_div(2).ok_or(LeMerkTreeError::BadDivision)?;
        let ancestor: Option<Index> = if be_ancestor < index.get_index() { Some(Index::from(be_ancestor)) } else { None };
        let be_right = index.get_index()
            .checked_mul(2)
            .ok_or(LeMerkTreeError::BadMultiplication)?
            .checked_add(1)
            .ok_or(LeMerkTreeError::BadAddition)?;
        let right_successor: Option<Index> = if be_right <= self.max_index.get_index() {
            Some(Index::from(be_right))
        } else { None };
        let left_successor: Option<Index> = if right_successor != None { // left is always strictly less than right in this scope, then we can have guarantees that when right is not None left should be Some(value).
            Some(
                Index::from(
                    index.get_index()
                        .checked_mul(2)
                        .ok_or(LeMerkTreeError::BadMultiplication)?
                )
            )
        } else { None };
        Ok(
            VirtualNode {
                data_hash: self.flat_hash_tree.get_cipher_block_mut_ref(index)?,
                index,
                ancestor,
                left_successor,
                right_successor,
            }
        )
    }
    fn get_level_by_depth(&mut self, depth: usize) -> Result<LeMerkLevel<CIPHER_BLOCK_SIZE>, LeMerkTreeError> {
        if depth > self.max_depth {
            Err(LeMerkTreeError::Overflow)
        } else {
            let level_size = 2_usize.checked_pow(depth as u32).ok_or(LeMerkTreeError::BadPow)?;
            let initial_index = level_size-1;
            let ending_index = initial_index + level_size;
            Ok(LeMerkLevel::from(
                self.flat_hash_tree.0[initial_index..ending_index].to_vec()
            ))
        }
    }
    fn get_root(&self) -> Result<[u8; CIPHER_BLOCK_SIZE], LeMerkTreeError> {
        Ok(self.flat_hash_tree.get_cipher_block(self.max_index)?)
    }
    // Calculates the node's values in place.
    fn recalculate(&mut self) {

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
fn build_merkletree_depth_20() {
    const SIZE: usize = 32;
    let mut builder: builder::LeMerkBuilder<SIZE> = builder::LeMerkBuilder::<SIZE>::new();
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