/// LeMerk is a custom Merkle Tree implemention.
use sha3;
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
                    .map(|i| Index::from(i))
                    .map(|i| { 
                        let a = self.get_cipher_block(i).unwrap(); // TODO : make this unwrap infallible
                        let b = self.get_cipher_block(i+Index::from(1)).unwrap();
                        let mut output = [0_u8; CIPHER_BLOCK_SIZE];
                        hash_visit::<sha3::Sha3_256>(&a,&b, &mut output);
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
    depth_length: usize,
    // Maximum possible Index
    max_index: Index,
    // A flatten representation of the whole tree.
    flat_hash_tree: LeMerkLevel<CIPHER_BLOCK_SIZE>,
}

struct VirtualNode<'a, const CIPHER_BLOCK_SIZE: usize> {
    data_hash: &'a mut [u8; CIPHER_BLOCK_SIZE],
    index: Index,
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
    fn get_pair_to_ancestor(&self) -> Index {
        todo!()
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
}