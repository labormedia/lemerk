///! LeMerk is a custom Merkle Tree implemention.
///! Example usage:
///```
///    use hex_literal::hex;
///    use lemerk::LeMerkTree;
///    use lemerk::builder::LeMerkBuilder;
///
///    const SIZE: usize = 32;
///    let max_depth = 19;
///    let mut builder: LeMerkBuilder<SIZE> = LeMerkBuilder::<SIZE>::new();
///    let custom_block = hex!("abababababababababababababababababababababababababababababababab");
///    let different_custom_block = hex!("ababababababaffbabababababababababababababababababababababababab");
///    let mut tree: LeMerkTree<SIZE> = builder
///        .with_max_depth(max_depth)
///        .with_initial_block(custom_block)  // A custom block.
///        .try_build::<sha3::Sha3_256>()
///        .expect("Unexpected build.");
///    let original_root_data = tree.get_root_data();
///    let leaves = tree.get_leaves_indexes();

///    let leaf_index = leaves[0];
///    let (updated_root, updated_proof) = tree.set_update_generate_proof(leaf_index, different_custom_block).unwrap();
///```
use sha3;
use hex_literal::hex;
use core::iter::Iterator;
/// Crypto helpers.
pub mod crypto;
use crypto::hash_visit;
/// LeMerk tree builder pattern.
pub mod builder;
/// Tree data elements
pub mod data;
pub use data::{
    CipherBlock,
    Index,
    DepthOffset,
};
pub mod error;
use error::*;
pub mod traits;
use traits::SizedTree;

/// Memory layout for a single layer of blocks. This is used for the expansion of the levels in the builder 
/// and the final flatten expansion of the whole tree, in a single layer indexed by the struct implementation.
#[derive(PartialEq, Debug, Clone)]
pub struct LeMerkLevel<const CIPHER_BLOCK_SIZE: usize>(Vec<[u8; CIPHER_BLOCK_SIZE]>);

impl<const CIPHER_BLOCK_SIZE: usize> LeMerkLevel<CIPHER_BLOCK_SIZE> {
    pub fn get_cipher_block_mut_ref(&mut self, value: Index) -> Result<&mut [u8; CIPHER_BLOCK_SIZE], LeMerkLevelError>{
        let index_usize = value.get_index();
        if index_usize < self.0.len() {
            Ok(&mut self.0[index_usize])
        } else {
            Err(LeMerkLevelError::Overflow)
        }
    }
    pub fn get_cipher_block(&self, index: Index) -> Result<[u8; CIPHER_BLOCK_SIZE], LeMerkLevelError>{
        let index_usize = index.get_index();
        if index_usize < self.0.len() {
            Ok(self.0[index_usize])
        } else {
            Err(LeMerkLevelError::Overflow)
        }
    }
    pub fn from(vector: Vec<[u8; CIPHER_BLOCK_SIZE]>) -> LeMerkLevel<CIPHER_BLOCK_SIZE> {
        LeMerkLevel::<CIPHER_BLOCK_SIZE>(vector)
    }
    pub fn len(&self) -> usize {
        self.0.len()
    }
}

/// The Iterator implementation maps the LeMerkLevel's hash_visit pair combinations to its next depth level closer to root, if not root.
/// As root doesn't have a different pair to its ancestor, because there's no other distinct pair and because it has ancestor None, then its next() value is None.
///     
/// ```
/// use lemerk::LeMerkLevel;
///     const SIZE: usize = 32;
///     let mut level: LeMerkLevel<SIZE> = LeMerkLevel::from(vec![[0_u8;SIZE]; 4]);
///     let mut next_level = level.next().expect("Wrong assumptions.");
///     let root = next_level.next().expect("Wrong assumptions.");
///     assert_eq!(
///         LeMerkLevel::from(
///             [
///                 [7, 15, 161, 171, 111, 204, 85, 126, 209, 77, 66, 148, 31, 25, 103, 105, 48, 72, 85, 30, 185, 4, 42, 141, 10, 5, 122, 251, 215, 94, 129, 224],
///                 [7, 15, 161, 171, 111, 204, 85, 126, 209, 77, 66, 148, 31, 25, 103, 105, 48, 72, 85, 30, 185, 4, 42, 141, 10, 5, 122, 251, 215, 94, 129, 224]
///             ].to_vec()
///         ), 
///         next_level
///     );
///     assert_eq!(
///         LeMerkLevel::from(
///             [
///                 [83, 218, 176, 66, 48, 138, 183, 1, 176, 115, 237, 212, 209, 76, 86, 84, 161, 247, 13, 33, 11, 103, 14, 242, 136, 201, 174, 234, 156, 74, 69, 48]
///             ].to_vec()
///         ), 
///         root
///     );
/// ```
impl<const CIPHER_BLOCK_SIZE: usize> Iterator for LeMerkLevel<CIPHER_BLOCK_SIZE> {
    type Item = LeMerkLevel<CIPHER_BLOCK_SIZE>;
    ///     
    /// ```
    /// use lemerk::LeMerkLevel;
    ///     const SIZE: usize = 32;
    ///     let mut level: LeMerkLevel<SIZE> = LeMerkLevel::from(vec![[0_u8;SIZE]; 4]);
    ///     let mut next_level = level.next().expect("Wrong assumptions.");
    ///     let root = next_level.next().expect("Wrong assumptions.");
    ///     assert_eq!(
    ///         LeMerkLevel::from(
    ///             [
    ///                 [7, 15, 161, 171, 111, 204, 85, 126, 209, 77, 66, 148, 31, 25, 103, 105, 48, 72, 85, 30, 185, 4, 42, 141, 10, 5, 122, 251, 215, 94, 129, 224],
    ///                 [7, 15, 161, 171, 111, 204, 85, 126, 209, 77, 66, 148, 31, 25, 103, 105, 48, 72, 85, 30, 185, 4, 42, 141, 10, 5, 122, 251, 215, 94, 129, 224]
    ///             ].to_vec()
    ///         ), 
    ///         next_level
    ///     );
    ///     assert_eq!(
    ///         LeMerkLevel::from(
    ///             [
    ///                 [83, 218, 176, 66, 48, 138, 183, 1, 176, 115, 237, 212, 209, 76, 86, 84, 161, 247, 13, 33, 11, 103, 14, 242, 136, 201, 174, 234, 156, 74, 69, 48]
    ///             ].to_vec()
    ///         ), 
    ///         root
    ///     );
    /// ```
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

/// Memory layout for a LeMerk Tree.
/// The constructor of LeMerkTree is LeMerkBuilder. 
#[derive(PartialEq, Debug)]
pub struct LeMerkTree<const CIPHER_BLOCK_SIZE: usize> {
    /// Level's length of the Merkle Tree.
    max_depth: usize,
    /// Maximum possible Index
    max_index: Index,
    /// A flatten representation of the whole tree.
    flat_hash_tree: LeMerkLevel<CIPHER_BLOCK_SIZE>,
    /// Length of the data layer, i.e. leaves.
    data_layer_length: usize
}

/// VirtualNode is a data structure designed to be used in the context of a LeMerkTree.
/// A LeMerkTree will use this data structure to build the virtual paths to the data contained in the flatten hash tree.
#[derive(Debug, PartialEq)]
pub struct VirtualNode<const CIPHER_BLOCK_SIZE: usize> {
    /// data_hash: [u8; CIPHER_BLOCK_SIZE],
    /// Zero based index. This is designed to be implemented for a flat_hash_tree as LeMerkLevel representation of an entire tree.
    index: Index,
    /// Index in the flat hash tree representaion.
    flat_tree_index: usize,
    /// Option wrapping the index of the ancestor, None if there's no ancestor (root). 
    ancestor: Option<Index>,
    left_successor: Option<Index>,
    right_successor: Option<Index>
}

impl<const CIPHER_BLOCK_SIZE: usize> VirtualNode<CIPHER_BLOCK_SIZE> {
    pub fn get_index(&self) -> Index {
        self.index
    }
    pub fn get_ancestor_index(&self) -> Result<Option<Index>, IndexError> {
        if self.get_index() == Index::from(0) { return Ok(None) }; // Index 0's ancestor is None.
        let index = self.index.get_index();
        let be_ancestor = index
            .checked_sub(1).ok_or(IndexError::IndexBadSubstraction)?
            .checked_div(2).ok_or(IndexError::IndexBadDivision)?;
        let ancestor: Option<Index> = if be_ancestor < index { Some(Index::from(be_ancestor)) } else { None };
        Ok(ancestor)
    }
    /// Gets a Result with an Option to the index value of the binary pair to the ancestor of the node.
    /// If the original index of the VirtualNode is 0 returns Some(None).
    pub fn get_pair_index_to_ancestor(&self) -> Result<Option<Index>, IndexError> {
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
    fn get_flat_tree_index(&self) -> usize {
        self.flat_tree_index
    }
    pub fn get_successors_indexes(&self) -> (Option<Index>, Option<Index>) {
        (self.left_successor, self.right_successor)
    }
    pub fn is_sucessor(&self, other: &VirtualNode<CIPHER_BLOCK_SIZE>) -> bool {
        let (left, right) = self.get_successors_indexes();
        if left == Some(other.get_index()) || right == Some(other.get_index()) {
            true
        } else {
            false
        }
    }
    pub fn is_ancestor(&self, other: &VirtualNode<CIPHER_BLOCK_SIZE>) -> bool {
        if Ok(Some(other.get_index())) == self.get_ancestor_index() {
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
    pub fn get_data_layer_length(&self) -> usize {
        self.data_layer_length
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
    pub fn get_indexes_path_to_root_by_index(&self, index: Index) -> Result<Vec<Index>, LeMerkTreeError> {
        let mut result = Vec::new();
        let mut virtual_node = self.get_virtual_node_by_index(index)?;
        result.push(virtual_node.get_index());
        while let Some(ancestor_index) = virtual_node.get_ancestor_index()? {
            virtual_node = self.get_virtual_node_by_index(ancestor_index)?;
            result.push(virtual_node.get_index());
        };
        Ok(result)
    }
    pub fn verify_path_to_root_by_index(&self, index: Index) -> Result<[u8; CIPHER_BLOCK_SIZE], LeMerkTreeError> {
        let mut result = self.get_cipher_block_by_index(index)?.clone();
        let mut virtual_node = self.get_virtual_node_by_index(index)?;
        while let Some(ancestor_index) = virtual_node.get_ancestor_index()? {
            let virtual_node_flat_tree_index = virtual_node.get_flat_tree_index();
            let pair_to_ancestor_flat_tree_index = self.get_virtual_node_by_index(
                    virtual_node.get_pair_index_to_ancestor()?.ok_or(LeMerkTreeError::IsNone)?
                )?.get_flat_tree_index();
            let ancestor_virtual_node = self.get_virtual_node_by_index(ancestor_index)?;
            let ancestor_flat_tree_index = ancestor_virtual_node.get_flat_tree_index();
            
            hash_visit::<sha3::Sha3_256>(
                &self.flat_hash_tree.get_cipher_block(virtual_node_flat_tree_index.into())?,
                &self.flat_hash_tree.get_cipher_block(pair_to_ancestor_flat_tree_index.into())?,
                &mut result
            );
            assert_eq!(self.flat_hash_tree.get_cipher_block(ancestor_flat_tree_index.into())?, result);
            virtual_node = self.get_virtual_node_by_index(ancestor_index)?;
        };
        Ok(self.get_root_data()?)
    }
    /// This method sets a leaf by its index with the block data provided.
    /// It returns the root update.
    pub fn set_and_update(&mut self, index: Index, block: [u8; CIPHER_BLOCK_SIZE]) -> Result<[u8; CIPHER_BLOCK_SIZE], LeMerkTreeError> {
        let mut virtual_node = self.get_virtual_node_by_index(index)?;
        let flat_tree_index_to_update = virtual_node.get_flat_tree_index();
        if flat_tree_index_to_update >= self.get_data_layer_length() {
            Err(LeMerkTreeError::OutOfBounds)
        } else {
            *self.flat_hash_tree.get_cipher_block_mut_ref(flat_tree_index_to_update.into())? = block;
            let mut result = self.get_cipher_block_by_index(index)?.clone();
            while let Some(ancestor_index) = virtual_node.get_ancestor_index()? {
                let virtual_node_flat_tree_index = virtual_node.get_flat_tree_index();
                let pair_to_ancestor_flat_tree_index = self.get_virtual_node_by_index(
                        virtual_node.get_pair_index_to_ancestor()?.ok_or(LeMerkTreeError::IsNone)?
                    )?.get_flat_tree_index();
                let ancestor_virtual_node = self.get_virtual_node_by_index(ancestor_index)?;
                let ancestor_flat_tree_index = ancestor_virtual_node.get_flat_tree_index();
                
                hash_visit::<sha3::Sha3_256>(
                    &self.flat_hash_tree.get_cipher_block(virtual_node_flat_tree_index.into())?,
                    &self.flat_hash_tree.get_cipher_block(pair_to_ancestor_flat_tree_index.into())?,
                    &mut result
                );
                *self.flat_hash_tree.get_cipher_block_mut_ref(ancestor_flat_tree_index.into())? = result;
                virtual_node = self.get_virtual_node_by_index(ancestor_index)?;
            };
            Ok(self.flat_hash_tree.get_cipher_block(virtual_node.get_flat_tree_index().into())?)
        }
    }
    pub fn set_update_generate_proof(&mut self, index: Index, block: [u8; CIPHER_BLOCK_SIZE]) -> Result<([u8; CIPHER_BLOCK_SIZE], Vec<[u8; CIPHER_BLOCK_SIZE]>), LeMerkTreeError> {
        let mut virtual_node = self.get_virtual_node_by_index(index)?;
        let flat_tree_index_to_update = virtual_node.get_flat_tree_index();
        let mut proof = Vec::new();
        if flat_tree_index_to_update >= self.get_data_layer_length() {
            Err(LeMerkTreeError::OutOfBounds)
        } else {
            *self.flat_hash_tree.get_cipher_block_mut_ref(flat_tree_index_to_update.into())? = block;
            let mut result = self.get_cipher_block_by_index(index)?.clone();
            while let Some(ancestor_index) = virtual_node.get_ancestor_index()? {
                let virtual_node_flat_tree_index = virtual_node.get_flat_tree_index();
                let pair_to_ancestor_flat_tree_index = self.get_virtual_node_by_index(
                        virtual_node.get_pair_index_to_ancestor()?.ok_or(LeMerkTreeError::IsNone)?
                    )?.get_flat_tree_index();
                let ancestor_virtual_node = self.get_virtual_node_by_index(ancestor_index)?;
                let ancestor_flat_tree_index = ancestor_virtual_node.get_flat_tree_index();
                let node_a = self.flat_hash_tree.get_cipher_block(virtual_node_flat_tree_index.into())?;
                let node_b = self.flat_hash_tree.get_cipher_block(pair_to_ancestor_flat_tree_index.into())?;
                hash_visit::<sha3::Sha3_256>(
                    &node_a,
                    &node_b,
                    &mut result
                );
                proof.push(node_b);
                *self.flat_hash_tree.get_cipher_block_mut_ref(ancestor_flat_tree_index.into())? = result;
                virtual_node = self.get_virtual_node_by_index(ancestor_index)?;
            };
            Ok((self.flat_hash_tree.get_cipher_block(virtual_node.get_flat_tree_index().into())?, proof))
        }
    }
    /// Generates a proof from a node index corresponding to a leaf in a LeMerkTree.
    /// A proof is defined a a tuple of a root and a collection of data blocks.
    /// For every given state of a LeMerkTree, there's a unique proof for every leaf in the tree.
    pub fn generate_proof(&mut self, index: Index) -> Result<([u8; CIPHER_BLOCK_SIZE], Vec<[u8; CIPHER_BLOCK_SIZE]>), LeMerkTreeError> {
        let mut virtual_node = self.get_virtual_node_by_index(index)?;
        let flat_tree_index_to_update = virtual_node.get_flat_tree_index();
        if flat_tree_index_to_update >= self.get_data_layer_length() {
            Err(LeMerkTreeError::OutOfBounds)
        } else {
            let mut proof = Vec::new();
            while let Some(ancestor_index) = virtual_node.get_ancestor_index()? {
                let pair_to_ancestor_flat_tree_index = self.get_virtual_node_by_index(
                        virtual_node.get_pair_index_to_ancestor()?.ok_or(LeMerkTreeError::IsNone)?
                    )?.get_flat_tree_index();
                let pair_node_to_ancestor_data = self.flat_hash_tree.get_cipher_block(pair_to_ancestor_flat_tree_index.into())?;
                proof.push(pair_node_to_ancestor_data);
                virtual_node = self.get_virtual_node_by_index(ancestor_index)?;
            }
            Ok((self.flat_hash_tree.get_cipher_block(virtual_node.get_flat_tree_index().into())?, proof))
        }
    }
    pub fn get_cipher_block_by_index(&self, index: Index) -> Result<[u8; CIPHER_BLOCK_SIZE], LeMerkTreeError> {
        let flat_tree_index = index.to_flat_hash_tree_index(self).ok_or(IndexError::IndexOverflow)?;
        Ok(self.flat_hash_tree.get_cipher_block(flat_tree_index.into())?)
    }
    pub fn get_root_data(&self) -> Result<[u8; CIPHER_BLOCK_SIZE], LeMerkTreeError> {
        Ok(self.flat_hash_tree.get_cipher_block(self.max_index)?)
    }
    /// Calculates the node's values in place.
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
    let builder: builder::LeMerkBuilder<SIZE> = builder::LeMerkBuilder::<SIZE>::new();
    let tree: LeMerkTree<SIZE> = builder
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
    let level_1 = tree.get_level_by_depth_index(1).unwrap();
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
    let builder: builder::LeMerkBuilder<SIZE> = builder::LeMerkBuilder::<SIZE>::new();
    let tree: LeMerkTree<SIZE> = builder
        .with_depth_length(tree_depth_length)
        .with_initial_block(hex!("abababababababababababababababababababababababababababababababab"))
        .try_build::<sha3::Sha3_256>()
        .expect("Unexpected build.");
    let pre_last_level = tree.get_level_by_depth_index(pre_last_level_depth_index).unwrap();
    let last_level = tree.get_level_by_depth_index(last_level_depth_index).unwrap();  // Max depth index for a LeMerkTree of depth length K is (K - 1).
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
                let virtual_node_ancestor = tree.get_virtual_node_by_index(virtual_node.get_ancestor_index().unwrap().unwrap()).unwrap();
                let (left_successor_index, right_successor_index) = virtual_node.get_successors_indexes();
                let virtual_node_left_successor = tree.get_virtual_node_by_index(left_successor_index.unwrap().into()).unwrap();
                let virtual_node_right_successor = tree.get_virtual_node_by_index(right_successor_index.unwrap().into()).unwrap();
                assert!(virtual_node_ancestor.is_sucessor(&virtual_node));
                assert!(virtual_node.is_ancestor(&virtual_node_ancestor));
                assert_ne!(virtual_node_left_successor, virtual_node_right_successor);
                assert_eq!(virtual_node_left_successor.get_ancestor_index(), virtual_node_right_successor.get_ancestor_index());
                assert_eq!(virtual_node_left_successor.get_pair_index_to_ancestor().unwrap().unwrap(), virtual_node_right_successor.get_index());
                assert_eq!(virtual_node_right_successor.get_pair_index_to_ancestor().unwrap().unwrap(), virtual_node_left_successor.get_index());
                assert!(virtual_node_left_successor.is_ancestor(&virtual_node));
                assert!(virtual_node_right_successor.is_ancestor(&virtual_node));
                assert!(virtual_node.is_sucessor(&virtual_node_left_successor));
                assert!(virtual_node.is_sucessor(&virtual_node_right_successor));
            }
        );
    
    {   // tests for node 0;
        let virtual_node = tree.get_virtual_node_by_index(Index::from(0)).unwrap();
        assert_eq!(virtual_node.get_ancestor_index(), Ok(None));
        let (left_successor_index, right_successor_index) = virtual_node.get_successors_indexes();
        let virtual_node_left_successor = tree.get_virtual_node_by_index(left_successor_index.unwrap().into()).unwrap();
        let virtual_node_right_successor = tree.get_virtual_node_by_index(right_successor_index.unwrap().into()).unwrap();
        assert_ne!(virtual_node_left_successor, virtual_node_right_successor);
        assert_eq!(virtual_node_left_successor.get_ancestor_index(), virtual_node_right_successor.get_ancestor_index());
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
    let builder: builder::LeMerkBuilder<SIZE> = builder::LeMerkBuilder::<SIZE>::new();
    let tree: LeMerkTree<SIZE> = builder
        .with_depth_length(tree_depth_length)
        .with_initial_block([0_u8; SIZE])
        .try_build::<sha3::Sha3_256>()
        .unwrap();
}

#[test]
fn building_tree_length_1_has_one_leaf() {
    let tree_depth_length = 1;
    const SIZE: usize = 32;
    let builder: builder::LeMerkBuilder<SIZE> = builder::LeMerkBuilder::<SIZE>::new();
    let tree: LeMerkTree<SIZE> = builder
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
    let builder: builder::LeMerkBuilder<SIZE> = builder::LeMerkBuilder::<SIZE>::new();
    let tree: LeMerkTree<SIZE> = builder
        .with_depth_length(tree_depth_length)
        .with_initial_block([0_u8; SIZE])
        .try_build::<sha3::Sha3_256>()
        .expect("Unexpected build.");
    let leaves = tree.get_leaves_indexes();
    assert_eq!(leaves.len(), 2);
    assert_eq!(leaves, vec![Index::from(1),Index::from(2)]);
}

#[test]
fn examine_leaves_for_merkletree_depth_20() {
    const SIZE: usize = 32;
    let max_depth = 19;
    let builder: builder::LeMerkBuilder<SIZE> = builder::LeMerkBuilder::<SIZE>::new();
    let custom_block = hex!("abababababababababababababababababababababababababababababababab");
    let different_custom_block = hex!("ababababababaffbabababababababababababababababababababababababab");
    let tree: LeMerkTree<SIZE> = builder
        .with_max_depth(max_depth)
        .with_initial_block(custom_block)  // A custom block.
        .try_build::<sha3::Sha3_256>()
        .expect("Unexpected build.");
    let leaves = tree.get_leaves_indexes();
    assert_eq!(leaves.len(), 2_usize.pow(max_depth as u32)); // size of leaves layer is 2_usize.pow(max_depth as u32).
    let paths: Vec<Vec<Index>> = leaves.into_iter()
        .map(
            |index| {
                // Checks all leaves conform to the initial value and not to a different value.
                let cipher_block = tree.get_cipher_block_by_index(index).unwrap();
                assert_eq!(cipher_block, custom_block);  // Test against a custom block.
                assert_ne!(cipher_block, different_custom_block);
                index
            }
        )
        .map(
            |index| {
                tree.get_indexes_path_to_root_by_index(index).unwrap()
            }
        )
        .collect();
    let are_different: bool = paths.iter().enumerate().fold((true, &vec![Index::from(0)]), | acc: (bool, &Vec<Index>), (i, path)| {
        assert_ne!(acc.1, path, "non equal {}", i);
        assert_eq!(acc.1.last().unwrap(), path.last().unwrap()); /// all paths conform to root.
        (acc.0 && path != acc.1, path)
    }).0;
    assert!(are_different);
    let _ = paths.into_iter()
        .map(
            |path| {
                path.into_iter()
                    .map( 
                        |index| {
                            tree.get_cipher_block_by_index(index).unwrap()
                        }
                     )
                     .collect()
            }
        )
        .map(
            |cipher_path| {
                assert_eq!( // all paths are initiated equal.
                    cipher_path,
                    [[171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171], [105, 159, 201, 79, 241, 236, 131, 241, 171, 245, 49, 3, 14, 50, 64, 3, 231, 117, 130, 152, 40, 22, 69, 36, 95, 124, 105, 132, 37, 165, 224, 231], [162, 66, 36, 51, 36, 74, 29, 162, 75, 60, 77, 177, 38, 220, 197, 147, 102, 111, 152, 54, 84, 3, 230, 170, 240, 127, 174, 1, 28, 130, 79, 9], [236, 70, 168, 219, 199, 251, 13, 165, 117, 59, 17, 243, 255, 4, 238, 107, 122, 42, 151, 155, 22, 128, 37, 212, 3, 148, 160, 255, 76, 242, 223, 89], [52, 250, 196, 184, 120, 29, 11, 129, 23, 70, 236, 69, 98, 54, 6, 244, 61, 241, 168, 185, 0, 159, 137, 197, 86, 78, 104, 2, 90, 111, 214, 4], [184, 177, 129, 15, 84, 196, 4, 137, 19, 9, 13, 120, 152, 55, 18, 189, 84, 205, 75, 174, 78, 35, 107, 225, 242, 148, 18, 35, 136, 171, 239, 107], [74, 1, 16, 67, 89, 76, 140, 2, 158, 198, 20, 25, 50, 197, 85, 185, 156, 70, 74, 183, 87, 52, 2, 122, 235, 150, 142, 216, 127, 213, 39, 92], [144, 2, 154, 203, 227, 37, 76, 99, 188, 157, 212, 168, 241, 228, 184, 226, 123, 68, 69, 187, 94, 90, 88, 151, 175, 146, 81, 236, 116, 79, 111, 104], [20, 137, 173, 94, 133, 206, 43, 108, 188, 207, 210, 242, 95, 141, 99, 209, 21, 255, 128, 25, 154, 251, 196, 236, 79, 111, 194, 72, 75, 248, 214, 144], [199, 149, 73, 74, 166, 98, 221, 1, 44, 93, 230, 197, 47, 10, 178, 142, 233, 19, 95, 232, 70, 7, 77, 98, 187, 120, 7, 207, 152, 116, 47, 217], [6, 132, 195, 134, 128, 128, 182, 236, 30, 89, 241, 70, 83, 117, 64, 179, 214, 48, 214, 19, 78, 179, 181, 24, 206, 83, 68, 184, 118, 10, 12, 178], [112, 5, 22, 23, 159, 4, 233, 224, 30, 189, 190, 41, 135, 230, 174, 184, 138, 212, 110, 223, 94, 234, 144, 48, 118, 239, 57, 50, 123, 165, 186, 139], [213, 173, 250, 186, 155, 60, 80, 24, 247, 210, 60, 212, 10, 236, 72, 190, 36, 236, 142, 167, 225, 248, 97, 3, 52, 144, 238, 53, 222, 84, 113, 110], [215, 217, 236, 242, 106, 206, 134, 76, 156, 5, 85, 70, 77, 50, 213, 30, 39, 104, 211, 78, 76, 122, 99, 84, 99, 5, 42, 5, 217, 30, 103, 32], [68, 173, 20, 144, 23, 157, 178, 132, 246, 250, 33, 216, 239, 251, 209, 186, 106, 48, 40, 4, 43, 150, 190, 155, 36, 159, 83, 141, 227, 245, 122, 133], [11, 121, 42, 233, 186, 63, 247, 200, 251, 140, 158, 71, 99, 38, 145, 147, 252, 24, 132, 29, 42, 102, 140, 64, 51, 236, 45, 140, 204, 109, 127, 88], [125, 200, 91, 118, 13, 230, 194, 25, 29, 82, 33, 109, 157, 220, 253, 209, 22, 164, 86, 216, 11, 195, 166, 39, 120, 59, 66, 24, 180, 197, 126, 167], [234, 147, 70, 82, 103, 201, 186, 242, 254, 236, 157, 228, 241, 85, 85, 172, 37, 4, 238, 212, 147, 144, 10, 192, 51, 187, 208, 168, 187, 52, 202, 99], [244, 96, 234, 249, 100, 250, 60, 212, 18, 150, 230, 14, 253, 191, 109, 215, 223, 84, 156, 120, 12, 63, 185, 67, 46, 23, 132, 168, 157, 248, 67, 2], [212, 73, 15, 77, 55, 76, 168, 164, 70, 133, 254, 148, 113, 197, 184, 219, 229, 140, 223, 253, 19, 211, 13, 154, 186, 21, 221, 41, 239, 185, 41, 48]]
                );
                assert_ne!(
                    cipher_path,
                    [[89, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171, 171], [105, 159, 201, 79, 241, 236, 131, 241, 171, 245, 49, 3, 14, 50, 64, 3, 231, 117, 130, 152, 40, 22, 69, 36, 95, 124, 105, 132, 37, 165, 224, 231], [162, 66, 36, 51, 36, 74, 29, 162, 75, 60, 77, 177, 38, 220, 197, 147, 102, 111, 152, 54, 84, 3, 230, 170, 240, 127, 174, 1, 28, 130, 79, 9], [236, 70, 168, 219, 199, 251, 13, 165, 117, 59, 17, 243, 255, 4, 238, 107, 122, 42, 151, 155, 22, 128, 37, 212, 3, 148, 160, 255, 76, 242, 223, 89], [52, 250, 196, 184, 120, 29, 11, 129, 23, 70, 236, 69, 98, 54, 6, 244, 61, 241, 168, 185, 0, 159, 137, 197, 86, 78, 104, 2, 90, 111, 214, 4], [184, 177, 129, 15, 84, 196, 4, 137, 19, 9, 13, 120, 152, 55, 18, 189, 84, 205, 75, 174, 78, 35, 107, 225, 242, 148, 18, 35, 136, 171, 239, 107], [74, 1, 16, 67, 89, 76, 140, 2, 158, 198, 20, 25, 50, 197, 85, 185, 156, 70, 74, 183, 87, 52, 2, 122, 235, 150, 142, 216, 127, 213, 39, 92], [144, 2, 154, 203, 227, 37, 76, 99, 188, 157, 212, 168, 241, 228, 184, 226, 123, 68, 69, 187, 94, 90, 88, 151, 175, 146, 81, 236, 116, 79, 111, 104], [20, 137, 173, 94, 133, 206, 43, 108, 188, 207, 210, 242, 95, 141, 99, 209, 21, 255, 128, 25, 154, 251, 196, 236, 79, 111, 194, 72, 75, 248, 214, 144], [199, 149, 73, 74, 166, 98, 221, 1, 44, 93, 230, 197, 47, 10, 178, 142, 233, 19, 95, 232, 70, 7, 77, 98, 187, 120, 7, 207, 152, 116, 47, 217], [6, 132, 195, 134, 128, 128, 182, 236, 30, 89, 241, 70, 83, 117, 64, 179, 214, 48, 214, 19, 78, 179, 181, 24, 206, 83, 68, 184, 118, 10, 12, 178], [112, 5, 22, 23, 159, 4, 233, 224, 30, 189, 190, 41, 135, 230, 174, 184, 138, 212, 110, 223, 94, 234, 144, 48, 118, 239, 57, 50, 123, 165, 186, 139], [213, 173, 250, 186, 155, 60, 80, 24, 247, 210, 60, 212, 10, 236, 72, 190, 36, 236, 142, 167, 225, 248, 97, 3, 52, 144, 238, 53, 222, 84, 113, 110], [215, 217, 236, 242, 106, 206, 134, 76, 156, 5, 85, 70, 77, 50, 213, 30, 39, 104, 211, 78, 76, 122, 99, 84, 99, 5, 42, 5, 217, 30, 103, 32], [68, 173, 20, 144, 23, 157, 178, 132, 246, 250, 33, 216, 239, 251, 209, 186, 106, 48, 40, 4, 43, 150, 190, 155, 36, 159, 83, 141, 227, 245, 122, 133], [11, 121, 42, 233, 186, 63, 247, 200, 251, 140, 158, 71, 99, 38, 145, 147, 252, 24, 132, 29, 42, 102, 140, 64, 51, 236, 45, 140, 204, 109, 127, 88], [125, 200, 91, 118, 13, 230, 194, 25, 29, 82, 33, 109, 157, 220, 253, 209, 22, 164, 86, 216, 11, 195, 166, 39, 120, 59, 66, 24, 180, 197, 126, 167], [234, 147, 70, 82, 103, 201, 186, 242, 254, 236, 157, 228, 241, 85, 85, 172, 37, 4, 238, 212, 147, 144, 10, 192, 51, 187, 208, 168, 187, 52, 202, 99], [244, 96, 234, 249, 100, 250, 60, 212, 18, 150, 230, 14, 253, 191, 109, 215, 223, 84, 156, 120, 12, 63, 185, 67, 46, 23, 132, 168, 157, 248, 67, 2], [212, 73, 15, 77, 55, 76, 168, 164, 70, 133, 254, 148, 113, 197, 184, 219, 229, 140, 223, 253, 19, 211, 13, 154, 186, 21, 221, 41, 239, 185, 41, 48]]
                );
                cipher_path
            }
        )
        .collect::<Vec<Vec<[u8; SIZE]>>>();
}

#[test]
fn verify_paths_for_merkletree_depth_20() {
    const SIZE: usize = 32;
    let max_depth = 19;
    let builder: builder::LeMerkBuilder<SIZE> = builder::LeMerkBuilder::<SIZE>::new();
    let custom_block = hex!("abababababababababababababababababababababababababababababababab");
    let different_custom_block = hex!("ababababababaffbabababababababababababababababababababababababab");
    let tree: LeMerkTree<SIZE> = builder
        .with_max_depth(max_depth)
        .with_initial_block(custom_block)  // A custom block.
        .try_build::<sha3::Sha3_256>()
        .expect("Unexpected build.");
    let leaves = tree.get_leaves_indexes();
    leaves.iter()
        .take(15)
        .for_each(
            |x| {
                let verified = tree.verify_path_to_root_by_index(*x).unwrap();
                assert_eq!(verified, tree.get_root_data().unwrap())
            }
        );

}

#[test]
fn set_and_update_merkletree_depth_20() {
    const SIZE: usize = 32;
    let max_depth = 19;
    let builder: builder::LeMerkBuilder<SIZE> = builder::LeMerkBuilder::<SIZE>::new();
    let custom_block = hex!("abababababababababababababababababababababababababababababababab");
    let different_custom_block = hex!("ababababababaffbabababababababababababababababababababababababab");
    let mut tree: LeMerkTree<SIZE> = builder
        .with_max_depth(max_depth)
        .with_initial_block(custom_block)  // A custom block.
        .try_build::<sha3::Sha3_256>()
        .expect("Unexpected build.");
    let original_root_data = tree.get_root_data();
    let leaves = tree.get_leaves_indexes();
    leaves.into_iter()
        .take(15)
        .for_each(
            |x| {
                let updated_root = tree.set_and_update(x, different_custom_block).unwrap();
                let verified = tree.verify_path_to_root_by_index(x).unwrap();
                assert_eq!(verified, tree.get_root_data().unwrap());
                assert_eq!(verified, updated_root);
            }
        );
    assert_ne!(tree.get_root_data(), original_root_data);
}

#[test]
fn set_and_update_last_15_merkletree_depth_20() {
    const SIZE: usize = 32;
    let max_depth = 19;
    let builder: builder::LeMerkBuilder<SIZE> = builder::LeMerkBuilder::<SIZE>::new();
    let custom_block = hex!("abababababababababababababababababababababababababababababababab");
    let different_custom_block = hex!("ababababababaffbabababababababababababababababababababababababab");
    let mut tree: LeMerkTree<SIZE> = builder
        .with_max_depth(max_depth)
        .with_initial_block(custom_block)  // A custom block.
        .try_build::<sha3::Sha3_256>()
        .expect("Unexpected build.");
    let original_root_data = tree.get_root_data();
    let leaves = tree.get_leaves_indexes();
    leaves.into_iter()
        .rev()
        .take(15)
        .for_each(
            |x| {
                let _ = tree.set_and_update(x, different_custom_block);
                let verified = tree.verify_path_to_root_by_index(x).unwrap();
                assert_eq!(verified, tree.get_root_data().unwrap())
            }
        );
    assert_ne!(tree.get_root_data(), original_root_data);
}

#[test]
fn set_verify_merkletree_depth_20() {
    const SIZE: usize = 32;
    let max_depth = 19;
    let builder: builder::LeMerkBuilder<SIZE> = builder::LeMerkBuilder::<SIZE>::new();
    let custom_block = hex!("abababababababababababababababababababababababababababababababab");
    let different_custom_block = hex!("ababababababaffbabababababababababababababababababababababababab");
    let mut tree: LeMerkTree<SIZE> = builder
        .with_max_depth(max_depth)
        .with_initial_block(custom_block)  // A custom block.
        .try_build::<sha3::Sha3_256>()
        .expect("Unexpected build.");
    let original_root_data = tree.get_root_data();
    let leaves = tree.get_leaves_indexes();
    leaves.into_iter()
        .take(15)
        .for_each(
            |x| {
                let mut virtual_node = tree.get_virtual_node_by_index(x).unwrap();
                let (updated_root, updated_proof) = tree.set_update_generate_proof(x, different_custom_block).unwrap();
                let (new_root, proof) = tree.generate_proof(x).unwrap();
                assert_eq!(updated_proof, proof);
                assert_eq!(updated_root, new_root);
                let mut i = 0;
                let mut visited = tree.get_cipher_block_by_index(x).unwrap();
                for node in proof {
                    if let Some(ancestor_index) = virtual_node.get_ancestor_index().unwrap() {
                        let ancestor_data = tree.get_cipher_block_by_index(ancestor_index).unwrap();
                        let mut output = [0_u8; SIZE];
                        hash_visit::<sha3::Sha3_256>(&visited, &node, &mut output);
                        assert_eq!(ancestor_data, output);
                        visited = output;
                        virtual_node = tree.get_virtual_node_by_index(ancestor_index).unwrap();
                        i+=1;
                    } else {
                        assert_eq!(visited, tree.get_root_data().unwrap());
                    };
                }
                let verified = tree.verify_path_to_root_by_index(x).unwrap();
                assert_eq!(verified, tree.get_root_data().unwrap());
            }
        );
    assert_ne!(tree.get_root_data(), original_root_data);
}