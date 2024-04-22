/// SizedTree trait is used by VirtualNode implementation to get the properties of the tree that is being assessed against, without the need to nest it to a LeMerkTree.
pub trait SizedTree {
    fn get_max_index(&self) -> usize;
    fn get_max_depth(&self) -> usize;
}