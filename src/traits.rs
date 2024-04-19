pub trait SizedTree {
    fn get_max_index(&self) -> usize;
    fn get_max_depth(&self) -> usize;
}