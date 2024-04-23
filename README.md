# LeMerk
## A custom Merkle Tree Implementation built on Rust.

## Example usage

The constructor for LeMerkTree is LeMerkBuilder:

```
    use hex_literal::hex;
    use lemerk::LeMerkTree;
    use lemerk::builder::LeMerkBuilder;

    const SIZE: usize = 32;
    let max_depth = 7;
    let mut builder: LeMerkBuilder<SIZE> = LeMerkBuilder::<SIZE>::new();
    let custom_block = hex!("abababababababababababababababababababababababababababababababab");
    let different_custom_block = hex!("ababababababaffbabababababababababababababababababababababababab");
    let mut tree: LeMerkTree<SIZE> = builder
        .with_max_depth(max_depth)
        .with_initial_block(custom_block)  // A custom block.
        .try_build::<sha3::Sha3_256>()
        .expect("Unexpected build.");
    let original_root_data = tree.get_root_data().unwrap();
    let leaves = tree.get_leaves_indexes();

    let leaf_index = leaves[0];
    let (updated_root, updated_proof) = tree.set_update_generate_proof(leaf_index, different_custom_block).unwrap();
    let new_root = tree.verify_proof(leaf_index, updated_proof).unwrap().unwrap();
    assert_eq!(new_root, tree.get_root_data().unwrap());
    assert_eq!(new_root, updated_root);
    assert_ne!(new_root, original_root_data);
    
```

## Tests
```
cargo test --release
```