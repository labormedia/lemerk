# LeMerk
## A custom Merkle Tree Implementation.

## Example usage

The constructor for LeMerkTree is LeMerkBuilder:

```
    use hex_literal::hex;
    use lemerk::LeMerkTree;
    use lemerk::builder::LeMerkBuilder;

    const SIZE: usize = 32;
    let max_depth = 7;
    let mut builder: LeMerkBuilder<SIZE> = LeMerkBuilder::<SIZE>::new();
    let custom_block = hex!bababababababababababababababababababababababababababababababab");
    let different_custom_block = hex!babababababaffbabababababababababababababababababababababababab");
    let mut tree: LeMerkTree<SIZE> = builder
        .with_max_depth(max_depth)
        .with_initial_block(custom_block)  // A custom block.
        .try_build::<sha3::Sha3_256>()
        .expect("Unexpected build.");
    let original_root_data = tree.get_root_data().unwrap();
    let leaves = tree.get_leaves_indexes(
    let leaf_index = leaves[0];
    let (updated_root, updated_proof) = tree.set_update_generate_proofaf_index, different_custom_block).unwrap();
    assert_ne!(original_root_data, updated_root);
    
```

## Tests
```
cargo test --release
```