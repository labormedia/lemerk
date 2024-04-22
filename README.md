# LeMerk
## A custom Merkle Tree Implementation.

## Example usage

The constructor for LeMerkTree is LeMerkBuilder:

```
    const SIZE: usize = 32;
    let max_depth = 19;
    let mut builder: builder::LeMerkBuilder<SIZE> = builder::LeMerkBuilder::<SIZE>::new();
    let custom_block = hex!("abababababababababababababababababababababababababababababababab");
    let different_custom_block = hex!("ababababababaffbabababababababababababababababababababababababab");
    let mut tree: LeMerkTree<SIZE> = builder
        .with_max_depth(max_depth)
        .with_initial_block(custom_block)  // A custom block.
        .try_build::<sha3::Sha3_256>()
        .expect("Unexpected build.");
    let original_root_data = tree.get_root_data();
    let leaves = tree.get_leaves_indexes();

    let leaf_index = leaves[0]
    let (updated_root, updated_proof) = tree.set_update_generate_proof(x, different_custom_block).unwrap();
```

## Tests
```
cargo test --release
```