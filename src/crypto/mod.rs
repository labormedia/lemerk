use sha3::Digest;

pub fn data_hash<D: Digest>(data: &[u8], output: &mut [u8]) {
    let mut hasher = D::new();
    hasher.update(data);
    output.copy_from_slice(&hasher.finalize());
}

pub fn hash_visit<D: Digest>(left: &[u8], right: &[u8], output: &mut [u8]) {
    let mut hasher = D::new();
    hasher.update(left);
    hasher.update(right);
    output.copy_from_slice(&hasher.finalize());
}

#[test]
fn test_data_hash() {
    let value = "hello world".as_bytes();
    let mut buffer = [0_u8;32];
    data_hash::<sha3::Sha3_256>(value, &mut buffer);
    assert_eq!(buffer,[100, 75, 204, 126, 86, 67, 115, 4, 9, 153, 170, 200, 158, 118, 34, 243, 202, 113, 251, 161, 217, 114, 253, 148, 163, 28, 59, 251, 242, 78, 57, 56]);
}

#[test]
fn test_preconcatenated_data_hash() {
    let value = [1_u8;64];
    let mut buffer = [0_u8;32];
    data_hash::<sha3::Sha3_256>(&value, &mut buffer);
    assert_eq!(buffer,[128, 53, 242, 62, 238, 50, 183, 173, 214, 12, 161, 141, 29, 27, 75, 79, 147, 94, 241, 23, 108, 49, 146, 107, 179, 81, 183, 109, 129, 9, 133, 244]);
}

#[test]
fn test_hash_visit() {
    let initial_value = [1_u8;32];
    let mut buffer = [0_u8;32];
    hash_visit::<sha3::Sha3_256>(&initial_value, &initial_value, &mut buffer);

    assert_eq!(buffer,[128, 53, 242, 62, 238, 50, 183, 173, 214, 12, 161, 141, 29, 27, 75, 79, 147, 94, 241, 23, 108, 49, 146, 107, 179, 81, 183, 109, 129, 9, 133, 244]);
}