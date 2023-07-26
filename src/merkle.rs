/// Source (tendermint-rs): https://github.com/informalsystems/tendermint-rs/blob/e930691a5639ef805c399743ac0ddbba0e9f53da/tendermint/src/merkle.rs#L32
use tendermint::merkle::{MerkleHash, Hash};

/// Compute leaf hashes for arbitrary byte vectors.
/// The leaves of the tree are the bytes of the given byte vectors in
/// the given order.
pub fn hash_all_leaves<H>(byte_vecs: &[impl AsRef<[u8]>]) -> Vec<Hash>
where
    H: MerkleHash + Default,
{
    let mut hasher = H::default();
    let hashed_leaves = byte_vecs
        .iter()
        .map(|b| hasher.leaf_hash(b.as_ref()))
        .collect();
    hashed_leaves
}

#[cfg(test)]
pub(crate) mod tests {
    use tendermint::merkle::simple_hash_from_byte_vectors;
    use sha2::Sha256;
    use subtle_encoding::hex;

    #[test]
    fn test_validator_inclusion() {
        // These are test cases generated from querying `cosmos-hub`
        // for the validator set at height 0 for validator 0.

        // let root_hash = [125u8, 130, 148, 137, 132, 154, 188, 169, 153, 181, 72, 1, 150, 95, 7, 68, 137, 114, 181, 223, 226, 151, 52, 72, 170, 185, 171, 167, 154, 96, 187, 240];
        // Total: 180
        let leaf_root_hex = "395aa064aa4c29f7010acfe3f25db9485bbd4b91897b6ad7ad547639252b4d56";
        let leaf_string = "L123456";

        let leaf_root = &hex::decode(leaf_root_hex).unwrap();
        let leaf_tree: Vec<Vec<u8>> = vec![leaf_string.as_bytes().to_vec(); 1];

        let root = simple_hash_from_byte_vectors::<Sha256>(&leaf_tree);
        assert_eq!(leaf_root, &root);
    }

    #[test]
    fn test_multiple_validator_inclusion() {
        // These are test cases generated from generating a random set of validators with a byte length of 38.

        // Serde JSON
        let leaf_root_hex = "5541a94a9cf19e568401a2eed59f4ac8118c945d37803632aad655c6ee4f3ed6";

        // JSON string
        let validators = vec![
            "de6ad0941095ada2a7996e6a888581928203b8b69e07ee254d289f5b9c9caea193c2ab01902d",
            "92fbe0c52937d80c5ea643c7832620b84bfdf154ec7129b8b471a63a763f2fe955af1ac65fd3",
            "e902f88b2371ff6243bf4b0ebe8f46205e00749dd4dad07b2ea34350a1f9ceedb7620ab913c2",
        ];

        // Process the JSON value
        for validator in &validators {
            println!("Validator: {}", validator);
        }

        let bytes_vec: Vec<Vec<u8>> = validators.iter().map(|s| hex::decode(s).unwrap()).collect();

        let leaf_root = &hex::decode(leaf_root_hex).unwrap();
        let leaf_tree: Vec<Vec<u8>> = bytes_vec;

        let root = simple_hash_from_byte_vectors::<Sha256>(&leaf_tree);
        assert_eq!(leaf_root, &root);
    }
}
