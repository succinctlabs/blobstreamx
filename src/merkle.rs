/// Source (tendermint-rs): https://github.com/informalsystems/tendermint-rs/blob/e930691a5639ef805c399743ac0ddbba0e9f53da/tendermint/src/merkle.rs#L32
use tendermint::merkle::{MerkleHash, Hash};
use sha2::{Sha256, Digest};

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

#[derive(Clone)]
struct Proof {
    total: i64,
    index: i64,
    leaf_hash: Vec<u8>,
    aunts: Vec<Vec<u8>>,
}

#[derive(Clone)]
struct ProofNode {
    hash: Vec<u8>,
    parent: Option<Box<ProofNode>>,
    left: Option<Box<ProofNode>>,
    right: Option<Box<ProofNode>>,
}

impl Proof {
    fn new(total: i64, index: i64, leaf_hash: Vec<u8>, aunts: Vec<Vec<u8>>) -> Self {
        Proof { total, index, leaf_hash, aunts }
    }
}

impl ProofNode {
    fn new(hash: Vec<u8>, parent: Option<Box<ProofNode>>, left: Option<Box<ProofNode>>, right: Option<Box<ProofNode>>) -> Self {
        ProofNode { hash, parent, left, right }
    }

    fn flatten_aunts(&self) -> Vec<Vec<u8>> {
        let mut inner_hashes = Vec::new();
        let mut current_node = self.parent.as_ref();

        while let Some(node) = current_node {
            match (node.left.as_ref(), node.right.as_ref()) {
                (Some(left_node), _) => inner_hashes.push(left_node.hash.clone()),
                (_, Some(right_node)) => inner_hashes.push(right_node.hash.clone()),
                _ => {}
            }

            current_node = node.parent.as_ref();
        }

        inner_hashes
    }
}

fn proofs_from_byte_slices(items: Vec<Vec<u8>>) -> (Vec<u8>, Vec<Proof>) {
    let (trails, root) = trails_from_byte_slices(items.clone());
    let root_hash = root.hash.clone();
    let mut proofs = Vec::new();

    for (i, trail) in trails.into_iter().enumerate() {
        proofs.push(Proof::new(
            items.len() as i64,
            i as i64,
            trail.hash.clone(),
            trail.flatten_aunts(),
        ));
    }

    (root_hash, proofs)
}

fn trails_from_byte_slices(items: Vec<Vec<u8>>) -> (Vec<ProofNode>, ProofNode) {
    match items.len() {
        0 => {
            let node = ProofNode::new(empty_hash(), None, None, None);
            (vec![], node)
        }
        1 => {
            let node = ProofNode::new(leaf_hash(&items[0]), None, None, None);
            (vec![node.clone()], node)
        }
        _ => {
            let k = get_split_point(items.len());
            let (lefts, left_root) = trails_from_byte_slices(items[..k].to_vec());
            let (rights, right_root) = trails_from_byte_slices(items[k..].to_vec());

            let root_hash = inner_hash(&left_root.hash, &right_root.hash);
            let root = ProofNode::new(
                root_hash,
                None,
                Some(Box::new(left_root)),
                Some(Box::new(right_root)),
            );

            let trails = [lefts, rights].concat();

            (trails, root)
        }
    }
}

fn get_split_point(length: usize) -> usize {
    if length < 1 {
        panic!("Trying to split a tree with size < 1")
    }
    let bitlen = (length as f64).log2() as usize;
    let k = 1 << bitlen;
    if k == length {
        k >> 1
    } else {
        k
    }
}

fn empty_hash() -> Vec<u8> {
    Sha256::digest(&[]).to_vec()
}

fn leaf_hash(leaf: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update([0x00].as_ref());
    hasher.update(leaf);
    hasher.finalize().to_vec()
}

fn inner_hash(left: &[u8], right: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update([0x01].as_ref());
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().to_vec()
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
