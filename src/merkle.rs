/// Source (tendermint-rs): https://github.com/informalsystems/tendermint-rs/blob/e930691a5639ef805c399743ac0ddbba0e9f53da/tendermint/src/merkle.rs#L32
use tendermint::merkle::{MerkleHash, Hash};
use tendermint_proto::Protobuf;
use tendermint_proto::{
    types::BlockId as RawBlockId,
    version::Consensus as RawConsensusVersion,
};
use tendermint::block::Header;
use sha2::{Sha256, Digest};
use subtle_encoding::hex;

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
    total: u64,
    index: u64,
    leaf_hash: Hash,
    aunts: Vec<Hash>,
}

#[derive(Clone)]
struct ProofNode {
    hash: Hash,
    parent: Option<Box<ProofNode>>,
    left: Option<Box<ProofNode>>,
    right: Option<Box<ProofNode>>,
}

impl Proof {
    fn new(total: u64, index: u64, leaf_hash: Hash, aunts: Vec<Hash>) -> Self {
        Proof { total, index, leaf_hash, aunts }
    }

    fn compute_root_hash(&self) -> Option<Hash> {
        return compute_hash_from_aunts(self.index, self.total, self.leaf_hash, self.aunts.clone())
    }

    fn verify(&self, root_hash: &Hash, leaf: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
        let leaf_hash = leaf_hash(leaf);
        if self.total < 0 {
            return Err("proof total must be positive".into());
        }
        if self.index < 0 {
            return Err("proof index cannot be negative".into());
        }
        if self.leaf_hash != leaf_hash {
            return Err(format!("invalid leaf hash: wanted {:?} got {:?}", hex::encode(leaf_hash), hex::encode(self.leaf_hash)).into());
        }
        let computed_hash = self.compute_root_hash().expect("failed to compute root hash");
        if computed_hash != *root_hash {
            return Err(format!("invalid root hash: wanted {:?} got {:?}", hex::encode(root_hash), hex::encode(computed_hash)).into());
        }
        Ok(())
    }
}

impl ProofNode {
    fn new(hash: Hash, parent: Option<Box<ProofNode>>, left: Option<Box<ProofNode>>, right: Option<Box<ProofNode>>) -> Self {
        ProofNode { hash, parent, left, right }
    }

    fn flatten_aunts(&self) -> Vec<Hash> {
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

fn compute_hash_from_aunts(index: u64, total: u64, leaf_hash: Hash, inner_hashes: Vec<Hash>) -> Option<Hash> {
    println!("Index: {:?}", index);
    println!("Total: {:?}", total);
    println!("Leaf Hash: {:?}", String::from_utf8(hex::encode(leaf_hash)));
    println!("Inner Hashes: {:?}", inner_hashes);
    if index >= total || index < 0 || total <= 0 {
        return None;
    }
    match total {
        0 => panic!("Cannot call compute_hash_from_aunts() with 0 total"),
        1 => {
            if !inner_hashes.is_empty() {
                return None;
            }
            return Some(leaf_hash);
        },
        _ => {
            if inner_hashes.is_empty() {
                return None;
            }
            let num_left = get_split_point(total as usize) as u64;
            if index < num_left {
                let left_hash = compute_hash_from_aunts(index, num_left, leaf_hash, inner_hashes[..inner_hashes.len()-1].to_vec());
                match left_hash {
                    None => return None,
                    Some(hash) => return Some(inner_hash(&hash, &inner_hashes[inner_hashes.len()-1])),
                }
            }
            let right_hash = compute_hash_from_aunts(index-num_left, total-num_left, leaf_hash, inner_hashes[..inner_hashes.len()-1].to_vec());
            match right_hash {
                None => return None,
                Some(hash) => return Some(inner_hash(&inner_hashes[inner_hashes.len()-1], &hash)),
            }
        }
    }
}

fn proofs_from_byte_slices(items: Vec<Vec<u8>>) -> (Hash, Vec<Proof>) {
    let (trails, root) = trails_from_byte_slices(items.clone());
    let root_hash = root.hash.clone();
    let mut proofs = Vec::new();

    for (i, trail) in trails.into_iter().enumerate() {
        proofs.push(Proof::new(
            items.len() as u64,
            i as u64,
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
            let (lefts, mut left_root) = trails_from_byte_slices(items[..k].to_vec());
            let (rights, mut right_root) = trails_from_byte_slices(items[k..].to_vec());

            let root_hash = inner_hash(&left_root.hash, &right_root.hash);
            let root = ProofNode::new(
                root_hash,
                None,
                None,
                None
            );

            left_root.parent = Some(Box::new(root.clone()));
            left_root.right = Some(Box::new(right_root.clone()));
            right_root.parent = Some(Box::new(root.clone()));
            right_root.left = Some(Box::new(left_root.clone()));

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

fn empty_hash() -> Hash {
    Sha256::digest(&[]).to_vec().try_into().expect("slice with incorrect length")
}

fn leaf_hash(leaf: &[u8]) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update([0x00].as_ref());
    hasher.update(leaf);
    hasher.finalize().to_vec().try_into().expect("slice with incorrect length")
}

fn inner_hash(left: &[u8], right: &[u8]) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update([0x01].as_ref());
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().to_vec().try_into().expect("slice with incorrect length")
}

fn generate_val_hash_proof(h: Header) -> (Hash, Vec<Proof>) {
    
    println!("Header Hash: {:?}", h.hash());

    // println!("Length of height: {:?}", h.height.encode_vec().len().to_string());

    let fields_bytes = vec![
        Protobuf::<RawConsensusVersion>::encode_vec(h.version),
        h.chain_id.clone().encode_vec(),
        h.height.encode_vec(),
        h.time.encode_vec(),
        Protobuf::<RawBlockId>::encode_vec(h.last_block_id.unwrap_or_default()),
        h.last_commit_hash.unwrap_or_default().encode_vec(),
        h.data_hash.unwrap_or_default().encode_vec(),
        h.validators_hash.encode_vec(),
        h.next_validators_hash.encode_vec(),
        h.consensus_hash.encode_vec(),
        h.app_hash.clone().encode_vec(),
        h.last_results_hash.unwrap_or_default().encode_vec(),
        h.evidence_hash.unwrap_or_default().encode_vec(),
        h.proposer_address.encode_vec(),
    ];

    // let hash = h.hash().as_bytes().try_into().expect("Failed to unwrap");
    // println!("Header Hash as Hex: {:?}", String::from_utf8(subtle_encoding::hex::encode(hash)).unwrap());


    let (root_hash, proofs) = proofs_from_byte_slices(fields_bytes);
    println!("Validator Hash (expected): {:?}", String::from_utf8(hex::encode(h.validators_hash)).unwrap());

    println!("Root Hash: {:?}", String::from_utf8(hex::encode(root_hash)).unwrap());
    println!("Validator Hash: {:?}", String::from_utf8(hex::encode(proofs[7].clone().leaf_hash)).unwrap());
    // Use map to format the aunts as hex strings
    let aunts = proofs[7].clone().aunts;
    let aunts_hex: Vec<String> = aunts.iter().map(|a| String::from_utf8(hex::encode(a)).unwrap()).collect();
    println!("Aunts: {:?}", aunts_hex);

    proofs[7].verify(&root_hash, &h.validators_hash.encode_vec()).unwrap();
    
    // for val in h.validators.iter() {
    //     val_hash.push(val.address.as_bytes().to_vec());
    // }
    // proofs_from_byte_slices(h)
    (root_hash, vec![])
}

#[cfg(test)]
pub(crate) mod tests {
    use tendermint::merkle::simple_hash_from_byte_vectors;
    use sha2::Sha256;
    use subtle_encoding::hex;

    use crate::merkle::generate_val_hash_proof;

    use super::proofs_from_byte_slices;

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

    #[test]
    fn test_proofs_from_byte_slices() {
        // Generate test cases from Celestia block:
        let block = tendermint::Block::from(
            serde_json::from_str::<tendermint::block::Block>(include_str!("./scripts/celestia_block.json")).unwrap()
        );
        
        // println!("Block: {:?}", block);

        generate_val_hash_proof(block.header);

        
    }
}
