use tendermint::abci::types::Validator;
/// Source (tendermint-rs): https://github.com/informalsystems/tendermint-rs/blob/e930691a5639ef805c399743ac0ddbba0e9f53da/tendermint/src/merkle.rs#L32
use tendermint::merkle::{MerkleHash, Hash};
use tendermint_proto::Protobuf;
use tendermint_proto::types::Data;
use tendermint_proto::{
    types::Commit as RawCommit,
    types::BlockId as RawBlockId,
    version::Consensus as RawConsensusVersion,
    types::SimpleValidator as RawSimpleValidator, consensus::Vote as RawVote,
    types::CommitSig as RawCommitSig,
    
};
use tendermint::{
    vote::{ValidatorIndex, Vote},
    block::{Commit, CommitSig},
};
use serde::{Deserialize, Serialize, Deserializer};
use tendermint::block::Header;
use tendermint::validator::{Set as ValidatorSet, Info, SimpleValidator};
use tendermint::vote::Power;
use sha2::{Sha256, Digest};
use subtle_encoding::hex;
use std::borrow::BorrowMut;
use std::rc::Rc;
use std::cell::RefCell;

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
        .map(|b| leaf_hash::<Sha256>(b.as_ref()))
        .collect();
    hashed_leaves
}

// Note: total_voting_power seems to be missing from celestia testnet nodes can use ValidatorSet once fixed
/// Validator set contains a vector of validators
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct TempValidatorSet {
    validators: Vec<Info>,
    proposer: Option<Info>,
    total_voting_power: Option<Power>
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[non_exhaustive]
struct TempSignedBlock
{
    /// Block header
    pub header: Header,

    /// Transaction data
    pub data: Data,

    /// Commit
    pub commit: Commit,

    /// Validator set
    pub validator_set: TempValidatorSet,

}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[non_exhaustive]
struct SignedBlock
{
    /// Block header
    pub header: Header,

    /// Transaction data
    pub data: Data,

    /// Commit
    pub commit: Commit,

    /// Validator set
    pub validator_set: ValidatorSet,

}

// Note: Matches the implementation in tendermint-rs, need to add PR to tendermint-rs to support proofs
// https://github.com/tendermint/tendermint/blob/35581cf54ec436b8c37fabb43fdaa3f48339a170/crypto/merkle/proof.go#L35-L236
#[derive(Clone)]
struct Proof {
    total: u64,
    index: u64,
    leaf_hash: Hash,
    aunts: Vec<Hash>,
}

#[derive(Clone)]
pub struct ProofNode {
    pub hash: Hash,
    pub left: Option<Rc<RefCell<ProofNode>>>,
    pub right: Option<Rc<RefCell<ProofNode>>>,
    pub parent: Option<Rc<RefCell<ProofNode>>>,
}

impl Proof {
    fn new(total: u64, index: u64, leaf_hash: Hash, aunts: Vec<Hash>) -> Self {
        Proof { total, index, leaf_hash, aunts }
    }

    fn compute_root_hash(&self) -> Option<Hash> {
        return compute_hash_from_aunts(self.index, self.total, self.leaf_hash, self.aunts.clone())
    }

    fn verify(&self, root_hash: &Hash, leaf: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
        let leaf_hash = leaf_hash::<Sha256>(leaf);
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
    fn new(hash: Hash, parent: Option<Rc<RefCell<ProofNode>>>, left: Option<Rc<RefCell<ProofNode>>>, right: Option<Rc<RefCell<ProofNode>>>) -> Self {
        ProofNode { hash, parent, left, right }
    }

    fn flatten_aunts(&self) -> Vec<Hash> {
        let mut inner_hashes = Vec::new();
        let mut current_node = Some(Rc::new(RefCell::new(self.clone())));

        while let Some(node) = current_node {
            // Separate this into two steps to avoid holding onto a borrow across loop iterations
            let (left, right) = {
                let node_borrowed = node.borrow();
                (node_borrowed.left.clone(), node_borrowed.right.clone())
            };
    
            match (&left, &right) {
                (Some(left_node), _) => inner_hashes.push(left_node.borrow().hash.clone()),
                (_, Some(right_node)) => inner_hashes.push(right_node.borrow().hash.clone()),
                _ => {}
            }
    
            // Now update current_node
            current_node = node.borrow().parent.clone();
        }

        inner_hashes
    }
}

fn compute_hash_from_aunts(index: u64, total: u64, leaf_hash: Hash, inner_hashes: Vec<Hash>) -> Option<Hash> {
    let aunts_hex: Vec<String> = inner_hashes.iter().map(|a| String::from_utf8(hex::encode(a)).unwrap()).collect();
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
                    Some(hash) => return Some(inner_hash::<Sha256>(hash, inner_hashes[inner_hashes.len()-1])),
                }
            }
            let right_hash = compute_hash_from_aunts(index-num_left, total-num_left, leaf_hash, inner_hashes[..inner_hashes.len()-1].to_vec());
            match right_hash {
                None => return None,
                Some(hash) => return Some(inner_hash::<Sha256>(inner_hashes[inner_hashes.len()-1], hash)),
            }
        }
    }
}

fn proofs_from_byte_slices(items: Vec<Vec<u8>>) -> (Hash, Vec<Proof>) {
    let (trails, root) = trails_from_byte_slices(items.clone());
    let root_hash = root.borrow().hash;
    let mut proofs = Vec::new();

    for (i, trail) in trails.into_iter().enumerate() {
        proofs.push(Proof::new(
            items.len() as u64,
            i as u64,
            trail.borrow().hash,
            trail.borrow().flatten_aunts(),
        ));
    }

    (root_hash, proofs)
}

// Create trail from byte slice to root
fn trails_from_byte_slices(items: Vec<Vec<u8>>) -> (Vec<Rc<RefCell<ProofNode>>>, Rc<RefCell<ProofNode>>) {
    match items.len() {
        0 => {
            let node = ProofNode::new(empty_hash(), None, None, None);
            (vec![], Rc::new(RefCell::new(node)))
        }
        1 => {
            let node = Rc::new(RefCell::new(ProofNode::new(leaf_hash::<Sha256>(&items[0]), None, None, None)));

            (vec![Rc::clone(&node)], Rc::clone(&node))
        }
        _ => {
            let k = get_split_point(items.len());
            let (lefts, left_root) = trails_from_byte_slices(items[..k].to_vec());
            let (rights, right_root) = trails_from_byte_slices(items[k..].to_vec());

            let root_hash = inner_hash::<Sha256>(left_root.borrow().hash, right_root.borrow().hash);
            let root = Rc::new(RefCell::new(ProofNode::new(
                root_hash,
                None,
                None,
                None,
            )));

            {
                let mut left_root_borrowed = (*left_root).borrow_mut();
                left_root_borrowed.parent = Some(Rc::clone(&root));
                left_root_borrowed.right = Some(Rc::clone(&right_root));
            }
            {
                let mut right_root_borrowed = (*right_root).borrow_mut();
                right_root_borrowed.parent = Some(Rc::clone(&root));
                right_root_borrowed.left = Some(Rc::clone(&left_root));
            }

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

fn leaf_hash<H>(leaf: &[u8]) -> Hash
where 
    H: MerkleHash + Default, {
    let mut hasher = H::default();
    hasher.leaf_hash(leaf)
}

fn inner_hash<H>(left: Hash, right: Hash) -> Hash
where 
    H: MerkleHash + Default, {
    let mut hasher = H::default();
    hasher.inner_hash(left, right)
}

fn generate_proofs_from_header(h: &Header) -> (Hash, Vec<Proof>) {

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

    proofs_from_byte_slices(fields_bytes)
}

// Gets the vote struct: https://github.com/informalsystems/tendermint-rs/blob/c2b5c9e01eab1c740598aa14375a7453f3bfa436/light-client-verifier/src/operations/voting_power.rs#L202-L238
fn non_absent_vote(
    commit_sig: &CommitSig,
    validator_index: ValidatorIndex,
    commit: &Commit,
) -> Option<Vote> {
    // Cast the raw commit sig to a commit sig
    let (validator_address, timestamp, signature, block_id) = match commit_sig {
        CommitSig::BlockIdFlagAbsent { .. } => return None,
        CommitSig::BlockIdFlagCommit {
            validator_address,
            timestamp,
            signature,
        } => (
            validator_address,
            timestamp,
            signature,
            Some(commit.block_id),
        ),
        CommitSig::BlockIdFlagNil {
            validator_address,
            timestamp,
            signature,
        } => (validator_address, timestamp, signature, None),
    };

    Some(Vote {
        vote_type: tendermint::vote::Type::Precommit,
        height: commit.height,
        round: commit.round,
        block_id,
        timestamp: Some(*timestamp),
        validator_address: *validator_address,
        validator_index,
        signature: signature.clone(),
        extension: Default::default(),
        extension_signature: None,
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use tendermint::block::{CommitSig, self};
    use tendermint::merkle::simple_hash_from_byte_vectors;
    use sha2::Sha256;
    use subtle_encoding::hex;
    use tendermint_proto::types::CanonicalVote as RawCanonicalVote;
    use tendermint_proto::{
        Protobuf,
        types::SimpleValidator as RawSimpleValidator, consensus::Vote as RawVote,
        types::CommitSig as RawCommitSig, types::Commit as RawCommit,
    };
    use tendermint::Signature;
    use tendermint::crypto::default::signature::Verifier;
    use tendermint::crypto::signature::Verifier as SignatureVerifier;
    use tendermint::crypto::signature;
    use tendermint::vote::{SignedVote, CanonicalVote};

    use crate::merkle::{generate_proofs_from_header, TempSignedBlock};
    use tendermint::validator::{Set as ValidatorSet, Info, SimpleValidator};
    use tendermint::{
        vote::{ValidatorIndex, Vote},
        block::Commit,
    };

    use super::{proofs_from_byte_slices, SignedBlock, non_absent_vote};

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
    fn test_generate_validator_hash_proof() {
        // Generate test cases from Celestia block:
        let temp_block = TempSignedBlock::from(
            serde_json::from_str::<TempSignedBlock>(include_str!("./scripts/signed_celestia_block.json")).unwrap()
        );
        
        // Cast to SignedBlock
        let block = SignedBlock {
            header: temp_block.header,
            data: temp_block.data,
            commit: temp_block.commit,
            validator_set: ValidatorSet::new(
                temp_block.validator_set.validators,
                temp_block.validator_set.proposer,
            )
        };

        for validator in block.validator_set.validators() {
            println!("Validator: {:?}", validator);
            let encoded_bytes = Protobuf::<RawSimpleValidator>::encode_vec(SimpleValidator::from(validator));
            println!("Encoded Validator (Hex): {:?}", String::from_utf8(hex::encode(encoded_bytes)));
        }

        let validator_hash = block.validator_set.hash();
        
        // Check that the computed hash and validators_hash match
        assert_eq!(validator_hash, block.header.validators_hash);

        
    }

    #[test]
    fn test_verify_signatures() {
        // Generate test cases from Celestia block:
        let temp_block = TempSignedBlock::from(
            serde_json::from_str::<TempSignedBlock>(include_str!("./scripts/signed_celestia_block.json")).unwrap()
        );
        
        // Cast to SignedBlock
        let block = SignedBlock {
            header: temp_block.header,
            data: temp_block.data,
            commit: temp_block.commit,
            validator_set: ValidatorSet::new(
                temp_block.validator_set.validators,
                temp_block.validator_set.proposer,
            )
        };

        // Source: https://github.com/informalsystems/tendermint-rs/blob/c2b5c9e01eab1c740598aa14375a7453f3bfa436/light-client-verifier/src/operations/voting_power.rs#L139-L198
        // Verify each of the signatures of the non_absent_votes
        // Verify signatures
        let non_absent_votes = block.commit.signatures.iter().enumerate().flat_map(|(idx, signature)| {
            non_absent_vote(
                signature,
                ValidatorIndex::try_from(idx).unwrap(),
                &block.commit,
            )
            .map(|vote| (signature, vote))
        });

        let mut min_sign_bytes_len = 1000000;
        let mut max_sign_bytes_len = 0;

        for (signature, vote) in non_absent_votes {
            let validator = match block.validator_set.validator(vote.validator_address) {
                Some(validator) => validator,
                None => continue, // Cannot find matching validator, so we skip the vote
            };

            println!("verified");

            // Cast the vote into a signedVote struct (which is used to get the signed bytes)
            let signed_vote =
                SignedVote::from_vote(vote.clone(), block.header.chain_id.clone())
                    .expect("missing signature");
            
            // Get the encoded signed vote bytes
            // https://github.com/celestiaorg/celestia-core/blob/main/proto/tendermint/types/canonical.proto#L30-L37
            let sign_bytes = signed_vote.sign_bytes();
            // let mut buf = Vec::new();
            // vote.to_signable_bytes(block.header.chain_id.clone(), &mut buf).expect("failed to encode vote");


            if (sign_bytes.len() < min_sign_bytes_len) {
                min_sign_bytes_len = sign_bytes.len();
            }
            if (sign_bytes.len() > max_sign_bytes_len) {
                max_sign_bytes_len = sign_bytes.len();
            }

            // // Similar to encoding the vote: https://github.com/informalsystems/tendermint-rs/blob/c2b5c9e01eab1c740598aa14375a7453f3bfa436/tendermint/src/vote.rs#L267-L271
            // let decoded_vote: CanonicalVote = Protobuf::<RawCanonicalVote>::decode_length_delimited_vec(&sign_bytes).expect("failed to decode sign_bytes");

            // Verify that the message signed is in fact the sign_bytes
            validator.verify_signature::<tendermint::crypto::default::signature::Verifier>(&sign_bytes, signed_vote.signature()).expect("invalid signature");

            // TODO: Break out of the loop when we have enough voting power.
            // See https://github.com/informalsystems/tendermint-rs/issues/235
        }        

        let validator_hash = block.validator_set.hash();
        
        // Check that the computed hash and validators_hash match
        assert_eq!(validator_hash, block.header.validators_hash);

        
    }

    #[test]
    fn test_verify_validator_hash_from_root_proof() {
        // Generate test cases from Celestia block:
        let block = tendermint::Block::from(
            serde_json::from_str::<tendermint::block::Block>(include_str!("./scripts/celestia_block.json")).unwrap()
        );
        
        let (root_hash, proofs) = generate_proofs_from_header(&block.header);

        // Verify validator proof
        proofs[7].verify(&root_hash, &block.header.validators_hash.encode_vec()).unwrap();
        
    }
}
