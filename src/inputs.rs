/// Source (tendermint-rs): https://github.com/informalsystems/tendermint-rs/blob/e930691a5639ef805c399743ac0ddbba0e9f53da/tendermint/src/merkle.rs#L32
use crate::merkle::{generate_proofs_from_header, non_absent_vote, SignedBlock, TempSignedBlock};
use crate::validator::VALIDATOR_SET_SIZE_MAX;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::cell::RefCell;
use std::rc::Rc;
use subtle_encoding::hex;
use tendermint::PublicKey;
use tendermint::{
    block::Header,
    block::{Commit, CommitSig},
    merkle::{Hash, MerkleHash},
    validator::{Info, Set as ValidatorSet},
    vote::{Power, SignedVote},
    vote::{ValidatorIndex, Vote},
};
use tendermint::crypto::ed25519::VerificationKey;
use tendermint::Signature;
use tendermint_proto::Protobuf;

#[derive(Debug, Clone)]
pub struct Validator {
    pub pubkey: VerificationKey,
    pub signature: Signature,
    pub message: Vec<u8>,
    pub message_byte_length: u32,
    pub voting_power: u64,
    pub validator_byte_length: u32,
    pub enabled: bool,
    pub signed: bool,
}

/// The protobuf-encoded leaf (a hash), and it's corresponding proof and path indices against the header.
#[derive(Debug, Clone)]
pub struct InclusionProof {
    pub enc_leaf: Vec<u8>,
    // Path and proof should have a fixed length of HEADER_PROOF_DEPTH.
    pub path: Vec<bool>,
    pub proof: Vec<[u8; 32]>,
}

#[derive(Debug, Clone)]
pub struct CelestiaBlockProof {
    pub validators: Vec<Validator>,
    pub header: Vec<u8>,
    pub data_hash_proof: InclusionProof,
    pub validator_hash_proof: InclusionProof,
    pub next_validators_hash_proof: InclusionProof,
    pub round_present: bool,
}

// If hash_so_far is on the left, False, else True
fn get_path_indices(index: u64, total: u64) -> Vec<bool> {
    let mut path_indices = vec![];

    let mut current_total = total;
    let mut current_index = index;
    while (current_total >= 1) {
        path_indices.push(current_index % 2 == 1);
        current_total = current_total / 2;
        current_index = current_index / 2;
    }
    path_indices
}

fn dummy_celestia_header() {
    // Generate dummy header from signature, pubkey, message

    let header = 

    for i in 0..VALIDATOR_SET_SIZE_MAX {

        const EXAMPLE_SECRET_CONN_KEY: &str = "F7FEB0B5BA0760B2C58893E329475D1EA81781DD636E37144B6D599AD38AA825";
        let pub_key = PublicKey::from_raw_ed25519(&hex::decode_upper(EXAMPLE_SECRET_CONN_KEY).unwrap());
        let voting_power = 10; 
        
    };

    // Generate validators hash from validators

    // Generate header from fields_bytes
    
    PublicKey::from_raw_ed25519(&[0u8; 32]).unwrap();
    // Generate EDDSA public key

}

pub fn generate_step_inputs() -> CelestiaBlockProof {
    // Generate test cases from Celestia block:
    let temp_block = Box::new(TempSignedBlock::from(
        serde_json::from_str::<TempSignedBlock>(include_str!(
            "./fixtures/11000/signed_block.json"
        ))
        .unwrap(),
    ));

    // Cast to SignedBlock
    let block = Box::new(SignedBlock {
        header: temp_block.header,
        data: temp_block.data,
        commit: temp_block.commit,
        validator_set: ValidatorSet::new(
            temp_block.validator_set.validators,
            temp_block.validator_set.proposer,
        ),
    });

    let mut validators = Vec::new();

    // Signatures or dummy
    // Need signature to output either verify or no verify (then we can assert that it matches or doesn't match)
    let block_validators = block.validator_set.validators();
    for i in 0..block.commit.signatures.len() {
        let val_idx = ValidatorIndex::try_from(i).unwrap();
        let validator = Box::new(
            match block.validator_set.validator(block_validators[i].address) {
                Some(validator) => validator,
                None => continue, // Cannot find matching validator, so we skip the vote
            },
        );
        if block.commit.signatures[i].is_commit() {
            let vote = non_absent_vote(
                &block.commit.signatures[i],
                val_idx,
                &block.commit,
            )
            .unwrap();
            
            let signed_vote = Box::new(
                SignedVote::from_vote(vote.clone(), block.header.chain_id.clone())
                    .expect("missing signature"),
            );
            let sig = signed_vote.signature();
            let val_bytes = validator.hash_bytes();
            validators.push(Validator {
                pubkey: validator.pub_key.ed25519().unwrap(),
                signature: sig.clone(),
                message: signed_vote.sign_bytes(),
                message_byte_length: signed_vote.sign_bytes().len() as u32,
                voting_power: validator.power(),
                validator_byte_length: val_bytes.len() as u32,
                enabled: true,
                signed: true,
            });
        } else {
            validators.push(Validator {
                pubkey: validator.pub_key.ed25519().unwrap(),
                signature: Signature::try_from(vec![0u8; 32]).expect("missing signature"),
                // TODO: Replace these with correct outputs
                message: vec![0u8; 120],
                message_byte_length: 120,
                voting_power: validator.power(),
                validator_byte_length: 38,
                enabled: true,
                signed: true,
            });
        }
    }

    // TODO: Compute inluded when casting to array of targets that is NUM_VALIDATORS_LEN long'
    // Note: We enc any hash that we need to submit merkle proofs for
    let header_hash = block.header.hash();
    let enc_next_validators_hash_leaf = block.header.next_validators_hash.encode_vec();
    let enc_validators_hash_leaf = block.header.validators_hash.encode_vec();
    let enc_data_hash_leaf = block.header.data_hash.unwrap().encode_vec();

    // Generate the merkle proofs for enc_next_validators_hash, enc_validators_hash, and enc_data_hash
    // These can be read into aunts_target for get_root_from_merkle_proof

    let (root, proofs) = generate_proofs_from_header(&block.header);
    let total = proofs[0].total;
    let enc_data_hash_proof = proofs[6].clone();
    let enc_data_hash_proof_indices = get_path_indices(6, total);
    let data_hash_proof = InclusionProof {
        enc_leaf: enc_data_hash_leaf,
        path: enc_data_hash_proof_indices,
        proof: enc_data_hash_proof.aunts,
    };
    // println!("data_hash_proof: {:?}", data_hash_proof);
    proofs[6]
            .verify(header_hash.as_bytes().try_into().unwrap(), &block.header.data_hash.unwrap().encode_vec())
            .unwrap();
    // println!("verified");

    let enc_validators_hash_proof = proofs[7].clone();
    let enc_validators_hash_proof_indices = get_path_indices(7, total);
    let validators_hash_proof = InclusionProof {
        enc_leaf: enc_validators_hash_leaf,
        path: enc_validators_hash_proof_indices,
        proof: enc_validators_hash_proof.aunts,
    };
    let enc_next_validators_hash_proof = proofs[8].clone();
    let enc_next_validators_hash_proof_indices = get_path_indices(8, total);
    let next_validators_hash_proof = InclusionProof {
        enc_leaf: enc_next_validators_hash_leaf,
        path: enc_next_validators_hash_proof_indices,
        proof: enc_next_validators_hash_proof.aunts,
    };

    CelestiaBlockProof { validators, header: header_hash.into(), data_hash_proof, validator_hash_proof: validators_hash_proof, next_validators_hash_proof, round_present: false }


}
