/// Source (tendermint-rs): https://github.com/informalsystems/tendermint-rs/blob/e930691a5639ef805c399743ac0ddbba0e9f53da/tendermint/src/merkle.rs#L32
use crate::merkle::{generate_proofs_from_header, non_absent_vote, SignedBlock, TempSignedBlock};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::cell::RefCell;
use std::rc::Rc;
use subtle_encoding::hex;
use tendermint::{
    block::Header,
    block::{Commit, CommitSig},
    merkle::{Hash, MerkleHash},
    validator::{Info, Set as ValidatorSet},
    vote::{Power, SignedVote},
    vote::{ValidatorIndex, Vote},
};
use tendermint_proto::Protobuf;

// If hash_so_far is on the left, False, else True
fn get_path_indices(index: u64, total: u64) -> Vec<bool> {
    let mut path_indices = vec![];

    let mut current_total = total;
    let mut current_index = index;
    // println!("current_total: {:?}", current_total);
    while (current_total >= 1) {
        path_indices.push(current_index % 2 == 1);
        current_total = current_total / 2;
        current_index = current_index / 2;
    }
    path_indices
}

fn generate_inputs() {
    // Generate test cases from Celestia block:
    let temp_block = Box::new(TempSignedBlock::from(
        serde_json::from_str::<TempSignedBlock>(include_str!(
            "./scripts/signed_celestia_block.json"
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

    let mut tendermint_validators = Vec::new();
    let mut total_voting_power = 0;
    // get pubkey and power
    for validator in block.validator_set.validators() {
        tendermint_validators.push(validator);
        total_voting_power += validator.power();
    }
    println!("Total voting power: {}", total_voting_power);

    // Val enabled is defined when passing into the circuit and moving the array into an array of BoolTargets
    // Val signed is of the length of the validators set
    let mut val_signed = Vec::new();
    let mut num_signed = 0;
    for i in 0..block.commit.signatures.len() {
        if block.commit.signatures[i].is_commit() {
            val_signed.push(true);
            num_signed += 1;
        } else {
            val_signed.push(false);
        }
    }
    println!("Number of validators signed: {}", num_signed);

    // Signatures or dummy
    // Need signature to output either verify or no verify (then we can assert that it matches or doesn't match)
    let mut signatures = Vec::new();
    for i in 0..block.commit.signatures.len() {
        if block.commit.signatures[i].is_commit() {
            let vote = non_absent_vote(
                &block.commit.signatures[i],
                ValidatorIndex::try_from(i).unwrap(),
                &block.commit,
            )
            .unwrap();
            let signed_vote = Box::new(
                SignedVote::from_vote(vote.clone(), block.header.chain_id.clone())
                    .expect("missing signature"),
            );
            let sig = signed_vote.signature();
            signatures.push(sig.clone().into_bytes());
        } else {
            signatures.push(vec![0u8; 64]);
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
    let enc_validators_hash_proof = proofs[7].clone();
    let enc_validators_hash_proof_indices = get_path_indices(7, total);
    let enc_next_validators_hash_proof = proofs[8].clone();
    let enc_next_validators_hash_proof_indices = get_path_indices(8, total);
}
