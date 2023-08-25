use std::fs;

/// Source (tendermint-rs): https://github.com/informalsystems/tendermint-rs/blob/e930691a5639ef805c399743ac0ddbba0e9f53da/tendermint/src/merkle.rs#L32
use crate::utils::{
    compute_hash_from_aunts, compute_hash_from_proof, generate_proofs_from_block_id,
    generate_proofs_from_header, leaf_hash, non_absent_vote, SignedBlock, TempSignedBlock,
};
use ed25519_consensus::SigningKey;
use sha2::Sha256;
use tendermint::crypto::ed25519::VerificationKey;
use tendermint::{private_key, Signature};
use tendermint::{validator::Set as ValidatorSet, vote::SignedVote, vote::ValidatorIndex};
use tendermint_proto::types::BlockId as RawBlockId;
use tendermint_proto::Protobuf;

#[derive(Debug, Clone)]
pub struct Validator {
    pub pubkey: VerificationKey,
    pub signature: Signature,
    pub message: Vec<u8>,
    pub message_bit_length: usize,
    pub voting_power: u64,
    pub validator_byte_length: usize,
    pub enabled: bool,
    pub signed: bool,
    pub present_on_trusted_header: Option<bool>,
}

#[derive(Debug, Clone)]
pub struct ValidatorHashField {
    pub pubkey: VerificationKey,
    pub voting_power: u64,
    pub validator_byte_length: usize,
    pub enabled: bool,
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
pub struct CelestiaBaseBlockProof {
    pub validators: Vec<Validator>,
    pub header: Vec<u8>,
    pub data_hash_proof: InclusionProof,
    pub validator_hash_proof: InclusionProof,
    pub next_validators_hash_proof: InclusionProof,
    pub round_present: bool,
}

#[derive(Debug, Clone)]
pub struct CelestiaStepBlockProof {
    pub prev_header: Vec<u8>,
    pub last_block_id_proof: InclusionProof,
    pub base: CelestiaBaseBlockProof,
}

#[derive(Debug, Clone)]
pub struct CelestiaSkipBlockProof {
    pub trusted_header: Vec<u8>,
    pub trusted_validator_hash_proof: InclusionProof,
    pub trusted_validator_fields: Vec<ValidatorHashField>,
    pub base: CelestiaBaseBlockProof,
}

// If hash_so_far is on the left, False, else True
pub fn get_path_indices(index: u64, total: u64) -> Vec<bool> {
    let mut path_indices = vec![];

    let mut current_total = total - 1;
    let mut current_index = index;
    while current_total >= 1 {
        path_indices.push(current_index % 2 == 1);
        current_total = current_total / 2;
        current_index = current_index / 2;
    }
    path_indices
}

fn get_signed_block(block: usize) -> Box<SignedBlock> {
    let mut file = String::new();
    file.push_str("./src/fixtures/");
    file.push_str(&block.to_string());
    file.push_str("/signed_block.json");

    let file_content = fs::read_to_string(file.as_str()).expect("error reading file");

    let temp_block = Box::new(TempSignedBlock::from(
        serde_json::from_str::<TempSignedBlock>(&file_content).expect("failed to parse json"),
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

    block
}

fn generate_base_inputs<const VALIDATOR_SET_SIZE_MAX: usize>(
    block: &Box<SignedBlock>,
) -> CelestiaBaseBlockProof {
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
        let val_bytes = validator.hash_bytes();
        if block.commit.signatures[i].is_commit() {
            let vote =
                non_absent_vote(&block.commit.signatures[i], val_idx, &block.commit).unwrap();

            let signed_vote = Box::new(
                SignedVote::from_vote(vote.clone(), block.header.chain_id.clone())
                    .expect("missing signature"),
            );
            let sig = signed_vote.signature();

            validators.push(Validator {
                pubkey: validator.pub_key.ed25519().unwrap(),
                signature: sig.clone(),
                message: signed_vote.sign_bytes(),
                message_bit_length: signed_vote.sign_bytes().len() * 8,
                voting_power: validator.power(),
                validator_byte_length: val_bytes.len(),
                enabled: true,
                signed: true,
                present_on_trusted_header: None,
            });
        } else {
            // These are dummy signatures (included in val hash, did not vote)
            validators.push(Validator {
                pubkey: validator.pub_key.ed25519().unwrap(),
                signature: Signature::try_from(vec![0u8; 64]).expect("missing signature"),
                // TODO: Replace these with correct outputs
                message: vec![0u8; 32],
                message_bit_length: 256,
                voting_power: validator.power(),
                validator_byte_length: val_bytes.len(),
                enabled: true,
                signed: false,
                present_on_trusted_header: None,
            });
        }
    }

    // These are empty signatures (not included in val hash)
    for i in block.commit.signatures.len()..VALIDATOR_SET_SIZE_MAX {
        let priv_key_bytes = vec![0u8; 32];
        let signing_key =
            private_key::Ed25519::try_from(&priv_key_bytes[..]).expect("failed to create key");
        let signing_key = SigningKey::try_from(signing_key).unwrap();
        let signing_key = ed25519_consensus::SigningKey::try_from(signing_key).unwrap();

        let verification_key = signing_key.verification_key();
        // TODO: Fix empty signatures
        validators.push(Validator {
            pubkey: VerificationKey::try_from(verification_key.as_bytes().as_ref())
                .expect("failed to create verification key"),
            signature: Signature::try_from(vec![0u8; 64]).expect("missing signature"),
            // TODO: Replace these with correct outputs
            message: vec![0u8; 32],
            message_bit_length: 256,
            voting_power: 0,
            validator_byte_length: 38,
            enabled: false,
            signed: false,
            present_on_trusted_header: None,
        });
    }

    // TODO: Compute inluded when casting to array of targets that is NUM_VALIDATORS_LEN long'
    // Note: We enc any hash that we need to submit merkle proofs for
    let header_hash = block.header.hash();
    let enc_next_validators_hash_leaf = block.header.next_validators_hash.encode_vec();
    let enc_validators_hash_leaf = block.header.validators_hash.encode_vec();
    let enc_data_hash_leaf = block.header.data_hash.unwrap().encode_vec();

    // Generate the merkle proofs for enc_next_validators_hash, enc_validators_hash, and enc_data_hash
    // These can be read into aunts_target for get_root_from_merkle_proof

    let (_root, proofs) = generate_proofs_from_header(&block.header);
    let total = proofs[0].total;
    let enc_data_hash_proof = proofs[6].clone();
    let enc_data_hash_proof_indices = get_path_indices(6, total);
    let data_hash_proof = InclusionProof {
        enc_leaf: enc_data_hash_leaf,
        path: enc_data_hash_proof_indices,
        proof: enc_data_hash_proof.aunts,
    };

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

    println!("num validators: {}", validators.len());

    let celestia_block_proof = CelestiaBaseBlockProof {
        validators,
        header: header_hash.as_bytes().to_vec(),
        data_hash_proof,
        validator_hash_proof: validators_hash_proof,
        next_validators_hash_proof,
        round_present: block.commit.round.value() > 0,
    };

    celestia_block_proof
}

pub fn generate_step_inputs<const VALIDATOR_SET_SIZE_MAX: usize>(
    block: usize,
) -> CelestiaStepBlockProof {
    // Generate test cases from Celestia block:
    let block = get_signed_block(block);

    let (_root, proofs) = generate_proofs_from_header(&block.header);
    let total = proofs[0].total;

    let enc_last_block_id_proof = proofs[4].clone();
    let enc_last_block_id_proof_indices = get_path_indices(4, total);
    println!(
        "last block proof indices: {:?}",
        enc_last_block_id_proof_indices
    );
    let enc_leaf =
        Protobuf::<RawBlockId>::encode_vec(block.header.last_block_id.unwrap_or_default());
    let last_block_id_proof = InclusionProof {
        enc_leaf: enc_leaf.clone(),
        path: enc_last_block_id_proof_indices,
        proof: enc_last_block_id_proof.clone().aunts,
    };
    assert_eq!(
        leaf_hash::<Sha256>(&enc_leaf),
        enc_last_block_id_proof.leaf_hash
    );

    let computed_root = compute_hash_from_aunts(
        4,
        14,
        leaf_hash::<Sha256>(&enc_leaf),
        enc_last_block_id_proof.clone().aunts,
    );
    assert_eq!(computed_root.unwrap(), block.header.hash().as_bytes());

    let prev_header_hash = block.header.last_block_id.unwrap().hash;
    let last_block_id =
        Protobuf::<RawBlockId>::encode_vec(block.header.last_block_id.unwrap_or_default());
    println!("last block id (len): {}", last_block_id.len());
    assert_eq!(
        prev_header_hash.as_bytes(),
        &last_block_id[2..34],
        "computed hash does not match"
    );

    let base = generate_base_inputs::<VALIDATOR_SET_SIZE_MAX>(&block);

    CelestiaStepBlockProof {
        prev_header: prev_header_hash.as_bytes().to_vec(),
        last_block_id_proof,
        base,
    }
}

fn update_present_on_trusted_header(
    base: &mut CelestiaBaseBlockProof,
    block: &Box<SignedBlock>,
    trusted_block: &Box<SignedBlock>,
) {
    // Parse each block to compute the validators that are the same from block_1 to block_2, and the cumulative voting power of the shared validators
    let mut shared_voting_power = 0;

    let threshold = 1 as f64 / 3 as f64;
    let block_2_total_voting_power = block.validator_set.total_voting_power().value();

    let block_1_validators = trusted_block.validator_set.validators();

    let mut idx = 0;
    let num_validators = block_1_validators.len();

    // Exit if we have already reached the threshold
    while block_2_total_voting_power as f64 * threshold > shared_voting_power as f64
        && idx < num_validators
    {
        if let Some(block_2_validator) = block
            .validator_set
            .validator(block_1_validators[idx].address)
        {
            shared_voting_power += block_2_validator.power();
            // Set the present_on_trusted_header field to true
            base.validators[idx].present_on_trusted_header = Some(true);
        }
        idx += 1;
    }
}

// Where block is the block we want to generate inputs for, and trusted_block is the block we're skipping from
pub fn generate_skip_inputs<const VALIDATOR_SET_SIZE_MAX: usize>(
    trusted_block: usize,
    block: usize,
) -> CelestiaSkipBlockProof {
    // Generate test cases from Celestia block:
    let block = get_signed_block(block);

    let mut base = generate_base_inputs::<VALIDATOR_SET_SIZE_MAX>(&block);

    // Get the trusted_block
    let trusted_block = get_signed_block(trusted_block);

    let mut trusted_validator_fields = Vec::new();

    // Signatures or dummy
    // Need signature to output either verify or no verify (then we can assert that it matches or doesn't match)
    let block_validators = trusted_block.validator_set.validators();

    for i in 0..trusted_block.commit.signatures.len() {
        let val_idx = ValidatorIndex::try_from(i).unwrap();
        let validator = Box::new(
            match trusted_block
                .validator_set
                .validator(block_validators[i].address)
            {
                Some(validator) => validator,
                None => continue, // Cannot find matching validator, so we skip the vote
            },
        );
        let val_bytes = validator.hash_bytes();
        trusted_validator_fields.push(ValidatorHashField {
            pubkey: validator.pub_key.ed25519().unwrap(),
            voting_power: validator.power(),
            validator_byte_length: val_bytes.len(),
            enabled: true,
        });
    }

    // These are empty signatures (not included in val hash)
    for i in trusted_block.commit.signatures.len()..VALIDATOR_SET_SIZE_MAX {
        let priv_key_bytes = vec![0u8; 32];
        let signing_key =
            private_key::Ed25519::try_from(&priv_key_bytes[..]).expect("failed to create key");
        let signing_key = SigningKey::try_from(signing_key).unwrap();
        let signing_key = ed25519_consensus::SigningKey::try_from(signing_key).unwrap();
        let verification_key = signing_key.verification_key();
        // TODO: Fix empty signatures
        trusted_validator_fields.push(ValidatorHashField {
            pubkey: VerificationKey::try_from(verification_key.as_bytes().as_ref())
                .expect("failed to create verification key"),
            voting_power: 0,
            validator_byte_length: 38,
            enabled: false,
        });
    }

    let (_root, proofs) = generate_proofs_from_header(&trusted_block.header);
    let total = proofs[0].total;

    let enc_validators_hash_leaf = trusted_block.header.validators_hash.encode_vec();
    let enc_validators_hash_proof = proofs[7].clone();
    let enc_validators_hash_proof_indices = get_path_indices(7, total);
    let validators_hash_proof = InclusionProof {
        enc_leaf: enc_validators_hash_leaf,
        path: enc_validators_hash_proof_indices,
        proof: enc_validators_hash_proof.aunts,
    };

    // Set the present_on_trusted_header field for each validator that is needed to reach the 1/3 threshold
    // Mutates the base object (which has present_on_trusted_header default set to none)
    update_present_on_trusted_header(&mut base, &block, &trusted_block);

    CelestiaSkipBlockProof {
        trusted_header: trusted_block.header.hash().into(),
        trusted_validator_hash_proof: validators_hash_proof,
        trusted_validator_fields,
        base,
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use crate::utils::generate_proofs_from_block_id;

    use super::*;

    #[test]
    fn test_prev_header_check() {
        let block_1 = get_signed_block(11000);
        let block_2 = get_signed_block(11001);

        assert_eq!(
            block_1.header.hash(),
            block_2.header.last_block_id.unwrap().hash
        );

        let (_root, proofs) = generate_proofs_from_header(&block_2.header);
        let total = proofs[0].total;
        let last_block_id_proof = proofs[4].clone();
        let last_block_id_proof_indices = get_path_indices(4, total);
        println!("last_block_id_proof: {:?}", last_block_id_proof.aunts);

        let (_root, proofs) = generate_proofs_from_block_id(&block_2.header.last_block_id.unwrap());
        let last_block_id = block_2.header.last_block_id.unwrap();

        let total = proofs[0].total;
        let prev_header_hash_proof = proofs[0].clone();
        let prev_header_hash_proof_indices = get_path_indices(0, total);
        println!("prev_header_hash_proof: {:?}", prev_header_hash_proof.aunts);
    }

    #[test]
    fn get_shared_voting_power() {
        let block_1 = get_signed_block(11000);
        let block_2 = get_signed_block(11105);

        // Parse each block to compute the validators that are the same from block_1 to block_2, and the cumulative voting power of the shared validators
        let mut shared_voting_power = 0;
        let mut shared_validators = Vec::new();

        let threshold = 1 as f64 / 3 as f64;
        let block_2_total_voting_power = block_2.validator_set.total_voting_power().value();

        let block_1_validators = block_1.validator_set.validators();

        let num_validators = block_1_validators.len();

        println!("num validators: {}", num_validators);

        let mut idx = 0;
        while block_2_total_voting_power as f64 * threshold > shared_voting_power as f64
            && idx < num_validators
        {
            if let Some(block_2_validator) = block_2
                .validator_set
                .validator(block_1_validators[idx].address)
            {
                shared_voting_power += block_2_validator.power();
                shared_validators.push(block_2_validator);
            }
            idx += 1
        }

        // // Add the validators from block_2_validators that have a matching pubkey with a validator in block_1_validators
        // block_1_validators.iter().for_each(|validator| {
        //     if let Some(block_2_validator) = block_2.validator_set.validator(validator.address) {
        //         shared_voting_power += block_2_validator.power();
        //         shared_validators.push(block_2_validator);
        //     }
        // });

        println!("shared voting power: {}", shared_voting_power);

        // Calculate shared voting power as a percentage of total voting power of block_2
        let shared_voting_power_percentage =
            shared_voting_power as f64 / block_2_total_voting_power as f64;
        println!(
            "shared voting power percentage: {}",
            shared_voting_power_percentage
        );

        println!("shared validators (len): {:?}", shared_validators.len());
    }
}
