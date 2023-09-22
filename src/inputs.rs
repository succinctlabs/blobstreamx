use std::fs;
use std::path::PathBuf;

use ed25519_consensus::SigningKey;
use ethers::types::H256;
use num::BigUint;
use plonky2x::frontend::ecc::ed25519::curve::curve_types::AffinePoint;
use plonky2x::frontend::ecc::ed25519::curve::ed25519::Ed25519;
use plonky2x::frontend::ecc::ed25519::field::ed25519_scalar::Ed25519Scalar;
use plonky2x::frontend::ecc::ed25519::gadgets::eddsa::EDDSASignatureTarget;
use plonky2x::frontend::merkle::tree::InclusionProof;
use plonky2x::prelude::{CircuitVariable, Field, GoldilocksField, RichField};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use tendermint::crypto::ed25519::VerificationKey;
use tendermint::validator::Set as ValidatorSet;
use tendermint::vote::{SignedVote, ValidatorIndex};
use tendermint::{private_key, Signature};
use tendermint_proto::types::BlockId as RawBlockId;
use tendermint_proto::Protobuf;

use crate::circuits::{
    BlockIDInclusionProofVariable, DataCommitmentProofValueType, HashInclusionProofVariable,
    HeightProofValueType, Validator, ValidatorHashField, DUMMY_SIGNATURE,
};
use crate::constants::{
    HEADER_PROOF_DEPTH, PROTOBUF_BLOCK_ID_SIZE_BYTES, PROTOBUF_HASH_SIZE_BYTES,
    VALIDATOR_MESSAGE_BYTES_LENGTH_MAX,
};
use crate::fixture::DataCommitmentFixture;
/// Source (tendermint-rs): https://github.com/informalsystems/tendermint-rs/blob/e930691a5639ef805c399743ac0ddbba0e9f53da/tendermint/src/merkle.rs#L32
use crate::input_data::tendermint_utils::{
    compute_hash_from_aunts, generate_proofs_from_header, leaf_hash, non_absent_vote,
    TempSignedBlock,
};
// TODO: Remove dependency on utils.
use crate::utils::SignedBlock;
type F = GoldilocksField;
type C = Ed25519;

/// The protobuf-encoded leaf (a hash), and it's corresponding proof and path indices against the header.
/// TODO: Remove this once we port step & skip circuits to use CircuitVariable
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TempMerkleInclusionProof {
    pub enc_leaf: Vec<u8>,
    // Path and proof should have a fixed length of HEADER_PROOF_DEPTH.
    pub path: Vec<bool>,
    pub proof: Vec<H256>,
}

impl From<TempMerkleInclusionProof>
    for <HashInclusionProofVariable<HEADER_PROOF_DEPTH> as CircuitVariable>::ValueType<
        GoldilocksField,
    >
{
    fn from(proof: TempMerkleInclusionProof) -> Self {
        if proof.proof.len() != HEADER_PROOF_DEPTH {
            panic!("path length does not match");
        }
        if proof.enc_leaf.len() != PROTOBUF_HASH_SIZE_BYTES {
            panic!("enc_leaf length does not match");
        }
        let leaf_as_fixed: [u8; PROTOBUF_HASH_SIZE_BYTES] = proof.enc_leaf[..].try_into().unwrap();
        Self {
            enc_leaf: leaf_as_fixed,
            proof: proof.proof,
        }
    }
}

impl From<TempMerkleInclusionProof>
    for <BlockIDInclusionProofVariable<HEADER_PROOF_DEPTH> as CircuitVariable>::ValueType<
        GoldilocksField,
    >
{
    fn from(proof: TempMerkleInclusionProof) -> Self {
        if proof.proof.len() != HEADER_PROOF_DEPTH {
            panic!("path length does not match");
        }
        if proof.enc_leaf.len() != PROTOBUF_BLOCK_ID_SIZE_BYTES {
            panic!("enc_leaf length does not match");
        }
        let leaf_as_fixed: [u8; PROTOBUF_BLOCK_ID_SIZE_BYTES] =
            proof.enc_leaf[..].try_into().unwrap();
        Self {
            enc_leaf: leaf_as_fixed,
            proof: proof.proof,
        }
    }
}

fn pubkey_to_affine_point(pubkey: &VerificationKey) -> AffinePoint<C> {
    let pubkey_bytes = pubkey.as_bytes();
    AffinePoint::new_from_compressed_point(pubkey_bytes)
}

type SignatureValueType<F> = <EDDSASignatureTarget<Ed25519> as CircuitVariable>::ValueType<F>;

fn signature_to_value_type(signature: &Signature) -> SignatureValueType<F> {
    let sig_bytes = signature.as_bytes();
    let sig_r = AffinePoint::new_from_compressed_point(&sig_bytes[0..32]);
    assert!(sig_r.is_valid());
    let sig_s_biguint = BigUint::from_bytes_le(&sig_bytes[32..64]);
    if sig_s_biguint.to_u32_digits().is_empty() {
        panic!("sig_s_biguint has 0 limbs which will cause problems down the line")
    }
    let sig_s = Ed25519Scalar::from_noncanonical_biguint(sig_s_biguint);
    SignatureValueType::<F> { r: sig_r, s: sig_s }
}

#[derive(Debug, Clone)]
pub struct CelestiaBaseBlockProof {
    pub validators: Vec<Validator<C, F>>,
    pub header: H256,
    pub data_hash_proof: TempMerkleInclusionProof,
    pub validator_hash_proof: TempMerkleInclusionProof,
    pub next_validators_hash_proof: TempMerkleInclusionProof,
    pub round_present: bool,
}

#[derive(Debug, Clone)]
pub struct CelestiaStepBlockProof {
    pub prev_header_next_validators_hash_proof: TempMerkleInclusionProof,
    pub prev_header: H256,
    pub last_block_id_proof: TempMerkleInclusionProof,
    pub base: CelestiaBaseBlockProof,
}

#[derive(Debug, Clone)]
pub struct CelestiaSkipBlockProof {
    pub trusted_header: H256,
    pub trusted_validator_hash_proof: TempMerkleInclusionProof,
    pub trusted_validator_fields: Vec<ValidatorHashField<C, F>>,
    pub block_height_proof: HeightProofValueType<F>,
    pub base: CelestiaBaseBlockProof,
}

// If hash_so_far is on the left, False, else True
pub fn get_path_indices(index: u64, total: u64) -> Vec<bool> {
    let mut path_indices = vec![];

    let mut current_total = total - 1;
    let mut current_index = index;
    while current_total >= 1 {
        path_indices.push(current_index % 2 == 1);
        current_total /= 2;
        current_index /= 2;
    }
    path_indices
}

pub fn get_signed_block_from_fixture(block: usize) -> Box<SignedBlock> {
    let mut file = String::new();
    file.push_str("./src/fixtures/mocha-3/");
    file.push_str(&block.to_string());
    file.push_str("/signed_block.json");

    let file_content = fs::read_to_string(file.as_str());

    let temp_block = Box::new(
        serde_json::from_str::<TempSignedBlock>(&file_content.unwrap())
            .expect("failed to parse json"),
    );

    // Cast to SignedBlock
    Box::new(SignedBlock {
        header: temp_block.header,
        data: temp_block.data,
        commit: temp_block.commit,
        validator_set: ValidatorSet::new(
            temp_block.validator_set.validators,
            temp_block.validator_set.proposer,
        ),
    })
}

fn get_data_commitment_fixture(start_block: usize, end_block: usize) -> DataCommitmentFixture {
    let path = PathBuf::from(format!(
        "./src/fixtures/mocha-4/{}-{}",
        start_block, end_block
    ))
    .join("data_commitment.json");

    let file_content = fs::read_to_string(path);

    serde_json::from_str::<DataCommitmentFixture>(&file_content.unwrap())
        .expect("failed to parse json")
}

/// Generate the inputs for a skip proof from a start_block to end_block.
pub fn generate_expected_data_commitment<const WINDOW_SIZE: usize, F: RichField>(
    start_block: usize,
    end_block: usize,
) -> H256 {
    // Generate test cases from data commitment fixture
    let fixture = get_data_commitment_fixture(start_block, end_block);

    H256::from_slice(fixture.expected_data_commitment.as_bytes())
}

/// Generate the inputs for a data commitment proof from start_block to end_block.
pub fn generate_data_commitment_inputs<const WINDOW_SIZE: usize, F: RichField>(
    start_block: usize,
    end_block: usize,
) -> DataCommitmentProofValueType<WINDOW_SIZE, F> {
    assert!(
        end_block - start_block == WINDOW_SIZE,
        "window size does not match"
    );

    // Generate test cases from data commitment fixture
    let fixture = get_data_commitment_fixture(start_block, end_block);

    let mut data_hashes = Vec::new();
    for i in start_block..end_block {
        data_hashes.push(H256::from_slice(
            fixture.data_hashes[i - start_block].as_bytes(),
        ));
    }

    let mut data_hash_proofs = Vec::new();
    let mut prev_header_proofs = Vec::new();
    for i in 0..WINDOW_SIZE {
        data_hash_proofs.push(InclusionProof {
            leaf: fixture.data_hash_proofs[i]
                .enc_leaf
                .clone()
                .try_into()
                .unwrap(),
            path_indices: fixture.data_hash_proofs[i].path.clone(),
            aunts: fixture.data_hash_proofs[i].proof.clone(),
        });
        prev_header_proofs.push(InclusionProof {
            leaf: fixture.prev_header_proofs[i]
                .enc_leaf
                .clone()
                .try_into()
                .unwrap(),
            path_indices: fixture.prev_header_proofs[i].path.clone(),
            aunts: fixture.prev_header_proofs[i].proof.clone(),
        });
    }

    DataCommitmentProofValueType {
        data_hashes,
        end_header: H256::from_slice(fixture.end_header.as_bytes()),
        end_header_height_proof: HeightProofValueType {
            proof: fixture.end_block_height_proof.proof,
            height: fixture.end_block.into(),
            enc_height_byte_length: fixture.encoded_end_height_byte_length,
        },
        start_header: H256::from_slice(fixture.start_header.as_bytes()),
        start_header_height_proof: HeightProofValueType {
            proof: fixture.start_block_height_proof.proof,
            height: fixture.start_block.into(),
            enc_height_byte_length: fixture.encoded_start_height_byte_length,
        },
        prev_header_proofs,
        data_hash_proofs,
    }
}

pub fn convert_to_h256(aunts: Vec<[u8; 32]>) -> Vec<H256> {
    let mut aunts_h256 = Vec::new();
    for aunt in aunts {
        aunts_h256.push(H256::from_slice(&aunt));
    }
    aunts_h256
}

/// Generate the base inputs for a proof of a Celestia block (to be used by the skip or step circuits).
fn generate_base_inputs<const VALIDATOR_SET_SIZE_MAX: usize>(
    block: &SignedBlock,
) -> CelestiaBaseBlockProof {
    let mut validators = Vec::new();

    // Signatures or dummy
    // Need signature to output either verify or no verify (then we can assert that it matches or doesn't match)
    let block_validators = block.validator_set.validators();

    // Exclude invalid validators (i.e. those that are malformed & are not included in the validator set).
    for i in 0..block.commit.signatures.len() {
        let validator = Box::new(
            match block.validator_set.validator(block_validators[i].address) {
                Some(validator) => validator,
                None => continue, // Cannot find matching validator, so we skip the vote
            },
        );
        let val_idx = ValidatorIndex::try_from(i).unwrap();
        let val_bytes = validator.hash_bytes();
        if block.commit.signatures[i].is_commit() {
            let vote =
                non_absent_vote(&block.commit.signatures[i], val_idx, &block.commit).unwrap();

            let signed_vote = Box::new(
                SignedVote::from_vote(vote, block.header.chain_id.clone())
                    .expect("missing signature"),
            );
            let mut message_padded = signed_vote.sign_bytes();
            message_padded.resize(VALIDATOR_MESSAGE_BYTES_LENGTH_MAX, 0u8);

            let sig = signed_vote.signature();

            validators.push(Validator {
                pubkey: pubkey_to_affine_point(&validator.pub_key.ed25519().unwrap()),
                signature: signature_to_value_type(&sig.clone()),
                message: message_padded.try_into().unwrap(),
                message_bit_length: F::from_canonical_usize(signed_vote.sign_bytes().len() * 8),
                voting_power: validator.power().into(),
                validator_byte_length: F::from_canonical_usize(val_bytes.len()),
                enabled: true,
                signed: true,
                present_on_trusted_header: false, // This field is ignored in this case
            });
        } else {
            // These are dummy signatures (included in val hash, did not vote)
            validators.push(Validator {
                pubkey: pubkey_to_affine_point(&validator.pub_key.ed25519().unwrap()),
                signature: signature_to_value_type(
                    &Signature::try_from(DUMMY_SIGNATURE.to_vec()).expect("missing signature"),
                ),
                // TODO: Replace these with correct outputs
                message: [0u8; VALIDATOR_MESSAGE_BYTES_LENGTH_MAX],
                message_bit_length: F::from_canonical_usize(256),
                voting_power: validator.power().into(),
                validator_byte_length: F::from_canonical_usize(val_bytes.len()),
                enabled: true,
                signed: false,
                present_on_trusted_header: false, // This field is ignored in this case
            });
        }
    }

    // These are empty signatures (not included in val hash)
    for _ in block.commit.signatures.len()..VALIDATOR_SET_SIZE_MAX {
        let priv_key_bytes = [0u8; 32];
        let signing_key =
            private_key::Ed25519::try_from(&priv_key_bytes[..]).expect("failed to create key");
        let signing_key = SigningKey::try_from(signing_key).unwrap();

        let verification_key = signing_key.verification_key();
        // TODO: Fix empty signatures
        validators.push(Validator {
            pubkey: pubkey_to_affine_point(
                &VerificationKey::try_from(verification_key.as_bytes().as_ref())
                    .expect("failed to create verification key"),
            ),
            signature: signature_to_value_type(
                &Signature::try_from(DUMMY_SIGNATURE.to_vec()).expect("missing signature"),
            ),
            // TODO: Replace these with correct outputs
            message: [0u8; VALIDATOR_MESSAGE_BYTES_LENGTH_MAX],
            message_bit_length: F::from_canonical_usize(256),
            voting_power: 0u64.into(),
            validator_byte_length: F::from_canonical_usize(38),
            enabled: false,
            signed: false,
            present_on_trusted_header: false, // This field ignored for this case
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
    let data_hash_proof = TempMerkleInclusionProof {
        enc_leaf: enc_data_hash_leaf,
        path: enc_data_hash_proof_indices,
        proof: convert_to_h256(enc_data_hash_proof.aunts),
    };

    let enc_validators_hash_proof = proofs[7].clone();
    let enc_validators_hash_proof_indices = get_path_indices(7, total);
    let validators_hash_proof = TempMerkleInclusionProof {
        enc_leaf: enc_validators_hash_leaf,
        path: enc_validators_hash_proof_indices,
        proof: convert_to_h256(enc_validators_hash_proof.aunts),
    };
    let enc_next_validators_hash_proof = proofs[8].clone();
    let enc_next_validators_hash_proof_indices = get_path_indices(8, total);
    let next_validators_hash_proof = TempMerkleInclusionProof {
        enc_leaf: enc_next_validators_hash_leaf,
        path: enc_next_validators_hash_proof_indices,
        proof: convert_to_h256(enc_next_validators_hash_proof.aunts),
    };

    println!("num validators: {}", validators.len());

    let celestia_block_proof = CelestiaBaseBlockProof {
        validators,
        header: H256::from_slice(header_hash.as_bytes()),
        data_hash_proof,
        validator_hash_proof: validators_hash_proof,
        next_validators_hash_proof,
        round_present: block.commit.round.value() > 0,
    };

    celestia_block_proof
}

/// Generate the inputs for a step proof for consecutive Celestia blocks.
pub fn generate_step_inputs<const VALIDATOR_SET_SIZE_MAX: usize>(
    block_number: usize,
) -> CelestiaStepBlockProof {
    // Generate test cases from Celestia block:
    let prev_block = get_signed_block_from_fixture(block_number - 1);
    let block = get_signed_block_from_fixture(block_number);

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
    let last_block_id_proof = TempMerkleInclusionProof {
        enc_leaf: enc_leaf.clone(),
        path: enc_last_block_id_proof_indices,
        proof: convert_to_h256(enc_last_block_id_proof.clone().aunts),
    };
    assert_eq!(
        leaf_hash::<Sha256>(&enc_leaf),
        enc_last_block_id_proof.leaf_hash
    );

    let computed_root = compute_hash_from_aunts(
        4,
        14,
        leaf_hash::<Sha256>(&enc_leaf),
        enc_last_block_id_proof.aunts,
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

    // Generate proofs from prev_header
    let (_prev_root, prev_block_proofs) = generate_proofs_from_header(&prev_block.header);
    let prev_block_total = prev_block_proofs[0].total;

    // Proof of the prev_header_next_validators_hash
    let enc_prev_header_next_validators_hash_leaf =
        prev_block.header.next_validators_hash.encode_vec();
    let enc_prev_header_next_validators_hash_proof = prev_block_proofs[8].clone();
    let enc_prev_header_next_validators_hash_proof_indices = get_path_indices(8, prev_block_total);
    let prev_header_next_validators_hash_proof = TempMerkleInclusionProof {
        enc_leaf: enc_prev_header_next_validators_hash_leaf,
        path: enc_prev_header_next_validators_hash_proof_indices,
        proof: convert_to_h256(enc_prev_header_next_validators_hash_proof.aunts),
    };

    let base = generate_base_inputs::<VALIDATOR_SET_SIZE_MAX>(&block);

    CelestiaStepBlockProof {
        prev_header_next_validators_hash_proof,
        prev_header: H256::from_slice(prev_header_hash.as_bytes()),
        last_block_id_proof,
        base,
    }
}

fn update_present_on_trusted_header(
    base: &mut CelestiaBaseBlockProof,
    block: &SignedBlock,
    trusted_block: &SignedBlock,
) {
    // Parse each block to compute the validators that are the same from block_1 to block_2, and the cumulative voting power of the shared validators
    let mut shared_voting_power = 0;

    let threshold = 1_f64 / 3_f64;
    let block_2_total_voting_power = block.validator_set.total_voting_power().value();

    let block_1_validators = trusted_block.validator_set.validators();

    let mut idx = 0;
    let num_validators = block_1_validators.len();

    // Exit if we have already reached the threshold
    // TODO: We might need to add checks to make this more resilient
    while block_2_total_voting_power as f64 * threshold > shared_voting_power as f64
        && idx < num_validators
    {
        if let Some(block_2_validator) = block
            .validator_set
            .validator(block_1_validators[idx].address)
        {
            // Confirm that the validator has signed on block_2
            for sig in block.commit.signatures.iter() {
                if sig.validator_address().is_some()
                    && sig.validator_address().unwrap() == block_2_validator.address
                {
                    // Add the shared voting power to the validator
                    shared_voting_power += block_2_validator.power();
                    // Set the present_on_trusted_header field to true
                    base.validators[idx].present_on_trusted_header = true;
                    println!("added validator: {}", idx);
                }
            }
        }
        idx += 1;
    }

    assert!(
        block_2_total_voting_power as f64 * threshold <= shared_voting_power as f64,
        "shared voting power is less than threshold"
    );
}

/// Generate the inputs for a skip proof from a trusted_block to block.
pub fn generate_skip_inputs<const VALIDATOR_SET_SIZE_MAX: usize>(
    trusted_block: usize,
    block: usize,
) -> CelestiaSkipBlockProof {
    // Generate test cases from Celestia block:
    let block = get_signed_block_from_fixture(block);

    let mut base = generate_base_inputs::<VALIDATOR_SET_SIZE_MAX>(&block);

    // Get the trusted_block
    let trusted_block = get_signed_block_from_fixture(trusted_block);

    let mut trusted_validator_fields = Vec::new();

    // Signatures or dummy
    // Need signature to output either verify or no verify (then we can assert that it matches or doesn't match)
    let block_validators = trusted_block.validator_set.validators();
    for i in 0..trusted_block.commit.signatures.len() {
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
            pubkey: pubkey_to_affine_point(&validator.pub_key.ed25519().unwrap()),
            voting_power: validator.power().into(),
            validator_byte_length: F::from_canonical_usize(val_bytes.len()),
            enabled: true,
        });
    }

    // These are empty signatures (not included in val hash)
    for _ in trusted_block.commit.signatures.len()..VALIDATOR_SET_SIZE_MAX {
        let priv_key_bytes = [0u8; 32];
        let signing_key =
            private_key::Ed25519::try_from(&priv_key_bytes[..]).expect("failed to create key");
        let signing_key = SigningKey::try_from(signing_key).unwrap();
        let verification_key = signing_key.verification_key();
        // TODO: Fix empty signatures
        trusted_validator_fields.push(ValidatorHashField {
            pubkey: pubkey_to_affine_point(
                &VerificationKey::try_from(verification_key.as_bytes().as_ref())
                    .expect("failed to create verification key"),
            ),
            voting_power: 0u64.into(),
            validator_byte_length: F::from_canonical_usize(38),
            enabled: false,
        });
    }

    let (_root, proofs) = generate_proofs_from_header(&trusted_block.header);
    let total = proofs[0].total;

    let enc_validators_hash_leaf = trusted_block.header.validators_hash.encode_vec();
    let enc_validators_hash_proof = proofs[7].clone();
    let enc_validators_hash_proof_indices = get_path_indices(7, total);
    let validators_hash_proof = TempMerkleInclusionProof {
        enc_leaf: enc_validators_hash_leaf,
        path: enc_validators_hash_proof_indices,
        proof: convert_to_h256(enc_validators_hash_proof.aunts),
    };

    // Set the present_on_trusted_header field for each validator that is needed to reach the 1/3 threshold
    // Mutates the base object (which has present_on_trusted_header default set to none)
    update_present_on_trusted_header(&mut base, &block, &trusted_block);

    let (_root, proofs) = generate_proofs_from_header(&block.header);
    let enc_height_leaf = block.header.height.encode_vec();
    let enc_height_proof = proofs[2].clone();

    let height_proof = HeightProofValueType {
        proof: convert_to_h256(enc_height_proof.aunts),
        enc_height_byte_length: enc_height_leaf.len() as u32,
        height: block.header.height.value().into(),
    };

    let hash: Vec<u8> = trusted_block.header.hash().into();
    CelestiaSkipBlockProof {
        trusted_header: H256::from_slice(&hash),
        trusted_validator_hash_proof: validators_hash_proof,
        trusted_validator_fields,
        block_height_proof: height_proof,
        base,
    }
}

// To run tests with logs (i.e. to see proof generation time), set the environment variable `RUST_LOG=debug` before the test command.
// Alternatively, add env::set_var("RUST_LOG", "debug") to the top of the test.
#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    #[test]
    #[cfg_attr(feature = "ci", ignore)]
    fn test_get_block_height() {
        let block = get_signed_block_from_fixture(11000);
        let encoded_block_height = block.header.height.encode_vec();
        println!("encoded block height: {:?}", encoded_block_height);

        let block = get_signed_block_from_fixture(11001);
        let encoded_block_height = block.header.height.encode_vec();
        println!("encoded block height: {:?}", encoded_block_height);
    }

    #[test]
    #[cfg_attr(feature = "ci", ignore)]
    fn test_get_header_hash() {
        let block = get_signed_block_from_fixture(10000);
        let header_hash = block.header.hash();
        println!("header hash: {}", header_hash);
    }
}
