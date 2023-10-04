use plonky2x::frontend::ecc::ed25519::gadgets::verify::EDDSABatchVerify;
use plonky2x::frontend::merkle::tree::MerkleInclusionProofVariable;
use plonky2x::frontend::uint::uint64::U64Variable;
use plonky2x::frontend::vars::U32Variable;
use plonky2x::prelude::{
    ArrayVariable, BoolVariable, Bytes32Variable, CircuitBuilder, CircuitVariable, PlonkParameters,
    RichField, Variable, Witness, WitnessWrite,
};
use tendermint::merkle::HASH_SIZE;

use crate::consts::{
    HEADER_PROOF_DEPTH, PROTOBUF_BLOCK_ID_SIZE_BYTES, PROTOBUF_HASH_SIZE_BYTES,
    VALIDATOR_MESSAGE_BYTES_LENGTH_MAX,
};
use crate::shared::TendermintHeader;
use crate::validator::TendermintValidator;
use crate::variables::{
    EDDSAPublicKeyVariable, EDDSASignatureVariable, HeightProofVariable,
    MarshalledValidatorVariable, TendermintHashVariable, ValidatorMessageVariable,
};
use crate::voting::TendermintVoting;

#[derive(Debug, Clone, CircuitVariable)]
#[value_name(Validator)]
pub struct ValidatorVariable {
    pub pubkey: EDDSAPublicKeyVariable,
    pub signature: EDDSASignatureVariable,
    pub message: ValidatorMessageVariable,
    pub message_byte_length: Variable,
    pub voting_power: U64Variable,
    pub validator_byte_length: Variable,
    pub enabled: BoolVariable,
    pub signed: BoolVariable,
    // Only used in skip circuit
    pub present_on_trusted_header: BoolVariable,
}

#[derive(Debug, Clone, CircuitVariable)]
#[value_name(ValidatorHashField)]
pub struct ValidatorHashFieldVariable {
    pub pubkey: EDDSAPublicKeyVariable,
    pub voting_power: U64Variable,
    pub validator_byte_length: Variable,
    pub enabled: BoolVariable,
}

/// The protobuf-encoded leaf (a hash), and it's corresponding proof and path indices against the header.
pub type HashInclusionProofVariable =
    MerkleInclusionProofVariable<HEADER_PROOF_DEPTH, PROTOBUF_HASH_SIZE_BYTES>;

pub type BlockIDInclusionProofVariable =
    MerkleInclusionProofVariable<HEADER_PROOF_DEPTH, PROTOBUF_BLOCK_ID_SIZE_BYTES>;

pub trait TendermintVerify<L: PlonkParameters<D>, const D: usize> {
    fn get_root<const LEAF_SIZE_BYTES: usize>(
        &mut self,
        proof: &MerkleInclusionProofVariable<HEADER_PROOF_DEPTH, LEAF_SIZE_BYTES>,
        path: &ArrayVariable<BoolVariable, HEADER_PROOF_DEPTH>,
    ) -> Bytes32Variable;

    /// Extract the header hash from the signed message from a validator.
    fn verify_hash_in_message(
        &mut self,
        message: &ValidatorMessageVariable,
        header_hash: Bytes32Variable,
        // Should be the same for all validators
        round_present_in_message: BoolVariable,
    ) -> BoolVariable;

    /// Verify the header hash of the previous block matches the current block's parent hash.
    fn verify_prev_header_in_header(
        &mut self,
        header: &TendermintHashVariable,
        prev_header: TendermintHashVariable,
        last_block_id_proof: &BlockIDInclusionProofVariable,
    );

    /// Verify the next validators hash in the previous block matches the current block's validators hash.
    fn verify_prev_header_next_validators_hash(
        &mut self,
        validators_hash: TendermintHashVariable,
        prev_header: &TendermintHashVariable,
        prev_header_next_validators_hash_proof: &HashInclusionProofVariable,
    );

    /// Verify a Tendermint consensus block.
    fn verify_header<const VALIDATOR_SET_SIZE_MAX: usize>(
        &mut self,
        validators: &ArrayVariable<ValidatorVariable, VALIDATOR_SET_SIZE_MAX>,
        header: &TendermintHashVariable,
        validator_hash_proof: &HashInclusionProofVariable,
        round_present: &BoolVariable,
    );

    /// Sequentially verify a Tendermint consensus block.
    fn step<const VALIDATOR_SET_SIZE_MAX: usize>(
        &mut self,
        validators: &ArrayVariable<ValidatorVariable, VALIDATOR_SET_SIZE_MAX>,
        header: &TendermintHashVariable,
        prev_header: &TendermintHashVariable,
        validator_hash_proof: &HashInclusionProofVariable,
        prev_header_next_validators_hash_proof: &HashInclusionProofVariable,
        last_block_id_proof: &BlockIDInclusionProofVariable,
        round_present: &BoolVariable,
    );

    /// Verify the trusted validators have signed the trusted header.
    fn verify_trusted_validators<const VALIDATOR_SET_SIZE_MAX: usize>(
        &mut self,
        validators: &ArrayVariable<ValidatorVariable, VALIDATOR_SET_SIZE_MAX>,
        trusted_header: TendermintHashVariable,
        trusted_validator_hash_proof: &HashInclusionProofVariable,
        trusted_validator_hash_fields: &ArrayVariable<
            ValidatorHashFieldVariable,
            VALIDATOR_SET_SIZE_MAX,
        >,
    );

    /// Verify Tendermint block that is non-sequential with the trusted block.
    fn skip<const VALIDATOR_SET_SIZE_MAX: usize>(
        &mut self,
        validators: &ArrayVariable<ValidatorVariable, VALIDATOR_SET_SIZE_MAX>,
        header: &TendermintHashVariable,
        header_height_proof: &HeightProofVariable,
        validator_hash_proof: &HashInclusionProofVariable,
        round_present: &BoolVariable,
        trusted_header: TendermintHashVariable,
        trusted_validator_hash_proof: &HashInclusionProofVariable,
        trusted_validator_hash_fields: &ArrayVariable<
            ValidatorHashFieldVariable,
            VALIDATOR_SET_SIZE_MAX,
        >,
    );

    // Assert the voting power of the signed validators is greater than the threshold.
    fn assert_voting_check<const VALIDATOR_SET_SIZE_MAX: usize>(
        &mut self,
        validators: ArrayVariable<ValidatorVariable, VALIDATOR_SET_SIZE_MAX>,
        threshold_numerator: &U64Variable,
        threshold_denominator: &U64Variable,
        include_in_check: Vec<BoolVariable>, // TODO: this should be an array var of the same size
    );
}

impl<L: PlonkParameters<D>, const D: usize> TendermintVerify<L, D> for CircuitBuilder<L, D> {
    fn get_root<const LEAF_SIZE_BYTES: usize>(
        &mut self,
        proof: &MerkleInclusionProofVariable<HEADER_PROOF_DEPTH, LEAF_SIZE_BYTES>,
        path: &ArrayVariable<BoolVariable, HEADER_PROOF_DEPTH>,
    ) -> Bytes32Variable {
        self.get_root_from_merkle_proof::<HEADER_PROOF_DEPTH, LEAF_SIZE_BYTES>(proof, path)
    }

    fn verify_hash_in_message(
        &mut self,
        message: &ValidatorMessageVariable,
        header_hash: Bytes32Variable,
        // Should be the same for all validators
        round_present_in_message: BoolVariable,
    ) -> BoolVariable {
        // Logic:
        //      Verify that header_hash is equal to the hash in the message at the correct index.
        //      If the round is missing, then the hash starts at index 16.
        //      If the round is present, then the hash starts at index 25.

        const MISSING_ROUND_START_IDX: usize = 16;

        const INCLUDING_ROUND_START_IDX: usize = 25;

        let round_missing_header: Bytes32Variable =
            message[MISSING_ROUND_START_IDX..MISSING_ROUND_START_IDX + HASH_SIZE].into();

        let round_present_header: Bytes32Variable =
            message[INCLUDING_ROUND_START_IDX..INCLUDING_ROUND_START_IDX + HASH_SIZE].into();

        let computed_header = self.select(
            round_present_in_message,
            round_present_header,
            round_missing_header,
        );

        self.is_equal(computed_header, header_hash)
    }

    fn assert_voting_check<const VALIDATOR_SET_SIZE_MAX: usize>(
        &mut self,
        validators: ArrayVariable<ValidatorVariable, VALIDATOR_SET_SIZE_MAX>,
        threshold_numerator: &U64Variable,
        threshold_denominator: &U64Variable,
        include_in_check: Vec<BoolVariable>,
    ) {
        assert_eq!(validators.as_vec().len(), include_in_check.len());
        let validator_voting_power: Vec<U64Variable> =
            validators.as_vec().iter().map(|v| v.voting_power).collect();

        let total_voting_power =
            self.get_total_voting_power::<VALIDATOR_SET_SIZE_MAX>(&validator_voting_power);

        // Assert the accumulated voting power is greater than the threshold
        let check_voting_power_bool = self.check_voting_power::<VALIDATOR_SET_SIZE_MAX>(
            &validator_voting_power,
            // Check if the signed validators are greater than the threshold
            &include_in_check,
            &total_voting_power,
            threshold_numerator,
            threshold_denominator,
        );
        let t = self._true();
        self.assert_is_equal(check_voting_power_bool, t);
    }

    fn step<const VALIDATOR_SET_SIZE_MAX: usize>(
        &mut self,
        validators: &ArrayVariable<ValidatorVariable, VALIDATOR_SET_SIZE_MAX>,
        header: &TendermintHashVariable,
        prev_header: &TendermintHashVariable,
        validator_hash_proof: &HashInclusionProofVariable,
        prev_header_next_validators_hash_proof: &HashInclusionProofVariable,
        last_block_id_proof: &BlockIDInclusionProofVariable,
        round_present: &BoolVariable,
    ) {
        // Verify 2/3 of the validators signed the headers
        self.verify_header(validators, header, validator_hash_proof, round_present);

        // Verify the previous header hash in the block matches the previous header hash in the last block ID.
        // FIXME: why is Rust compiler being weird
        self.verify_prev_header_in_header(header, *prev_header, last_block_id_proof);

        // Extract the validators hash from the validator hash proof
        let validators_hash: Bytes32Variable = validator_hash_proof.leaf[2..2 + HASH_SIZE].into();

        // Verify the next validators hash in the previous block matches the current validators hash
        // FIXME: why is Rust compiler being weird
        self.verify_prev_header_next_validators_hash(
            validators_hash,
            prev_header,
            prev_header_next_validators_hash_proof,
        );
    }

    fn verify_header<const VALIDATOR_SET_SIZE_MAX: usize>(
        &mut self,
        validators: &ArrayVariable<ValidatorVariable, VALIDATOR_SET_SIZE_MAX>,
        header: &TendermintHashVariable,
        validator_hash_proof: &HashInclusionProofVariable,
        round_present: &BoolVariable,
    ) {
        let false_t = self._false();
        let true_t = self._true();

        // TODO: clean up below, it's a bit horrendous
        // Fields used for verifying signatures
        let validators_signed = ArrayVariable::<BoolVariable, VALIDATOR_SET_SIZE_MAX>::new(
            validators.as_vec().iter().map(|v| v.signed).collect(),
        );
        let messages = ArrayVariable::<ValidatorMessageVariable, VALIDATOR_SET_SIZE_MAX>::new(
            validators.as_vec().iter().map(|v| v.message).collect(),
        );
        let message_byte_lengths = ArrayVariable::<U32Variable, VALIDATOR_SET_SIZE_MAX>::new(
            validators
                .as_vec()
                .iter()
                .map(|v| U32Variable(v.message_byte_length))
                .collect(),
        );
        let signatures = ArrayVariable::<EDDSASignatureVariable, VALIDATOR_SET_SIZE_MAX>::new(
            validators
                .as_vec()
                .iter()
                .map(|v| v.signature.clone())
                .collect(),
        );
        let pubkeys = ArrayVariable::<EDDSAPublicKeyVariable, VALIDATOR_SET_SIZE_MAX>::new(
            validators
                .as_vec()
                .iter()
                .map(|v| v.pubkey.clone())
                .collect(),
        );

        // Verifies signatures of the validators
        self.conditional_batch_eddsa_verify::<VALIDATOR_SET_SIZE_MAX, VALIDATOR_MESSAGE_BYTES_LENGTH_MAX>(
            validators_signed.clone(),
            message_byte_lengths,
            messages,
            signatures,
            pubkeys,
        );

        // Verify each of the validators marshal correctly
        // Assumes the validators are sorted in the correct order
        let byte_lengths: Vec<Variable> = validators
            .as_vec()
            .iter()
            .map(|v| v.validator_byte_length)
            .collect();
        let marshalled_validators: Vec<MarshalledValidatorVariable> = validators
            .as_vec()
            .iter()
            .map(|v| self.marshal_tendermint_validator(&v.pubkey, &v.voting_power))
            .collect();
        let validators_enabled: Vec<BoolVariable> =
            validators.as_vec().iter().map(|v| v.enabled).collect();
        // Compute the validators hash
        let validators_hash_target = self.hash_validator_set::<VALIDATOR_SET_SIZE_MAX>(
            &marshalled_validators,
            &byte_lengths,
            validators_enabled,
        );

        // Assert that computed validator hash matches expected validator hash
        let extracted_hash: Bytes32Variable = validator_hash_proof.leaf[2..2 + HASH_SIZE].into();

        self.assert_is_equal(extracted_hash, validators_hash_target);

        // Assert the accumulated voting power is greater than the threshold
        let threshold_numerator = self.constant::<U64Variable>(2);
        let threshold_denominator = self.constant::<U64Variable>(3);
        // TODO: why is rust compiler being so weird
        self.assert_voting_check(
            validators.clone(),
            &threshold_numerator,
            &threshold_denominator,
            validators_signed.as_vec(),
        );

        // Verify that the header is included in each message from a signed validator.
        // Verify that each validator marked as signed is enabled.
        for i in 0..VALIDATOR_SET_SIZE_MAX {
            // If the validator is signed, assert it is enabled.
            let enabled_and_signed = self.and(validators[i].enabled, validators[i].signed);
            self.assert_is_equal(validators[i].signed, enabled_and_signed);

            // Verify that the header is in the message in the correct location.
            // If a validator is signed, then the header should be in its signed message.
            let hash_in_message =
                self.verify_hash_in_message(&validators[i].message, *header, *round_present);
            let hash_in_message_and_signed = self.and(hash_in_message, validators[i].signed);
            self.assert_is_equal(hash_in_message_and_signed, validators_signed[i]);
        }

        // Note: Hardcode the path for each of the leaf proofs (otherwise you can prove arbitrary data in the header)
        let val_hash_path = vec![true_t, true_t, true_t, false_t];

        let header_from_validator_root_proof = self.get_root::<PROTOBUF_HASH_SIZE_BYTES>(
            validator_hash_proof,
            &val_hash_path.try_into().unwrap(),
        );

        self.assert_is_equal(*header, header_from_validator_root_proof);
    }

    fn verify_prev_header_in_header(
        &mut self,
        header: &TendermintHashVariable,
        prev_header: TendermintHashVariable,
        last_block_id_proof: &BlockIDInclusionProofVariable,
    ) {
        let last_block_id_path = vec![self._false(), self._false(), self._true(), self._false()];
        let header_from_last_block_id_proof = self.get_root::<PROTOBUF_BLOCK_ID_SIZE_BYTES>(
            last_block_id_proof,
            &last_block_id_path.try_into().unwrap(),
        );
        // TODO: add back a comment here I think
        self.assert_is_equal(header_from_last_block_id_proof, *header);

        // Extract prev header hash from the encoded leaf (starts at second byte)
        let extracted_prev_header_hash: Bytes32Variable =
            last_block_id_proof.leaf[2..2 + HASH_SIZE].into();
        self.assert_is_equal(prev_header, extracted_prev_header_hash);
    }

    fn verify_prev_header_next_validators_hash(
        &mut self,
        validators_hash: TendermintHashVariable,
        prev_header: &TendermintHashVariable,
        prev_header_next_validators_hash_proof: &HashInclusionProofVariable,
    ) {
        let next_val_hash_path = vec![self._false(), self._false(), self._false(), self._true()];
        let header_from_next_validators_root_proof = self.get_root::<PROTOBUF_HASH_SIZE_BYTES>(
            prev_header_next_validators_hash_proof,
            &next_val_hash_path.try_into().unwrap(),
        );
        // Confirms the prev_header computed from the proof of {next_validators_hash} matches the prev_header
        self.assert_is_equal(header_from_next_validators_root_proof, *prev_header);

        // Extract prev header hash from the encoded leaf (starts at second byte)
        let extracted_next_validators_hash =
            prev_header_next_validators_hash_proof.leaf[2..2 + HASH_SIZE].into();
        // Confirms the current validatorsHash matches the nextValidatorsHash of the prev_header
        self.assert_is_equal(validators_hash, extracted_next_validators_hash);
    }

    fn skip<const VALIDATOR_SET_SIZE_MAX: usize>(
        &mut self,
        validators: &ArrayVariable<ValidatorVariable, VALIDATOR_SET_SIZE_MAX>,
        header: &TendermintHashVariable,
        header_height_proof: &HeightProofVariable,
        validator_hash_proof: &HashInclusionProofVariable,
        round_present: &BoolVariable,
        trusted_header: TendermintHashVariable,
        trusted_validator_hash_proof: &HashInclusionProofVariable,
        trusted_validator_hash_fields: &ArrayVariable<
            ValidatorHashFieldVariable,
            VALIDATOR_SET_SIZE_MAX,
        >,
    ) {
        self.verify_trusted_validators(
            validators,
            trusted_header,
            trusted_validator_hash_proof,
            trusted_validator_hash_fields,
        );

        self.verify_header(validators, header, validator_hash_proof, round_present);

        self.verify_block_height(
            *header,
            &header_height_proof.proof,
            &header_height_proof.height,
            header_height_proof.enc_height_byte_length,
        )
    }

    fn verify_trusted_validators<const VALIDATOR_SET_SIZE_MAX: usize>(
        &mut self,
        validators: &ArrayVariable<ValidatorVariable, VALIDATOR_SET_SIZE_MAX>,
        trusted_header: TendermintHashVariable,
        trusted_validator_hash_proof: &HashInclusionProofVariable,
        trusted_validator_hash_fields: &ArrayVariable<
            ValidatorHashFieldVariable,
            VALIDATOR_SET_SIZE_MAX,
        >,
    ) {
        // Note: A trusted validator is one who is present on the trusted header
        let false_t = self._false();
        let true_t = self._true();

        // Get the header from the validator hash merkle proof
        let val_hash_path = vec![true_t, true_t, true_t, false_t];
        let header_from_validator_root_proof = self.get_root::<PROTOBUF_HASH_SIZE_BYTES>(
            trusted_validator_hash_proof,
            &val_hash_path.try_into().unwrap(),
        );
        // Confirm the validator hash proof matches the trusted header
        self.assert_is_equal(header_from_validator_root_proof, trusted_header);

        let marshalled_trusted_validators: Vec<MarshalledValidatorVariable> =
            trusted_validator_hash_fields
                .as_vec()
                .iter()
                .map(|v| self.marshal_tendermint_validator(&v.pubkey, &v.voting_power))
                .collect();

        let trusted_validators_enabled: Vec<BoolVariable> = trusted_validator_hash_fields
            .as_vec()
            .iter()
            .map(|v| v.enabled)
            .collect();

        let trusted_byte_lengths: Vec<Variable> = trusted_validator_hash_fields
            .as_vec()
            .iter()
            .map(|v| v.validator_byte_length)
            .collect();

        // Compute the validators hash from the validators
        let validators_hash_target = self.hash_validator_set::<VALIDATOR_SET_SIZE_MAX>(
            &marshalled_trusted_validators,
            &trusted_byte_lengths,
            trusted_validators_enabled,
        );

        // Assert the computed validator hash matches the expected validator hash
        let extracted_hash = trusted_validator_hash_proof.leaf[2..2 + HASH_SIZE].into();

        self.assert_is_equal(validators_hash_target, extracted_hash);

        // If a validator is present_on_trusted_header, then they should have signed.
        // Not all validators that have signed need to be present on the trusted header.
        // TODO: We should probably assert every validator that is enabled has signed.
        for i in 0..VALIDATOR_SET_SIZE_MAX {
            let present_and_signed = self.and(
                validators[i].present_on_trusted_header,
                validators[i].signed,
            );

            // If you are present, then you should have signed
            self.assert_is_equal(validators[i].present_on_trusted_header, present_and_signed);
        }

        // If a validator on the new header is present, then its pubkey should be present in the validator set from the trusted header.
        for i in 0..VALIDATOR_SET_SIZE_MAX {
            let mut pubkey_match = self._false();
            for j in 0..VALIDATOR_SET_SIZE_MAX {
                let pubkey_match_idx = self.is_equal(
                    validators[i].pubkey.clone(),
                    trusted_validator_hash_fields[j].pubkey.clone(),
                );
                pubkey_match = self.or(pubkey_match, pubkey_match_idx);
            }
            // It is possible for a current validator to be present on the trusted header, but not have signed the current header.
            let match_and_present = self.and(pubkey_match, validators[i].present_on_trusted_header);

            // If a validator is marked as present on the trusted header, then it should be present on the trusted header.
            self.assert_is_equal(validators[i].present_on_trusted_header, match_and_present);
        }

        let present_on_trusted_header: Vec<BoolVariable> = validators
            .as_vec()
            .iter()
            .map(|v| v.present_on_trusted_header)
            .collect();

        // Assert validators from the trusted block comprise at least 1/3 of the total voting power.
        let threshold_numerator = self.constant::<U64Variable>(1);
        let threshold_denominator = self.constant::<U64Variable>(3);
        self.assert_voting_check(
            validators.clone(),
            &threshold_numerator,
            &threshold_denominator,
            present_on_trusted_header,
        );
    }
}

// To run tests with logs (i.e. to see proof generation time), set the environment variable `RUST_LOG=debug` before the test command.
// Alternatively, add env::set_var("RUST_LOG", "debug") to the top of the test.
#[cfg(test)]
pub(crate) mod tests {
    use ethers::types::H256;
    use plonky2x::prelude::DefaultBuilder;
    use subtle_encoding::hex;

    use super::*;
    use crate::consts::VALIDATOR_MESSAGE_BYTES_LENGTH_MAX;

    #[test]
    fn test_verify_hash_in_message() {
        // This is a test case generated from block 144094 of Celestia's Mocha 3 testnet
        // Block Hash: 8909e1b73b7d987e95a7541d96ed484c17a4b0411e98ee4b7c890ad21302ff8c (needs to be lower case)
        // Signed Message (from the last validator): 6b080211de3202000000000022480a208909e1b73b7d987e95a7541d96ed484c17a4b0411e98ee4b7c890ad21302ff8c12240801122061263df4855e55fcab7aab0a53ee32cf4f29a1101b56de4a9d249d44e4cf96282a0b089dce84a60610ebb7a81932076d6f6368612d33
        // No round exists in present the message that was signed above

        env_logger::try_init().unwrap_or_default();

        // Define the circuit
        let mut builder = DefaultBuilder::new();
        let message = builder.read::<ValidatorMessageVariable>();
        let header_hash = builder.read::<TendermintHashVariable>();
        let round_present_in_message = builder.read::<BoolVariable>();

        let verified =
            builder.verify_hash_in_message(&message, header_hash, round_present_in_message);

        builder.write(verified);
        let circuit = builder.build();

        let header_hash =
            hex::decode("8909e1b73b7d987e95a7541d96ed484c17a4b0411e98ee4b7c890ad21302ff8c")
                .unwrap();
        let header_hash_h256 = H256::from_slice(&header_hash);
        let mut signed_message = hex::decode("6b080211de3202000000000022480a208909e1b73b7d987e95a7541d96ed484c17a4b0411e98ee4b7c890ad21302ff8c12240801122061263df4855e55fcab7aab0a53ee32cf4f29a1101b56de4a9d249d44e4cf96282a0b089dce84a60610ebb7a81932076d6f6368612d33").unwrap();
        signed_message.resize(VALIDATOR_MESSAGE_BYTES_LENGTH_MAX, 0u8);
        let mut input = circuit.input();
        input.write::<ValidatorMessageVariable>(signed_message.try_into().unwrap());
        input.write::<TendermintHashVariable>(header_hash_h256);
        input.write::<BoolVariable>(false);
        let (_, mut output) = circuit.prove(&input);
        let verified = output.read::<BoolVariable>();
        assert!(verified);
    }
}
