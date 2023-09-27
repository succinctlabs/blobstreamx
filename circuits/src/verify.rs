use plonky2x::frontend::ecc::ed25519::curve::curve_types::Curve;
use plonky2x::frontend::ecc::ed25519::curve::ed25519::Ed25519;
use plonky2x::frontend::ecc::ed25519::gadgets::eddsa::EDDSASignatureTarget;
use plonky2x::frontend::ecc::ed25519::gadgets::verify::EDDSABatchVerify;
use plonky2x::frontend::merkle::tree::MerkleInclusionProofVariable;
use plonky2x::frontend::uint::uint64::U64Variable;
use plonky2x::frontend::vars::U32Variable;
use plonky2x::prelude::{
    ArrayVariable, BoolVariable, Bytes32Variable, BytesVariable, CircuitBuilder, CircuitVariable,
    PlonkParameters, RichField, Variable, Witness, WitnessWrite,
};
use tendermint::merkle::HASH_SIZE;

use crate::consts::{
    HEADER_PROOF_DEPTH, PROTOBUF_HASH_SIZE_BYTES, VALIDATOR_MESSAGE_BYTES_LENGTH_MAX,
};
use crate::shared::TendermintHeader;
use crate::validator::TendermintValidator;
use crate::variables::{
    EDDSAPublicKeyVariable, EncBlockIDVariable, EncTendermintHashVariable, HeightProofVariable,
    MarshalledValidatorVariable, TendermintHashVariable, ValidatorMessageVariable,
};
use crate::voting::TendermintVoting;

#[derive(Debug, Clone, CircuitVariable)]
#[value_name(Validator)]
pub struct ValidatorVariable<C: Curve> {
    pub pubkey: EDDSAPublicKeyVariable<C>,
    pub signature: EDDSASignatureTarget<C>,
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
pub struct ValidatorHashFieldVariable<C: Curve> {
    pub pubkey: EDDSAPublicKeyVariable<C>,
    pub voting_power: U64Variable,
    pub validator_byte_length: Variable,
    pub enabled: BoolVariable,
}

/// The protobuf-encoded leaf (a hash), and it's corresponding proof and path indices against the header.
#[derive(Debug, Clone, CircuitVariable)]
#[value_name(HashInclusionProof)]
pub struct HashInclusionProofVariable<const HEADER_PROOF_DEPTH: usize> {
    pub enc_leaf: EncTendermintHashVariable,
    pub proof: ArrayVariable<TendermintHashVariable, HEADER_PROOF_DEPTH>,
}

/// The protobuf-encoded leaf (a tendermint block ID), and it's corresponding proof and path indices against the header.
#[derive(Debug, Clone, CircuitVariable)]
#[value_name(BlockIDInclusionProof)]
pub struct BlockIDInclusionProofVariable<const HEADER_PROOF_DEPTH: usize> {
    pub enc_leaf: EncBlockIDVariable,
    pub proof: ArrayVariable<TendermintHashVariable, HEADER_PROOF_DEPTH>,
}

#[derive(Debug, Clone, CircuitVariable)]
pub struct StepProofTarget<
    C: Curve,
    const HEADER_PROOF_DEPTH: usize,
    const VALIDATOR_SET_SIZE_MAX: usize,
> {
    prev_header_next_validators_hash_proof: HashInclusionProofVariable<HEADER_PROOF_DEPTH>,
    prev_header: TendermintHashVariable,
    last_block_id_proof: BlockIDInclusionProofVariable<HEADER_PROOF_DEPTH>,
    base: BaseBlockProofVariable<C, HEADER_PROOF_DEPTH, VALIDATOR_SET_SIZE_MAX>,
}

#[derive(Debug, Clone, CircuitVariable)]
pub struct SkipProofTarget<
    C: Curve,
    const HEADER_PROOF_DEPTH: usize,
    const VALIDATOR_SET_SIZE_MAX: usize,
> {
    trusted_header: TendermintHashVariable,
    trusted_validator_hash_proof: HashInclusionProofVariable<HEADER_PROOF_DEPTH>,
    trusted_validator_hash_fields: Vec<ValidatorHashFieldVariable<C>>,
    base: BaseBlockProofVariable<C, HEADER_PROOF_DEPTH, VALIDATOR_SET_SIZE_MAX>,
}

#[derive(Debug, Clone, CircuitVariable)]
pub struct BaseBlockProofVariable<
    C: Curve,
    const HEADER_PROOF_DEPTH: usize,
    const VALIDATOR_SET_SIZE_MAX: usize,
> {
    validators: ArrayVariable<ValidatorVariable<C>, VALIDATOR_SET_SIZE_MAX>,
    header: TendermintHashVariable,
    data_hash_proof: HashInclusionProofVariable<HEADER_PROOF_DEPTH>,
    validator_hash_proof: HashInclusionProofVariable<HEADER_PROOF_DEPTH>,
    next_validators_hash_proof: HashInclusionProofVariable<HEADER_PROOF_DEPTH>,
    round_present: BoolVariable,
}

pub trait TendermintVerify<
    L: PlonkParameters<D>,
    const D: usize,
    const VALIDATOR_SET_SIZE_MAX: usize,
>
{
    type Curve: Curve;

    fn get_root<const LEAF_SIZE_BYTES: usize>(
        &mut self,
        leaf: &BytesVariable<LEAF_SIZE_BYTES>,
        path: &ArrayVariable<BoolVariable, HEADER_PROOF_DEPTH>,
        proof: &ArrayVariable<TendermintHashVariable, HEADER_PROOF_DEPTH>,
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
        last_block_id_proof: &BlockIDInclusionProofVariable<HEADER_PROOF_DEPTH>,
    );

    /// Verify the next validators hash in the previous block matches the current block's validators hash.
    fn verify_prev_header_next_validators_hash(
        &mut self,
        validators_hash: TendermintHashVariable,
        prev_header: &TendermintHashVariable,
        prev_header_next_validators_hash_proof: &HashInclusionProofVariable<HEADER_PROOF_DEPTH>,
    );

    /// Verify a Tendermint consensus block.
    fn verify_header(
        &mut self,
        validators: &ArrayVariable<ValidatorVariable<Self::Curve>, VALIDATOR_SET_SIZE_MAX>,
        header: &TendermintHashVariable,
        // data_hash_proof: &HashInclusionProofVariable<HEADER_PROOF_DEPTH>,
        validator_hash_proof: &HashInclusionProofVariable<HEADER_PROOF_DEPTH>,
        // next_validators_hash_proof: &HashInclusionProofVariable<HEADER_PROOF_DEPTH>,
        round_present: &BoolVariable,
    );

    /// Sequentially verify a Tendermint consensus block.
    fn step(
        &mut self,
        validators: &ArrayVariable<ValidatorVariable<Self::Curve>, VALIDATOR_SET_SIZE_MAX>,
        header: &TendermintHashVariable,
        prev_header: &TendermintHashVariable,
        validator_hash_proof: &HashInclusionProofVariable<HEADER_PROOF_DEPTH>,
        prev_header_next_validators_hash_proof: &HashInclusionProofVariable<HEADER_PROOF_DEPTH>,
        last_block_id_proof: &BlockIDInclusionProofVariable<HEADER_PROOF_DEPTH>,
        round_present: &BoolVariable,
    );

    /// Verify the trusted validators have signed the trusted header.
    fn verify_trusted_validators(
        &mut self,
        validators: &ArrayVariable<ValidatorVariable<Self::Curve>, VALIDATOR_SET_SIZE_MAX>,
        trusted_header: TendermintHashVariable,
        trusted_validator_hash_proof: &HashInclusionProofVariable<HEADER_PROOF_DEPTH>,
        trusted_validator_hash_fields: &ArrayVariable<
            ValidatorHashFieldVariable<Self::Curve>,
            VALIDATOR_SET_SIZE_MAX,
        >,
    );

    /// Verify Tendermint block that is non-sequential with the trusted block.
    fn skip(
        &mut self,
        validators: &ArrayVariable<ValidatorVariable<Self::Curve>, VALIDATOR_SET_SIZE_MAX>,
        header: &TendermintHashVariable,
        header_height_proof: &HeightProofVariable,
        validator_hash_proof: &HashInclusionProofVariable<HEADER_PROOF_DEPTH>,
        round_present: &BoolVariable,
        trusted_header: TendermintHashVariable,
        trusted_validator_hash_proof: &HashInclusionProofVariable<HEADER_PROOF_DEPTH>,
        trusted_validator_hash_fields: &ArrayVariable<
            ValidatorHashFieldVariable<Self::Curve>,
            VALIDATOR_SET_SIZE_MAX,
        >,
    );

    // Assert the voting power of the signed validators is greater than the threshold.
    fn assert_voting_check(
        &mut self,
        validators: ArrayVariable<ValidatorVariable<Self::Curve>, VALIDATOR_SET_SIZE_MAX>,
        threshold_numerator: &U32Variable,
        threshold_denominator: &U32Variable,
        include_in_check: Vec<BoolVariable>, // TODO: this should be an array var of the same size
    );
}

impl<L: PlonkParameters<D>, const D: usize, const VALIDATOR_SET_SIZE_MAX: usize>
    TendermintVerify<L, D, VALIDATOR_SET_SIZE_MAX> for CircuitBuilder<L, D>
{
    type Curve = Ed25519;

    fn get_root<const LEAF_SIZE_BYTES: usize>(
        &mut self,
        leaf: &BytesVariable<LEAF_SIZE_BYTES>,
        path: &ArrayVariable<BoolVariable, HEADER_PROOF_DEPTH>,
        proof: &ArrayVariable<TendermintHashVariable, HEADER_PROOF_DEPTH>,
    ) -> Bytes32Variable {
        self.get_root_from_merkle_proof::<HEADER_PROOF_DEPTH, LEAF_SIZE_BYTES>(
            &MerkleInclusionProofVariable {
                leaf: *leaf,
                path_indices: path.clone(),
                aunts: proof.clone(),
            },
        )
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

    fn assert_voting_check(
        &mut self,
        validators: ArrayVariable<ValidatorVariable<Self::Curve>, VALIDATOR_SET_SIZE_MAX>,
        threshold_numerator: &U32Variable,
        threshold_denominator: &U32Variable,
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

    fn step(
        &mut self,
        validators: &ArrayVariable<ValidatorVariable<Self::Curve>, VALIDATOR_SET_SIZE_MAX>,
        header: &TendermintHashVariable,
        prev_header: &TendermintHashVariable,
        validator_hash_proof: &HashInclusionProofVariable<HEADER_PROOF_DEPTH>,
        prev_header_next_validators_hash_proof: &HashInclusionProofVariable<HEADER_PROOF_DEPTH>,
        last_block_id_proof: &BlockIDInclusionProofVariable<HEADER_PROOF_DEPTH>,
        round_present: &BoolVariable,
    ) {
        // Verify 2/3 of the validators signed the headers
        self.verify_header(validators, header, validator_hash_proof, round_present);

        // Verify the previous header hash in the block matches the previous header hash in the last block ID.
        // FIXME: why is Rust compiler being weird
        <plonky2x::prelude::CircuitBuilder<L, D> as TendermintVerify<
            L,
            D,
            VALIDATOR_SET_SIZE_MAX,
        >>::verify_prev_header_in_header(self, header, *prev_header, last_block_id_proof);

        // Extract the validators hash from the validator hash proof
        let validators_hash: Bytes32Variable =
            validator_hash_proof.enc_leaf[2..2 + HASH_SIZE].into();

        // Verify the next validators hash in the previous block matches the current validators hash
        // FIXME: why is Rust compiler being weird
        <plonky2x::prelude::CircuitBuilder<L, D> as TendermintVerify<
            L,
            D,
            VALIDATOR_SET_SIZE_MAX,
        >>::verify_prev_header_next_validators_hash(
            self,
            validators_hash,
            prev_header,
            prev_header_next_validators_hash_proof,
        );
    }

    fn verify_header(
        &mut self,
        validators: &ArrayVariable<ValidatorVariable<Self::Curve>, VALIDATOR_SET_SIZE_MAX>,
        header: &TendermintHashVariable,
        validator_hash_proof: &HashInclusionProofVariable<HEADER_PROOF_DEPTH>,
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
        let signatures =
            ArrayVariable::<EDDSASignatureTarget<Ed25519>, VALIDATOR_SET_SIZE_MAX>::new(
                validators
                    .as_vec()
                    .iter()
                    .map(|v| v.signature.clone())
                    .collect(),
            );
        let pubkeys = ArrayVariable::<EDDSAPublicKeyVariable<Ed25519>, VALIDATOR_SET_SIZE_MAX>::new(
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
        let extracted_hash: Bytes32Variable =
            validator_hash_proof.enc_leaf[2..2 + HASH_SIZE].into();

        self.assert_is_equal(extracted_hash, validators_hash_target);

        // Assert the accumulated voting power is greater than the threshold
        let threshold_numerator = self.constant::<U32Variable>(2u32);
        let threshold_denominator = self.constant::<U32Variable>(3u32);
        // TODO: why is rust compiler being so weird
        <plonky2x::prelude::CircuitBuilder<L, D> as TendermintVerify<
            L,
            D,
            VALIDATOR_SET_SIZE_MAX,
        >>::assert_voting_check(
            self,
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
            let hash_in_message = <plonky2x::prelude::CircuitBuilder<L, D> as TendermintVerify<
                L,
                D,
                VALIDATOR_SET_SIZE_MAX,
            >>::verify_hash_in_message(
                self, &validators[i].message, *header, *round_present
            );
            let hash_in_message_and_signed = self.and(hash_in_message, validators[i].signed);
            self.assert_is_equal(hash_in_message_and_signed, validators_signed[i]);
        }

        // Note: Hardcode the path for each of the leaf proofs (otherwise you can prove arbitrary data in the header)
        let val_hash_path = vec![true_t, true_t, true_t, false_t];

        let header_from_validator_root_proof =
            <plonky2x::prelude::CircuitBuilder<L, D> as TendermintVerify<
                L,
                D,
                VALIDATOR_SET_SIZE_MAX,
            >>::get_root::<34>(
                self,
                &validator_hash_proof.enc_leaf,
                &val_hash_path.try_into().unwrap(),
                &validator_hash_proof.proof,
            );

        self.assert_is_equal(*header, header_from_validator_root_proof);
    }

    fn verify_prev_header_in_header(
        &mut self,
        header: &TendermintHashVariable,
        prev_header: TendermintHashVariable,
        last_block_id_proof: &BlockIDInclusionProofVariable<HEADER_PROOF_DEPTH>,
    ) {
        let last_block_id_path = vec![self._false(), self._false(), self._true(), self._false()];
        let header_from_last_block_id_proof =
            <plonky2x::prelude::CircuitBuilder<L, D> as TendermintVerify<
                L,
                D,
                VALIDATOR_SET_SIZE_MAX,
            >>::get_root::<72>(
                self,
                &last_block_id_proof.enc_leaf,
                &last_block_id_path.try_into().unwrap(),
                &last_block_id_proof.proof,
            );
        // TODO: add back a comment here I think
        self.assert_is_equal(header_from_last_block_id_proof, *header);

        // Extract prev header hash from the encoded leaf (starts at second byte)
        let extracted_prev_header_hash: Bytes32Variable =
            last_block_id_proof.enc_leaf[2..2 + HASH_SIZE].into();
        self.assert_is_equal(prev_header, extracted_prev_header_hash);
    }

    fn verify_prev_header_next_validators_hash(
        &mut self,
        validators_hash: TendermintHashVariable,
        prev_header: &TendermintHashVariable,
        prev_header_next_validators_hash_proof: &HashInclusionProofVariable<HEADER_PROOF_DEPTH>,
    ) {
        let next_val_hash_path = vec![self._false(), self._false(), self._false(), self._true()];
        let header_from_next_validators_root_proof =
            <plonky2x::prelude::CircuitBuilder<L, D> as TendermintVerify<
                L,
                D,
                VALIDATOR_SET_SIZE_MAX,
            >>::get_root::<34>(
                self,
                &prev_header_next_validators_hash_proof.enc_leaf,
                &next_val_hash_path.try_into().unwrap(),
                &prev_header_next_validators_hash_proof.proof,
            );
        // Confirms the prev_header computed from the proof of {next_validators_hash} matches the prev_header
        self.assert_is_equal(header_from_next_validators_root_proof, *prev_header);

        // Extract prev header hash from the encoded leaf (starts at second byte)
        let extracted_next_validators_hash =
            prev_header_next_validators_hash_proof.enc_leaf[2..2 + HASH_SIZE].into();
        // Confirms the current validatorsHash matches the nextValidatorsHash of the prev_header
        self.assert_is_equal(validators_hash, extracted_next_validators_hash);
    }

    fn skip(
        &mut self,
        validators: &ArrayVariable<ValidatorVariable<Self::Curve>, VALIDATOR_SET_SIZE_MAX>,
        header: &TendermintHashVariable,
        header_height_proof: &HeightProofVariable,
        validator_hash_proof: &HashInclusionProofVariable<HEADER_PROOF_DEPTH>,
        round_present: &BoolVariable,
        trusted_header: TendermintHashVariable,
        trusted_validator_hash_proof: &HashInclusionProofVariable<HEADER_PROOF_DEPTH>,
        trusted_validator_hash_fields: &ArrayVariable<
            ValidatorHashFieldVariable<Self::Curve>,
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

    fn verify_trusted_validators(
        &mut self,
        validators: &ArrayVariable<ValidatorVariable<Self::Curve>, VALIDATOR_SET_SIZE_MAX>,
        trusted_header: TendermintHashVariable,
        trusted_validator_hash_proof: &HashInclusionProofVariable<HEADER_PROOF_DEPTH>,
        trusted_validator_hash_fields: &ArrayVariable<
            ValidatorHashFieldVariable<Self::Curve>,
            VALIDATOR_SET_SIZE_MAX,
        >,
    ) {
        // Note: A trusted validator is one who is present on the trusted header
        let false_t = self._false();
        let true_t = self._true();

        // Get the header from the validator hash merkle proof
        let val_hash_path = vec![true_t, true_t, true_t, false_t];
        let header_from_validator_root_proof =
            <plonky2x::prelude::CircuitBuilder<L, D> as TendermintVerify<
                L,
                D,
                VALIDATOR_SET_SIZE_MAX,
            >>::get_root::<PROTOBUF_HASH_SIZE_BYTES>(
                self,
                &trusted_validator_hash_proof.enc_leaf,
                &val_hash_path.try_into().unwrap(),
                &trusted_validator_hash_proof.proof,
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
        let extracted_hash = trusted_validator_hash_proof.enc_leaf[2..2 + HASH_SIZE].into();

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
        let threshold_numerator = self.constant::<U32Variable>(1);
        let threshold_denominator = self.constant::<U32Variable>(3);
        <plonky2x::prelude::CircuitBuilder<L, D> as TendermintVerify<
            L,
            D,
            VALIDATOR_SET_SIZE_MAX,
        >>::assert_voting_check(
            self,
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
    use log;
    use plonky2::timed;
    use plonky2::util::timing::TimingTree;
    use plonky2x::prelude::{DefaultBuilder, DefaultParameters};
    use subtle_encoding::hex;

    use super::*;
    // TODO: Remove dependency on inputs crate
    use crate::{
        consts::VALIDATOR_MESSAGE_BYTES_LENGTH_MAX,
        inputs::{
            generate_skip_inputs, generate_step_inputs, CelestiaSkipBlockProof,
            CelestiaStepBlockProof,
        },
    };

    type L = DefaultParameters;
    const D: usize = 2;

    #[test]
    fn test_verify_hash_in_message() {
        // This is a test case generated from block 144094 of Celestia's Mocha 3 testnet
        // Block Hash: 8909e1b73b7d987e95a7541d96ed484c17a4b0411e98ee4b7c890ad21302ff8c (needs to be lower case)
        // Signed Message (from the last validator): 6b080211de3202000000000022480a208909e1b73b7d987e95a7541d96ed484c17a4b0411e98ee4b7c890ad21302ff8c12240801122061263df4855e55fcab7aab0a53ee32cf4f29a1101b56de4a9d249d44e4cf96282a0b089dce84a60610ebb7a81932076d6f6368612d33
        // No round exists in present the message that was signed above

        env_logger::try_init().unwrap_or_default();
        const VALIDATOR_SET_SIZE_MAX: usize = 2;

        // Define the circuit
        let mut builder = DefaultBuilder::new();
        let message = builder.read::<ValidatorMessageVariable>();
        let header_hash = builder.read::<TendermintHashVariable>();
        let round_present_in_message = builder.read::<BoolVariable>();

        let verified = <plonky2x::prelude::CircuitBuilder<L, D> as TendermintVerify<
            L,
            D,
            VALIDATOR_SET_SIZE_MAX,
        >>::verify_hash_in_message(
            &mut builder,
            &message,
            header_hash,
            round_present_in_message,
        );

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

    // fn test_step_template<const VALIDATOR_SET_SIZE_MAX: usize>(block: usize) {
    //     env_logger::try_init().unwrap_or_default();

    //     type Curve = Ed25519;
    //     const HEADER_PROOF_DEPTH: usize = 4;

    //     let mut timing = TimingTree::new("Verify Celestia Step", log::Level::Debug);

    //     // We put input generation at the top so that we can debug that first without having the expensive build step part
    //     println!("Generating inputs");
    //     // Note: Length of output is the closest power of 2 gte the number of validators for this block.
    //     let celestia_block_proof: CelestiaStepBlockProof =
    //         generate_step_inputs::<VALIDATOR_SET_SIZE_MAX>(block);
    //     println!(
    //         "Number of validators: {}",
    //         celestia_block_proof.base.validators.len()
    //     );

    //     println!("Making step circuit");
    //     let mut builder = DefaultBuilder::new();
    //     // TODO: for some reason, having the validators as public inputs doesn't work
    //     // It only works up to validator set size 2, then we get a panic
    //     // So we set the validators variable to a constant for now.
    //     let validators = builder
    //         .constant::<ArrayVariable<ValidatorVariable<Curve>, VALIDATOR_SET_SIZE_MAX>>(
    //             celestia_block_proof.base.validators,
    //         );
    //     let header = builder.read::<TendermintHashVariable>();
    //     let prev_header = builder.read::<TendermintHashVariable>();

    //     let validator_hash_proof = builder.read::<HashInclusionProofVariable<HEADER_PROOF_DEPTH>>();

    //     let prev_header_next_validators_hash_proof =
    //         builder.read::<HashInclusionProofVariable<HEADER_PROOF_DEPTH>>();
    //     let last_block_id_proof =
    //         builder.read::<BlockIDInclusionProofVariable<HEADER_PROOF_DEPTH>>();
    //     let round_present = builder.read::<BoolVariable>();

    //     builder.step(
    //         &validators,
    //         &header,
    //         &prev_header,
    //         &validator_hash_proof,
    //         &prev_header_next_validators_hash_proof,
    //         &last_block_id_proof,
    //         &round_present,
    //     );

    //     println!("Building circuit");
    //     let circuit = builder.build();
    //     println!("num gates: {:?}", circuit.data.common.gates.len());

    //     let mut input = circuit.input();
    //     // TODO: for some reason having the Validators as public inputs doesn't work
    //     // input.write::<ArrayVariable<ValidatorVariable<Curve>, VALIDATOR_SET_SIZE_MAX>>(
    //     //     celestia_block_proof.base.validators,
    //     // );
    //     input.write::<TendermintHashVariable>(celestia_block_proof.base.header);
    //     input.write::<TendermintHashVariable>(celestia_block_proof.prev_header);
    //     input.write::<HashInclusionProofVariable<HEADER_PROOF_DEPTH>>(
    //         celestia_block_proof.base.validator_hash_proof.into(),
    //     );
    //     input.write::<HashInclusionProofVariable<HEADER_PROOF_DEPTH>>(
    //         celestia_block_proof
    //             .prev_header_next_validators_hash_proof
    //             .into(),
    //     );
    //     input.write::<BlockIDInclusionProofVariable<HEADER_PROOF_DEPTH>>(
    //         celestia_block_proof.last_block_id_proof.into(),
    //     );
    //     input.write::<BoolVariable>(celestia_block_proof.base.round_present);

    //     let (proof, output) = timed!(timing, "Step proof time", circuit.prove(&input));
    //     circuit.verify(&proof, &input, &output);
    //     timing.print();
    // }

    // fn test_skip_template<const VALIDATOR_SET_SIZE_MAX: usize>(trusted_block: usize, block: usize) {
    //     env_logger::try_init().unwrap_or_default();

    //     type Curve = Ed25519;
    //     const HEADER_PROOF_DEPTH: usize = 4;

    //     let mut timing = TimingTree::new("Verify Celestia skip", log::Level::Debug);

    //     println!("Generating inputs");
    //     // Note: Length of output is the closest power of 2 gte the number of validators for this block.
    //     let celestia_skip_block_proof: CelestiaSkipBlockProof =
    //         generate_skip_inputs::<VALIDATOR_SET_SIZE_MAX>(trusted_block, block);
    //     println!(
    //         "Number of validators: {}",
    //         celestia_skip_block_proof.base.validators.len()
    //     );

    //     println!("Making skip circuit");
    //     let mut builder = DefaultBuilder::new();
    //     let validators =
    //         builder.read::<ArrayVariable<ValidatorVariable<Curve>, VALIDATOR_SET_SIZE_MAX>>();

    //     let header = builder.read::<TendermintHashVariable>();

    //     let header_height_proof = builder.read::<HeightProofVariable>();
    //     let validator_hash_proof = builder.read::<HashInclusionProofVariable<HEADER_PROOF_DEPTH>>();

    //     let round_present = builder.read::<BoolVariable>();
    //     let trusted_header = builder.read::<TendermintHashVariable>();
    //     let trusted_validators_hash_proof =
    //         builder.read::<HashInclusionProofVariable<HEADER_PROOF_DEPTH>>();
    //     let trusted_validators_hash_fields = builder
    //         .read::<ArrayVariable<ValidatorHashFieldVariable<Curve>, VALIDATOR_SET_SIZE_MAX>>();

    //     builder.skip(
    //         &validators,
    //         &header,
    //         &header_height_proof,
    //         &validator_hash_proof,
    //         &round_present,
    //         trusted_header,
    //         &trusted_validators_hash_proof,
    //         &trusted_validators_hash_fields,
    //     );

    //     println!("Building circuit");
    //     let circuit = builder.build();
    //     println!("num gates: {:?}", circuit.data.common.gates.len());

    //     let mut input = circuit.input();
    //     input.write::<ArrayVariable<ValidatorVariable<Curve>, VALIDATOR_SET_SIZE_MAX>>(
    //         celestia_skip_block_proof.base.validators,
    //     );
    //     input.write::<TendermintHashVariable>(celestia_skip_block_proof.base.header);

    //     input.write::<HeightProofVariable>(celestia_skip_block_proof.block_height_proof);
    //     input.write::<HashInclusionProofVariable<HEADER_PROOF_DEPTH>>(
    //         celestia_skip_block_proof.base.validator_hash_proof.into(),
    //     );

    //     input.write::<BoolVariable>(celestia_skip_block_proof.base.round_present);
    //     input.write::<TendermintHashVariable>(celestia_skip_block_proof.trusted_header);
    //     input.write::<HashInclusionProofVariable<HEADER_PROOF_DEPTH>>(
    //         celestia_skip_block_proof
    //             .trusted_validator_hash_proof
    //             .into(),
    //     );
    //     input.write::<ArrayVariable<ValidatorHashFieldVariable<Curve>, VALIDATOR_SET_SIZE_MAX>>(
    //         celestia_skip_block_proof.trusted_validator_fields,
    //     );

    //     let (proof, output) = timed!(timing, "Skip proof time", circuit.prove(&input));
    //     circuit.verify(&proof, &input, &output);

    //     timing.print();
    // }

    // #[test]
    // #[cfg_attr(feature = "ci", ignore)]
    // fn test_step_with_dummy_sigs() {
    //     // Testing block 11105 (4 validators, 2 signed)
    //     // Need to handle empty validators as well
    //     // Should set some dummy values
    //     let block = 11105;

    //     const VALIDATOR_SET_SIZE_MAX: usize = 8;

    //     test_step_template::<VALIDATOR_SET_SIZE_MAX>(block);
    // }

    // #[test]
    // #[cfg_attr(feature = "ci", ignore)]
    // fn test_step_small() {
    //     // Testing block 11000
    //     let block = 11000;

    //     const VALIDATOR_SET_SIZE_MAX: usize = 4;

    //     test_step_template::<VALIDATOR_SET_SIZE_MAX>(block);
    // }

    // #[test]
    // #[cfg_attr(feature = "ci", ignore)]
    // fn test_step_with_empty() {
    //     // Testing block 10000
    //     let block = 10000;

    //     const VALIDATOR_SET_SIZE_MAX: usize = 4;

    //     test_step_template::<VALIDATOR_SET_SIZE_MAX>(block);
    // }

    // #[test]
    // #[cfg_attr(feature = "ci", ignore)]
    // fn test_step_large() {
    //     // Testing block 75000
    //     // 77 validators (128)
    //     // Block 50000
    //     // 32 validators
    //     // Block 15000
    //     // 16 validators
    //     // Testing block 60000
    //     // 60 validators, 4 disabled (valhash)

    //     let block = 75000;

    //     const VALIDATOR_SET_SIZE_MAX: usize = 128;

    //     test_step_template::<VALIDATOR_SET_SIZE_MAX>(block);
    // }

    // #[test]
    // #[cfg_attr(feature = "ci", ignore)]
    // fn test_skip_small() {
    //     // Testing skip from 11000 to 11105
    //     let trusted_block = 11000;

    //     let block = 11105;

    //     const VALIDATOR_SET_SIZE_MAX: usize = 4;

    //     test_skip_template::<VALIDATOR_SET_SIZE_MAX>(trusted_block, block);
    // }

    // #[test]
    // #[cfg_attr(feature = "ci", ignore)]
    // fn test_skip_large() {
    //     // Testing skip from 60000 to 75000

    //     // 75000 has 128 validator max
    //     let trusted_block = 60000;

    //     let block = 75000;

    //     const VALIDATOR_SET_SIZE_MAX: usize = 128;

    //     test_skip_template::<VALIDATOR_SET_SIZE_MAX>(trusted_block, block);
    // }
}
