//! The protobuf encoding of a Tendermint validator is a deterministic function of the validator's
//! public key (32 bytes) and voting power (int64). The encoding is as follows in bytes:
//
//!     10 34 10 32 <pubkey> 16 <varint>
//
//! The `pubkey` is encoded as the raw list of bytes used in the public key. The `varint` is
//! encoded using protobuf's default integer encoding, which consist of 7 bit payloads. You can
//! read more about them here: https://protobuf.dev/programming-guides/encoding/#varints.

use plonky2x::{
    frontend::ecc::ed25519::{
        curve::{curve_types::Curve, ed25519::Ed25519},
        gadgets::eddsa::EDDSASignatureTarget,
    },
    frontend::uint::uint64::U64Variable,
    frontend::vars::U32Variable,
    prelude::{
        ArrayVariable, BoolVariable, Bytes32Variable, BytesVariable, CircuitBuilder,
        CircuitVariable, PlonkParameters, RichField, Variable, Witness, WitnessWrite,
    },
};

use crate::utils::{
    EDDSAPublicKeyVariable, EncBlockIDVariable, EncTendermintHashVariable, TendermintHashVariable,
    ValidatorMessageVariable,
};
use crate::{
    signature::TendermintSignature,
    utils::{MarshalledValidatorVariable, PROTOBUF_BLOCK_ID_SIZE_BYTES, PROTOBUF_HASH_SIZE_BYTES},
    validator::TendermintValidator,
    voting::TendermintVoting,
};

#[derive(Debug, Clone, CircuitVariable)]
#[value_name(Validator)]
pub struct ValidatorVariable<C: Curve> {
    pub pubkey: EDDSAPublicKeyVariable<C>,
    pub signature: EDDSASignatureTarget<C>,
    pub message: ValidatorMessageVariable,
    pub message_bit_length: Variable,
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
    // Path and proof should have a fixed length of HEADER_PROOF_DEPTH.
    // path: ArrayVariable<BoolVariable, HEADER_PROOF_DEPTH>,
    pub proof: ArrayVariable<TendermintHashVariable, HEADER_PROOF_DEPTH>,
}

/// The protobuf-encoded leaf (a tendermint block ID), and it's corresponding proof and path indices against the header.
#[derive(Debug, Clone, CircuitVariable)]
#[value_name(BlockIDInclusionProof)]
pub struct BlockIDInclusionProofVariable<const HEADER_PROOF_DEPTH: usize> {
    pub enc_leaf: EncBlockIDVariable,
    // Path and proof should have a fixed length of HEADER_PROOF_DEPTH.
    // path: ArrayVariable<BoolVariable, HEADER_PROOF_DEPTH>,
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
    const HEADER_PROOF_DEPTH: usize,
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

    /// Verifies that the previous header hash in the block matches the previous header hash in the last block ID.
    fn verify_prev_header_in_header(
        &mut self,
        header: &TendermintHashVariable,
        prev_header: &TendermintHashVariable,
        last_block_id_proof: &BlockIDInclusionProofVariable<HEADER_PROOF_DEPTH>,
    );

    /// Verifies that the previous header hash in the block matches the previous header hash in the last block ID.
    fn verify_prev_header_next_validators_hash(
        &mut self,
        validators_hash: &TendermintHashVariable,
        prev_header: &TendermintHashVariable,
        prev_header_next_validators_hash_proof: &HashInclusionProofVariable<HEADER_PROOF_DEPTH>,
    );

    /// Verifies a Tendermint consensus block.
    fn verify_header(
        &mut self,
        validators: &ArrayVariable<ValidatorVariable<Self::Curve>, VALIDATOR_SET_SIZE_MAX>,
        header: &TendermintHashVariable,
        data_hash_proof: &HashInclusionProofVariable<HEADER_PROOF_DEPTH>,
        validator_hash_proof: &HashInclusionProofVariable<HEADER_PROOF_DEPTH>,
        next_validators_hash_proof: &HashInclusionProofVariable<HEADER_PROOF_DEPTH>,
        round_present: &BoolVariable,
    );

    /// Sequentially verifies a Tendermint consensus block.
    fn step(
        &mut self,
        validators: &ArrayVariable<ValidatorVariable<Self::Curve>, VALIDATOR_SET_SIZE_MAX>,
        header: &TendermintHashVariable,
        prev_header: &TendermintHashVariable,
        data_hash_proof: &HashInclusionProofVariable<HEADER_PROOF_DEPTH>,
        validator_hash_proof: &HashInclusionProofVariable<HEADER_PROOF_DEPTH>,
        next_validators_hash_proof: &HashInclusionProofVariable<HEADER_PROOF_DEPTH>,
        prev_header_next_validators_hash_proof: &HashInclusionProofVariable<HEADER_PROOF_DEPTH>,
        last_block_id_proof: &BlockIDInclusionProofVariable<HEADER_PROOF_DEPTH>,
        round_present: &BoolVariable,
    );

    /// Verifies that the trusted validators have signed the current header.
    fn verify_trusted_validators(
        &mut self,
        validators: &ArrayVariable<ValidatorVariable<Self::Curve>, VALIDATOR_SET_SIZE_MAX>,
        trusted_header: &TendermintHashVariable,
        trusted_validator_hash_proof: &HashInclusionProofVariable<HEADER_PROOF_DEPTH>,
        trusted_validator_hash_fields: &ArrayVariable<
            ValidatorHashFieldVariable<Self::Curve>,
            VALIDATOR_SET_SIZE_MAX,
        >,
    );

    /// Verifies a Tendermint block that is non-sequential with the trusted block.
    fn skip(
        &mut self,
        validators: &ArrayVariable<ValidatorVariable<Self::Curve>, VALIDATOR_SET_SIZE_MAX>,
        header: &TendermintHashVariable,
        data_hash_proof: &HashInclusionProofVariable<HEADER_PROOF_DEPTH>,
        validator_hash_proof: &HashInclusionProofVariable<HEADER_PROOF_DEPTH>,
        next_validators_hash_proof: &HashInclusionProofVariable<HEADER_PROOF_DEPTH>,
        round_present: &BoolVariable,
        trusted_header: &TendermintHashVariable,
        trusted_validator_hash_proof: &HashInclusionProofVariable<HEADER_PROOF_DEPTH>,
        trusted_validator_hash_fields: &ArrayVariable<
            ValidatorHashFieldVariable<Self::Curve>,
            VALIDATOR_SET_SIZE_MAX,
        >,
    );

    fn assert_voting_check(
        &mut self,
        validators: ArrayVariable<ValidatorVariable<Self::Curve>, VALIDATOR_SET_SIZE_MAX>,
        threshold_numerator: &U32Variable,
        threshold_denominator: &U32Variable,
        include_in_check: Vec<BoolVariable>, // TODO: this should be an array var of the same size
    );
}

impl<
        L: PlonkParameters<D>,
        const D: usize,
        const HEADER_PROOF_DEPTH: usize,
        const VALIDATOR_SET_SIZE_MAX: usize,
    > TendermintVerify<L, D, HEADER_PROOF_DEPTH, VALIDATOR_SET_SIZE_MAX> for CircuitBuilder<L, D>
{
    type Curve = Ed25519;

    fn get_root<const LEAF_SIZE_BYTES: usize>(
        &mut self,
        leaf: &BytesVariable<LEAF_SIZE_BYTES>,
        path: &ArrayVariable<BoolVariable, HEADER_PROOF_DEPTH>,
        proof: &ArrayVariable<TendermintHashVariable, HEADER_PROOF_DEPTH>,
    ) -> Bytes32Variable {
        let hashed_leaf = self.leaf_hash(&leaf.0);
        self.get_root_from_merkle_proof_hashed_leaf(proof, path, hashed_leaf)
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
            &threshold_numerator,
            &threshold_denominator,
        );
        let t = self._true();
        self.assert_is_equal(check_voting_power_bool, t);
    }

    fn step(
        &mut self,
        validators: &ArrayVariable<ValidatorVariable<Self::Curve>, VALIDATOR_SET_SIZE_MAX>,
        header: &TendermintHashVariable,
        prev_header: &TendermintHashVariable,
        data_hash_proof: &HashInclusionProofVariable<HEADER_PROOF_DEPTH>,
        validator_hash_proof: &HashInclusionProofVariable<HEADER_PROOF_DEPTH>,
        next_validators_hash_proof: &HashInclusionProofVariable<HEADER_PROOF_DEPTH>,
        prev_header_next_validators_hash_proof: &HashInclusionProofVariable<HEADER_PROOF_DEPTH>,
        last_block_id_proof: &BlockIDInclusionProofVariable<HEADER_PROOF_DEPTH>,
        round_present: &BoolVariable,
    ) {
        // Verifies that 2/3 of the validators signed the headers
        self.verify_header(
            validators,
            header,
            data_hash_proof,
            validator_hash_proof,
            next_validators_hash_proof,
            round_present,
        );

        // Verifies that the previous header hash in the block matches the previous header hash in the last block ID.
        // self.verify_prev_header_in_header(header, prev_header, last_block_id_proof);
        // FIXME: why is Rust compiler being weird
        <plonky2x::prelude::CircuitBuilder<L, D> as TendermintVerify<
            L,
            D,
            HEADER_PROOF_DEPTH,
            VALIDATOR_SET_SIZE_MAX,
        >>::verify_prev_header_in_header(self, header, prev_header, last_block_id_proof);

        // Extract the validators hash from the validator hash proof
        const HASH_START_BYTE: usize = 2;
        let validators_hash = self
            .extract_hash_from_protobuf::<HASH_START_BYTE, PROTOBUF_HASH_SIZE_BYTES>(
                &validator_hash_proof.enc_leaf,
            );

        // Verifies that the next validators hash in the previous block matches the current validators hash
        // self.verify_prev_header_next_validators_hash(
        //     &validators_hash,
        //     prev_header,
        //     prev_header_next_validators_hash_proof,
        // );
        // FIXME: why is Rust compiler being weird

        <plonky2x::prelude::CircuitBuilder<L, D> as TendermintVerify<
            L,
            D,
            HEADER_PROOF_DEPTH,
            VALIDATOR_SET_SIZE_MAX,
        >>::verify_prev_header_next_validators_hash(
            self,
            &validators_hash,
            prev_header,
            prev_header_next_validators_hash_proof,
        );
    }

    fn verify_header(
        &mut self,
        validators: &ArrayVariable<ValidatorVariable<Self::Curve>, VALIDATOR_SET_SIZE_MAX>,
        header: &TendermintHashVariable,
        data_hash_proof: &HashInclusionProofVariable<HEADER_PROOF_DEPTH>,
        validator_hash_proof: &HashInclusionProofVariable<HEADER_PROOF_DEPTH>,
        next_validators_hash_proof: &HashInclusionProofVariable<HEADER_PROOF_DEPTH>,
        round_present: &BoolVariable,
    ) {
        let false_t = self._false();
        let true_t = self._true();
        // Verify each of the validators marshal correctly
        // Assumes the validators are sorted in the correct order

        // TODO: clean up below, it's a bit horrendous
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

        // Fields used for verifying signatures
        let validators_signed: Vec<BoolVariable> =
            validators.as_vec().iter().map(|v| v.signed).collect();
        let messages: Vec<ValidatorMessageVariable> =
            validators.as_vec().iter().map(|v| v.message).collect();
        let message_bit_lengths: Vec<U32Variable> = validators
            .as_vec()
            .iter()
            .map(|v| U32Variable(v.message_bit_length))
            .collect();
        let signatures: Vec<EDDSASignatureTarget<Ed25519>> = validators
            .as_vec()
            .iter()
            .map(|v| v.signature.clone())
            .collect();
        let pubkeys: Vec<EDDSAPublicKeyVariable<Ed25519>> = validators
            .as_vec()
            .iter()
            .map(|v| v.pubkey.clone())
            .collect();

        // Verifies signatures of the validators
        self.verify_signatures::<VALIDATOR_SET_SIZE_MAX>(
            &validators_signed,
            messages,
            message_bit_lengths,
            signatures,
            pubkeys,
        );

        // Compute the validators hash
        let validators_hash_target = self.hash_validator_set::<VALIDATOR_SET_SIZE_MAX>(
            &marshalled_validators,
            &byte_lengths,
            &validators_enabled,
        );

        /// Start of the hash in protobuf encoded validator hash & last block id
        const HASH_START_BYTE: usize = 2;
        // Assert that computed validator hash matches expected validator hash
        let extracted_hash = self
            .extract_hash_from_protobuf::<HASH_START_BYTE, PROTOBUF_HASH_SIZE_BYTES>(
                &validator_hash_proof.enc_leaf,
            );

        self.assert_is_equal(extracted_hash, validators_hash_target);

        // Assert the accumulated voting power is greater than the threshold
        let threshold_numerator = self.constant::<U32Variable>(2u32);
        let threshold_denominator = self.constant::<U32Variable>(3u32);
        // TODO: why is rust compiler being so weird
        // self.assert_voting_check(
        //     *validators,
        //     &threshold_numerator,
        //     &threshold_denominator,
        //     validators_signed,
        // );
        <plonky2x::prelude::CircuitBuilder<L, D> as TendermintVerify<
            L,
            D,
            HEADER_PROOF_DEPTH,
            VALIDATOR_SET_SIZE_MAX,
        >>::assert_voting_check(
            self,
            validators.clone(),
            &threshold_numerator,
            &threshold_denominator,
            validators_signed.clone(),
        );

        // // Verify that the header is included in each message signed by an enabled validator
        for i in 0..VALIDATOR_SET_SIZE_MAX {
            // Verify that the header is in the message in the correct location
            let hash_in_message =
                self.verify_hash_in_message(&validators[i].message, *header, *round_present);

            // If the validator is enabled, then the hash should be in the message
            // TODO: this might be overconstrained because of the edge case where the validator did not sign
            // but hash is still in message
            // This is likely not a problem since DUMMY_MESSAGE is hardcoded in the circuit
            // But worth nothing
            self.assert_is_equal(hash_in_message, validators_signed[i]);
        }

        // Note: Hardcode the path for each of the leaf proofs (otherwise you can prove arbitrary data in the header)
        let data_hash_path = vec![false_t, true_t, true_t, false_t];
        let val_hash_path = vec![true_t, true_t, true_t, false_t];
        let next_val_hash_path = vec![false_t, false_t, false_t, true_t];

        let header_from_data_root_proof =
            <plonky2x::prelude::CircuitBuilder<L, D> as TendermintVerify<
                L,
                D,
                HEADER_PROOF_DEPTH,
                VALIDATOR_SET_SIZE_MAX,
            >>::get_root::<34>(
                self,
                &data_hash_proof.enc_leaf,
                &data_hash_path.try_into().unwrap(),
                &data_hash_proof.proof,
            );
        let header_from_validator_root_proof =
            <plonky2x::prelude::CircuitBuilder<L, D> as TendermintVerify<
                L,
                D,
                HEADER_PROOF_DEPTH,
                VALIDATOR_SET_SIZE_MAX,
            >>::get_root::<34>(
                self,
                &validator_hash_proof.enc_leaf,
                &val_hash_path.try_into().unwrap(),
                &validator_hash_proof.proof,
            );
        let header_from_next_validators_root_proof =
            <plonky2x::prelude::CircuitBuilder<L, D> as TendermintVerify<
                L,
                D,
                HEADER_PROOF_DEPTH,
                VALIDATOR_SET_SIZE_MAX,
            >>::get_root::<34>(
                self,
                &next_validators_hash_proof.enc_leaf,
                &next_val_hash_path.try_into().unwrap(),
                &next_validators_hash_proof.proof,
            );

        // Confirm that the header from the proof of {validator_hash, next_validators_hash, data_hash, last_block_id} all match the header
        self.assert_is_equal(*header, header_from_data_root_proof);
        self.assert_is_equal(*header, header_from_validator_root_proof);
        self.assert_is_equal(*header, header_from_next_validators_root_proof);
    }

    fn verify_prev_header_in_header(
        &mut self,
        header: &TendermintHashVariable,
        prev_header: &TendermintHashVariable,
        last_block_id_proof: &BlockIDInclusionProofVariable<HEADER_PROOF_DEPTH>,
    ) {
        /// Start of the hash in protobuf in last block id
        const HASH_START_BYTE: usize = 2;

        let last_block_id_path = vec![self._false(), self._false(), self._true(), self._false()];
        let header_from_last_block_id_proof =
            <plonky2x::prelude::CircuitBuilder<L, D> as TendermintVerify<
                L,
                D,
                HEADER_PROOF_DEPTH,
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
        let extracted_prev_header_hash = self
            .extract_hash_from_protobuf::<HASH_START_BYTE, PROTOBUF_BLOCK_ID_SIZE_BYTES>(
                &last_block_id_proof.enc_leaf,
            );
        self.assert_is_equal(*prev_header, extracted_prev_header_hash);
    }

    fn verify_prev_header_next_validators_hash(
        &mut self,
        validators_hash: &TendermintHashVariable,
        prev_header: &TendermintHashVariable,
        prev_header_next_validators_hash_proof: &HashInclusionProofVariable<HEADER_PROOF_DEPTH>,
    ) {
        let next_val_hash_path = vec![self._false(), self._false(), self._false(), self._true()];
        let header_from_next_validators_root_proof =
            <plonky2x::prelude::CircuitBuilder<L, D> as TendermintVerify<
                L,
                D,
                HEADER_PROOF_DEPTH,
                VALIDATOR_SET_SIZE_MAX,
            >>::get_root::<34>(
                self,
                &prev_header_next_validators_hash_proof.enc_leaf,
                &next_val_hash_path.try_into().unwrap(),
                &prev_header_next_validators_hash_proof.proof,
            );
        // Confirm that the prev_header computed from the proof of {next_validators_hash} matches the prev_header
        self.assert_is_equal(header_from_next_validators_root_proof, *prev_header);

        /// Start of the hash in protobuf in next_validators_hash
        const HASH_START_BYTE: usize = 2;

        // Extract prev header hash from the encoded leaf (starts at second byte)
        let extracted_next_validators_hash = self
            .extract_hash_from_protobuf::<HASH_START_BYTE, PROTOBUF_HASH_SIZE_BYTES>(
                &prev_header_next_validators_hash_proof.enc_leaf,
            );
        // Confirm that the current validatorsHash matches the nextValidatorsHash of the prev_header
        self.assert_is_equal(*validators_hash, extracted_next_validators_hash);
    }

    fn skip(
        &mut self,
        validators: &ArrayVariable<ValidatorVariable<Self::Curve>, VALIDATOR_SET_SIZE_MAX>,
        header: &TendermintHashVariable,
        data_hash_proof: &HashInclusionProofVariable<HEADER_PROOF_DEPTH>,
        validator_hash_proof: &HashInclusionProofVariable<HEADER_PROOF_DEPTH>,
        next_validators_hash_proof: &HashInclusionProofVariable<HEADER_PROOF_DEPTH>,
        round_present: &BoolVariable,
        trusted_header: &TendermintHashVariable,
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

        self.verify_header(
            validators,
            header,
            data_hash_proof,
            validator_hash_proof,
            next_validators_hash_proof,
            round_present,
        );
    }

    fn verify_trusted_validators(
        &mut self,
        validators: &ArrayVariable<ValidatorVariable<Self::Curve>, VALIDATOR_SET_SIZE_MAX>,
        trusted_header: &TendermintHashVariable,
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
                HEADER_PROOF_DEPTH,
                VALIDATOR_SET_SIZE_MAX,
            >>::get_root::<34>(
                self,
                &trusted_validator_hash_proof.enc_leaf,
                &val_hash_path.try_into().unwrap(),
                &trusted_validator_hash_proof.proof,
            );

        // Confirm the validator hash proof matches the trusted header
        self.assert_is_equal(header_from_validator_root_proof, *trusted_header);

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
            &trusted_validators_enabled,
        );

        const HASH_START_BYTE: usize = 2;
        // Assert the computed validator hash matches the expected validator hash
        let extracted_hash = self
            .extract_hash_from_protobuf::<HASH_START_BYTE, PROTOBUF_HASH_SIZE_BYTES>(
                &trusted_validator_hash_proof.enc_leaf,
            );
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

        // If a validator is present, then its pubkey should be present in the trusted validators
        for i in 0..VALIDATOR_SET_SIZE_MAX {
            let mut pubkey_match = self._false();
            for j in 0..VALIDATOR_SET_SIZE_MAX {
                let pubkey_match_idx = self.is_equal(
                    validators[i].pubkey.clone(),
                    trusted_validator_hash_fields[j].pubkey.clone(),
                );
                pubkey_match = self.or(pubkey_match, pubkey_match_idx);
            }
            // It is possible for a validator to be present on the trusted header, but not have signed this header.
            let match_and_present = self.and(pubkey_match, validators[i].present_on_trusted_header);

            // If you are present, then you should have a matching pubkey
            self.assert_is_equal(validators[i].present_on_trusted_header, match_and_present);
        }

        let present_on_trusted_header: Vec<BoolVariable> = validators
            .as_vec()
            .iter()
            .map(|v| v.present_on_trusted_header)
            .collect();

        // The trusted validators must comprise at least 1/3 of the total voting power
        // Assert the voting power from the trusted validators is greater than the threshold
        let threshold_numerator = self.constant::<U32Variable>(1);
        let threshold_denominator = self.constant::<U32Variable>(3);
        <plonky2x::prelude::CircuitBuilder<L, D> as TendermintVerify<
            L,
            D,
            HEADER_PROOF_DEPTH,
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

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use ethers::types::H256;
    use ethers::utils::hex;
    use log;
    use plonky2::timed;
    use plonky2::util::timing::TimingTree;
    use plonky2x::prelude::DefaultBuilder;
    use std::env;

    use crate::inputs::{
        generate_skip_inputs, generate_step_inputs, CelestiaSkipBlockProof, CelestiaStepBlockProof,
    };
    use crate::utils::VALIDATOR_MESSAGE_BYTES_LENGTH_MAX;

    // TODO: this test should be moved to the `signature` file
    #[test]
    fn test_verify_hash_in_message() {
        // This is a test case generated from block 144094 of Celestia's Mocha testnet
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

    fn test_step_template<const VALIDATOR_SET_SIZE_MAX: usize>(block: usize) {
        env::set_var("RUST_LOG", "debug");
        env_logger::try_init().unwrap_or_default();

        type Curve = Ed25519;
        const HEADER_PROOF_DEPTH: usize = 4;

        let mut timing = TimingTree::new("Verify Celestia Step", log::Level::Debug);

        // We put input generation at the top so that we can debug that first without having the expensive build step part
        println!("Generating inputs");
        // Note: Length of output is the closest power of 2 gte the number of validators for this block.
        let celestia_block_proof: CelestiaStepBlockProof =
            generate_step_inputs::<VALIDATOR_SET_SIZE_MAX>(block);
        println!(
            "Number of validators: {}",
            celestia_block_proof.base.validators.len()
        );

        println!("Making step circuit");
        let mut builder = DefaultBuilder::new();
        // TODO: for some reason, having the validators as public inputs doesn't work
        // It only works up to validator set size 2, then we get a panic
        // So we set the validators variable to a constant for now.
        let validators = builder
            .constant::<ArrayVariable<ValidatorVariable<Curve>, VALIDATOR_SET_SIZE_MAX>>(
                celestia_block_proof.base.validators,
            );
        let header = builder.read::<TendermintHashVariable>();
        let prev_header = builder.read::<TendermintHashVariable>();
        let data_hash_proof = builder.read::<HashInclusionProofVariable<HEADER_PROOF_DEPTH>>();
        let validator_hash_proof = builder.read::<HashInclusionProofVariable<HEADER_PROOF_DEPTH>>();
        let next_validators_hash_proof =
            builder.read::<HashInclusionProofVariable<HEADER_PROOF_DEPTH>>();
        let prev_header_next_validators_hash_proof =
            builder.read::<HashInclusionProofVariable<HEADER_PROOF_DEPTH>>();
        let last_block_id_proof =
            builder.read::<BlockIDInclusionProofVariable<HEADER_PROOF_DEPTH>>();
        let round_present = builder.read::<BoolVariable>();

        builder.step(
            &validators,
            &header,
            &prev_header,
            &data_hash_proof,
            &validator_hash_proof,
            &next_validators_hash_proof,
            &prev_header_next_validators_hash_proof,
            &last_block_id_proof,
            &round_present,
        );

        println!("Building circuit");
        let circuit = builder.mock_build();
        println!("num gates: {:?}", circuit.data.common.gates.len());

        let mut input = circuit.input();
        // TODO: for some reason having the Validators as public inputs doesn't work
        // input.write::<ArrayVariable<ValidatorVariable<Curve>, VALIDATOR_SET_SIZE_MAX>>(
        //     celestia_block_proof.base.validators,
        // );
        input.write::<TendermintHashVariable>(celestia_block_proof.base.header);
        input.write::<TendermintHashVariable>(celestia_block_proof.prev_header);
        input.write::<HashInclusionProofVariable<HEADER_PROOF_DEPTH>>(
            celestia_block_proof.base.data_hash_proof.into(),
        );
        input.write::<HashInclusionProofVariable<HEADER_PROOF_DEPTH>>(
            celestia_block_proof.base.validator_hash_proof.into(),
        );
        input.write::<HashInclusionProofVariable<HEADER_PROOF_DEPTH>>(
            celestia_block_proof.base.next_validators_hash_proof.into(),
        );
        input.write::<HashInclusionProofVariable<HEADER_PROOF_DEPTH>>(
            celestia_block_proof
                .prev_header_next_validators_hash_proof
                .into(),
        );
        input.write::<BlockIDInclusionProofVariable<HEADER_PROOF_DEPTH>>(
            celestia_block_proof.last_block_id_proof.into(),
        );
        input.write::<BoolVariable>(true); // TODO: WHAT IS THIS, WHAT DOES IT MEAN

        let (proof, output) = timed!(timing, "Step proof time", circuit.mock_prove(&input));
        // circuit.verify(&proof, &input, &output);

        timing.print();
    }

    fn test_skip_template<const VALIDATOR_SET_SIZE_MAX: usize>(trusted_block: usize, block: usize) {
        env::set_var("RUST_LOG", "debug");
        env_logger::try_init().unwrap_or_default();

        type Curve = Ed25519;
        const HEADER_PROOF_DEPTH: usize = 4;

        let mut timing = TimingTree::new("Verify Celestia skip", log::Level::Debug);

        println!("Making skip circuit");
        let mut builder = DefaultBuilder::new();
        let validators =
            builder.read::<ArrayVariable<ValidatorVariable<Curve>, VALIDATOR_SET_SIZE_MAX>>();
        let header = builder.read::<TendermintHashVariable>();
        let data_hash_proof = builder.read::<HashInclusionProofVariable<HEADER_PROOF_DEPTH>>();
        let validator_hash_proof = builder.read::<HashInclusionProofVariable<HEADER_PROOF_DEPTH>>();
        let next_validators_hash_proof =
            builder.read::<HashInclusionProofVariable<HEADER_PROOF_DEPTH>>();
        let round_present = builder.read::<BoolVariable>();
        let trusted_header = builder.read::<TendermintHashVariable>();
        let trusted_validators_hash_proof =
            builder.read::<HashInclusionProofVariable<HEADER_PROOF_DEPTH>>();
        let trusted_validators_hash_fields = builder
            .read::<ArrayVariable<ValidatorHashFieldVariable<Curve>, VALIDATOR_SET_SIZE_MAX>>();

        builder.skip(
            &validators,
            &header,
            &data_hash_proof,
            &validator_hash_proof,
            &next_validators_hash_proof,
            &round_present,
            &trusted_header,
            &trusted_validators_hash_proof,
            &trusted_validators_hash_fields,
        );

        println!("Building circuit");
        let circuit = builder.build();
        println!("num gates: {:?}", circuit.data.common.gates.len());

        println!("Generating inputs");
        // Note: Length of output is the closest power of 2 gte the number of validators for this block.
        let celestia_skip_block_proof: CelestiaSkipBlockProof =
            generate_skip_inputs::<VALIDATOR_SET_SIZE_MAX>(trusted_block, block);

        println!(
            "Number of validators: {}",
            celestia_skip_block_proof.base.validators.len()
        );

        let input = circuit.input();
        // TODO: now do all the input writes
        // input.write::<ArrayVariable<ValidatorVariable<Curve>, VALIDATOR_SET_SIZE_MAX>>(
        //     celestia_block_proof.base.validators.try_into().unwrap(),
        // );

        let (proof, output) = timed!(timing, "Skip proof time", circuit.prove(&input));
        circuit.verify(&proof, &input, &output);

        timing.print();
    }

    #[test]
    fn test_step_with_dummy_sigs() {
        // Testing block 11105 (4 validators, 2 signed)
        // Need to handle empty validators as well
        // Should set some dummy values
        let block = 11105;

        const VALIDATOR_SET_SIZE_MAX: usize = 8;

        test_step_template::<VALIDATOR_SET_SIZE_MAX>(block);
    }

    #[test]
    fn test_step_small() {
        // Testing block 11000
        let block = 11000;

        const VALIDATOR_SET_SIZE_MAX: usize = 4;

        test_step_template::<VALIDATOR_SET_SIZE_MAX>(block);
    }

    #[test]
    fn test_step_with_empty() {
        // Testing block 10000
        let block = 10000;

        const VALIDATOR_SET_SIZE_MAX: usize = 4;

        test_step_template::<VALIDATOR_SET_SIZE_MAX>(block);
    }

    #[test]
    fn test_step_large() {
        // Testing block 75000
        // 77 validators (128)
        // Block 50000
        // 32 validators
        // Block 15000
        // 16 validators
        // Testing block 60000
        // 60 validators, 4 disabled (valhash)

        let block = 75000;

        const VALIDATOR_SET_SIZE_MAX: usize = 128;

        test_step_template::<VALIDATOR_SET_SIZE_MAX>(block);
    }

    #[test]
    fn test_skip() {
        // Testing skip from 11000 to 11105

        // For now, only test with validator_set_size_max of the same size, confirm that we can set validator_et-isze_max to an arbitrary amount and the circuit should work for all sizes below that
        let trusted_block = 11000;

        let block = 11105;

        const VALIDATOR_SET_SIZE_MAX: usize = 4;

        test_skip_template::<VALIDATOR_SET_SIZE_MAX>(trusted_block, block);
    }

    #[test]
    fn test_skip_large() {
        // Testing skip from 60000 to 75000

        // 75000 has 128 validator max

        // For now, only test with validator_set_size_max of the same size, confirm that we can set validator_et-isze_max to an arbitrary amount and the circuit should work for all sizes below that
        let trusted_block = 60000;

        let block = 75000;

        const VALIDATOR_SET_SIZE_MAX: usize = 128;

        test_skip_template::<VALIDATOR_SET_SIZE_MAX>(trusted_block, block);
    }
}
