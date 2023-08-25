//! The protobuf encoding of a Tendermint validator is a deterministic function of the validator's
//! public key (32 bytes) and voting power (int64). The encoding is as follows in bytes:
//
//!     10 34 10 32 <pubkey> 16 <varint>
//
//! The `pubkey` is encoded as the raw list of bytes used in the public key. The `varint` is
//! encoded using protobuf's default integer encoding, which consist of 7 bit payloads. You can
//! read more about them here: https://protobuf.dev/programming-guides/encoding/#varints.

use curta::math::extension::CubicParameters;
use plonky2::{
    field::{extension::Extendable, types::Field},
    hash::hash_types::RichField,
    iop::{
        target::{BoolTarget, Target},
        witness::WitnessWrite,
    },
    plonk::{
        circuit_builder::CircuitBuilder,
        config::{AlgebraicHasher, GenericConfig},
    },
};

use plonky2x::{
    ecc::ed25519::{
        curve::{
            curve_types::{AffinePoint, Curve},
            ed25519::Ed25519,
        },
        field::ed25519_scalar::Ed25519Scalar,
        gadgets::{
            curve::{CircuitBuilderCurve, WitnessAffinePoint},
            eddsa::{EDDSAPublicKeyTarget, EDDSASignatureTarget},
        },
    },
    num::{
        biguint::WitnessBigUint,
        nonnative::nonnative::CircuitBuilderNonNative,
        u32::{
            gadgets::arithmetic_u32::{CircuitBuilderU32, U32Target},
            witness::WitnessU32,
        },
    },
    prelude::PartialWitness,
};

use num::BigUint;

use crate::{
    inputs::{CelestiaBaseBlockProof, CelestiaSkipBlockProof, CelestiaStepBlockProof},
    signature::TendermintSignature,
    utils::{
        to_be_bits, EncBlockIDTarget, EncTendermintHashTarget, I64Target,
        MarshalledValidatorTarget, TendermintHashTarget, ValidatorMessageTarget, HASH_SIZE_BITS,
        HEADER_PROOF_DEPTH, PROTOBUF_BLOCK_ID_SIZE_BITS, PROTOBUF_HASH_SIZE_BITS,
        VALIDATOR_MESSAGE_BYTES_LENGTH_MAX,
    },
    validator::TendermintMarshaller,
    voting::TendermintVoting,
};

#[derive(Debug, Clone)]
pub struct ValidatorTarget<C: Curve> {
    pubkey: EDDSAPublicKeyTarget<C>,
    signature: EDDSASignatureTarget<C>,
    message: ValidatorMessageTarget,
    message_bit_length: Target,
    voting_power: I64Target,
    validator_byte_length: Target,
    enabled: BoolTarget,
    signed: BoolTarget,
    // Only used in skip circuit
    present_on_trusted_header: BoolTarget,
}

#[derive(Debug, Clone)]
pub struct ValidatorHashFieldTarget<C: Curve> {
    pubkey: EDDSAPublicKeyTarget<C>,
    voting_power: I64Target,
    validator_byte_length: Target,
    enabled: BoolTarget,
}

/// The protobuf-encoded leaf (a hash), and it's corresponding proof and path indices against the header.
#[derive(Debug, Clone)]
pub struct HashInclusionProofTarget {
    enc_leaf: EncTendermintHashTarget,
    // Path and proof should have a fixed length of HEADER_PROOF_DEPTH.
    path: Vec<BoolTarget>,
    proof: Vec<TendermintHashTarget>,
}

/// The protobuf-encoded leaf (a tendermint block ID), and it's corresponding proof and path indices against the header.
#[derive(Debug, Clone)]
pub struct BlockIDInclusionProofTarget {
    enc_leaf: EncBlockIDTarget,
    // Path and proof should have a fixed length of HEADER_PROOF_DEPTH.
    path: Vec<BoolTarget>,
    proof: Vec<TendermintHashTarget>,
}

#[derive(Debug, Clone)]
pub struct StepProofTarget<C: Curve> {
    prev_header: TendermintHashTarget,
    last_block_id_proof: BlockIDInclusionProofTarget,
    base: BaseBlockProofTarget<C>,
}

#[derive(Debug, Clone)]
pub struct SkipProofTarget<C: Curve> {
    trusted_header: TendermintHashTarget,
    trusted_validator_hash_proof: HashInclusionProofTarget,
    trusted_validator_hash_fields: Vec<ValidatorHashFieldTarget<C>>,
    base: BaseBlockProofTarget<C>,
}

#[derive(Debug, Clone)]
pub struct BaseBlockProofTarget<C: Curve> {
    validators: Vec<ValidatorTarget<C>>,
    header: TendermintHashTarget,
    data_hash_proof: HashInclusionProofTarget,
    validator_hash_proof: HashInclusionProofTarget,
    next_validators_hash_proof: HashInclusionProofTarget,
    round_present: BoolTarget,
}

pub trait TendermintVerify<F: RichField + Extendable<D>, const D: usize> {
    type Curve: Curve;

    /// Verifies that the previous header hash in the block matches the previous header hash in the last block ID.
    fn verify_prev_header_in_header<
        E: CubicParameters<F>,
        C: GenericConfig<D, F = F, FE = F::Extension> + 'static,
    >(
        &mut self,
        header: &TendermintHashTarget,
        prev_header: &TendermintHashTarget,
        last_block_id_proof: &BlockIDInclusionProofTarget,
    ) where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>;

    /// Verifies a Tendermint consensus block.
    fn verify_header<
        E: CubicParameters<F>,
        C: GenericConfig<D, F = F, FE = F::Extension> + 'static,
        const VALIDATOR_SET_SIZE_MAX: usize,
    >(
        &mut self,
        validators: &Vec<ValidatorTarget<Self::Curve>>,
        header: &TendermintHashTarget,
        data_hash_proof: &HashInclusionProofTarget,
        validator_hash_proof: &HashInclusionProofTarget,
        next_validators_hash_proof: &HashInclusionProofTarget,
        round_present: &BoolTarget,
    ) where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>;

    /// Sequentially verifies a Tendermint consensus block.
    fn step<
        E: CubicParameters<F>,
        C: GenericConfig<D, F = F, FE = F::Extension> + 'static,
        const VALIDATOR_SET_SIZE_MAX: usize,
    >(
        &mut self,
        validators: &Vec<ValidatorTarget<Self::Curve>>,
        header: &TendermintHashTarget,
        prev_header: &TendermintHashTarget,
        data_hash_proof: &HashInclusionProofTarget,
        validator_hash_proof: &HashInclusionProofTarget,
        next_validators_hash_proof: &HashInclusionProofTarget,
        last_block_id_proof: &BlockIDInclusionProofTarget,
        round_present: &BoolTarget,
    ) where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>;

    /// Verifies that the trusted validators have signed the current header.
    fn verify_trusted_validators<
        E: CubicParameters<F>,
        C: GenericConfig<D, F = F, FE = F::Extension> + 'static,
        const VALIDATOR_SET_SIZE_MAX: usize,
    >(
        &mut self,
        validators: &Vec<ValidatorTarget<Self::Curve>>,
        trusted_header: &TendermintHashTarget,
        trusted_validator_hash_proof: &HashInclusionProofTarget,
        trusted_validator_hash_fields: &Vec<ValidatorHashFieldTarget<Self::Curve>>,
    ) where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>;

    /// Verifies a Tendermint block that is non-sequential with the trusted block.
    fn skip<
        E: CubicParameters<F>,
        C: GenericConfig<D, F = F, FE = F::Extension> + 'static,
        const VALIDATOR_SET_SIZE_MAX: usize,
    >(
        &mut self,
        validators: &Vec<ValidatorTarget<Self::Curve>>,
        header: &TendermintHashTarget,
        data_hash_proof: &HashInclusionProofTarget,
        validator_hash_proof: &HashInclusionProofTarget,
        next_validators_hash_proof: &HashInclusionProofTarget,
        round_present: &BoolTarget,
        trusted_header: &TendermintHashTarget,
        trusted_validator_hash_proof: &HashInclusionProofTarget,
        trusted_validator_hash_fields: &Vec<ValidatorHashFieldTarget<Self::Curve>>,
    ) where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>;
}

impl<F: RichField + Extendable<D>, const D: usize> TendermintVerify<F, D> for CircuitBuilder<F, D> {
    type Curve = Ed25519;

    fn step<
        E: CubicParameters<F>,
        C: GenericConfig<D, F = F, FE = F::Extension> + 'static,
        const VALIDATOR_SET_SIZE_MAX: usize,
    >(
        &mut self,
        validators: &Vec<ValidatorTarget<Self::Curve>>,
        header: &TendermintHashTarget,
        prev_header: &TendermintHashTarget,
        data_hash_proof: &HashInclusionProofTarget,
        validator_hash_proof: &HashInclusionProofTarget,
        next_validators_hash_proof: &HashInclusionProofTarget,
        last_block_id_proof: &BlockIDInclusionProofTarget,
        round_present: &BoolTarget,
    ) where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        // Verifies that 2/3 of the validators signed the headers
        self.verify_header::<E, C, VALIDATOR_SET_SIZE_MAX>(
            validators,
            header,
            data_hash_proof,
            validator_hash_proof,
            next_validators_hash_proof,
            round_present,
        );

        // Verifies that the previous header hash in the block matches the previous header hash in the last block ID.
        self.verify_prev_header_in_header::<E, C>(header, prev_header, last_block_id_proof);
    }

    fn verify_header<
        E: CubicParameters<F>,
        C: GenericConfig<D, F = F, FE = F::Extension> + 'static,
        const VALIDATOR_SET_SIZE_MAX: usize,
    >(
        &mut self,
        validators: &Vec<ValidatorTarget<Self::Curve>>,
        header: &TendermintHashTarget,
        data_hash_proof: &HashInclusionProofTarget,
        validator_hash_proof: &HashInclusionProofTarget,
        next_validators_hash_proof: &HashInclusionProofTarget,
        round_present: &BoolTarget,
    ) where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        let one = self.one();
        let false_t = self._false();
        let true_t = self._true();
        // Verify each of the validators marshal correctly
        // Assumes the validators are sorted in the correct order
        let byte_lengths: Vec<Target> =
            validators.iter().map(|v| v.validator_byte_length).collect();
        let marshalled_validators: Vec<MarshalledValidatorTarget> = validators
            .iter()
            .map(|v| self.marshal_tendermint_validator(&v.pubkey.0, &v.voting_power))
            .collect();
        let validators_signed: Vec<BoolTarget> = validators.iter().map(|v| v.signed).collect();
        let validators_enabled: Vec<BoolTarget> = validators.iter().map(|v| v.enabled).collect();

        let validators_signed_u32: Vec<U32Target> = validators_signed
            .iter()
            .map(|v| {
                let zero = self.zero_u32();
                let one = self.one_u32();
                U32Target(self.select(*v, one.0, zero.0))
            })
            .collect();

        let validator_voting_power: Vec<I64Target> =
            validators.iter().map(|v| v.voting_power).collect();

        let mut messages: Vec<Vec<BoolTarget>> =
            validators.iter().map(|v| v.message.0.to_vec()).collect();
        for i in 0..messages.len() {
            messages[i].resize(VALIDATOR_MESSAGE_BYTES_LENGTH_MAX * 8, self._false());
        }

        let messages: Vec<ValidatorMessageTarget> = messages
            .iter()
            .map(|v| ValidatorMessageTarget(v.clone().try_into().unwrap()))
            .collect();

        let message_bit_lengths: Vec<Target> =
            validators.iter().map(|v| v.message_bit_length).collect();

        let signatures: Vec<&EDDSASignatureTarget<Ed25519>> =
            validators.iter().map(|v| &v.signature).collect();
        let pubkeys: Vec<&EDDSAPublicKeyTarget<Ed25519>> =
            validators.iter().map(|v| &v.pubkey).collect();

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
            .extract_hash_from_protobuf::<HASH_START_BYTE, PROTOBUF_HASH_SIZE_BITS>(
                &validator_hash_proof.enc_leaf.0,
            );
        for i in 0..HASH_SIZE_BITS {
            self.connect(
                validators_hash_target.0[i].target,
                extracted_hash.0[i].target,
            );
        }

        let total_voting_power =
            self.get_total_voting_power::<VALIDATOR_SET_SIZE_MAX>(&validator_voting_power);
        let threshold_numerator = self.constant_u32(2);
        let threshold_denominator = self.constant_u32(3);

        // Assert the accumulated voting power is greater than the threshold
        let check_voting_power_bool = self.check_voting_power::<VALIDATOR_SET_SIZE_MAX>(
            &validator_voting_power,
            // Check if the signed validators are greater than the threshold
            &validators_signed_u32,
            &total_voting_power,
            &threshold_numerator,
            &threshold_denominator,
        );
        self.connect(check_voting_power_bool.target, one);

        // Verifies signatures of the validators
        self.verify_signatures::<E, C>(
            &validators_signed,
            messages,
            message_bit_lengths,
            signatures,
            pubkeys,
        );

        // TODO: Verify that this will work with dummy signatures
        for i in 0..VALIDATOR_SET_SIZE_MAX {
            // Verify that the header is in the message in the correct location
            let hash_in_message =
                self.verify_hash_in_message(&validators[i].message, header, round_present);

            // If the validator is enabled, then the hash should be in the message
            self.connect(hash_in_message.target, validators_signed[i].target);
        }

        // Note: Hardcode the path for each of the leaf proofs (otherwise you can prove arbitrary data in the header)
        let data_hash_path = vec![false_t, true_t, true_t, false_t];
        let val_hash_path = vec![true_t, true_t, true_t, false_t];
        let next_val_hash_path = vec![false_t, false_t, false_t, true_t];

        let data_hash_leaf_hash =
            self.leaf_hash::<PROTOBUF_HASH_SIZE_BITS>(&data_hash_proof.enc_leaf.0);
        let header_from_data_root_proof = self.get_root_from_merkle_proof::<HEADER_PROOF_DEPTH>(
            &data_hash_proof.proof,
            &data_hash_path,
            &data_hash_leaf_hash,
        );

        let validator_hash_leaf_hash =
            self.leaf_hash::<PROTOBUF_HASH_SIZE_BITS>(&validator_hash_proof.enc_leaf.0);
        let header_from_validator_root_proof = self
            .get_root_from_merkle_proof::<HEADER_PROOF_DEPTH>(
                &validator_hash_proof.proof,
                &val_hash_path,
                &validator_hash_leaf_hash,
            );

        let next_validators_hash_leaf_hash =
            self.leaf_hash::<PROTOBUF_HASH_SIZE_BITS>(&next_validators_hash_proof.enc_leaf.0);
        let header_from_next_validators_root_proof = self
            .get_root_from_merkle_proof::<HEADER_PROOF_DEPTH>(
                &next_validators_hash_proof.proof,
                &next_val_hash_path,
                &next_validators_hash_leaf_hash,
            );

        // Confirm that the header from the proof of {validator_hash, next_validators_hash, data_hash, last_block_id} all match the header
        for i in 0..HASH_SIZE_BITS {
            self.connect(header.0[i].target, header_from_data_root_proof.0[i].target);
            self.connect(
                header.0[i].target,
                header_from_validator_root_proof.0[i].target,
            );
            self.connect(
                header.0[i].target,
                header_from_next_validators_root_proof.0[i].target,
            );
        }
    }

    fn verify_prev_header_in_header<
        E: CubicParameters<F>,
        C: GenericConfig<D, F = F, FE = F::Extension> + 'static,
    >(
        &mut self,
        header: &TendermintHashTarget,
        prev_header: &TendermintHashTarget,
        last_block_id_proof: &BlockIDInclusionProofTarget,
    ) where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        let false_t = self._false();
        let true_t = self._true();

        /// Start of the hash in protobuf encoded validator hash & last block id
        const HASH_START_BYTE: usize = 2;

        let last_block_id_path = vec![false_t, false_t, true_t, false_t];

        let last_block_id_leaf_hash =
            self.leaf_hash::<PROTOBUF_BLOCK_ID_SIZE_BITS>(&last_block_id_proof.enc_leaf.0);
        let header_from_last_block_id_proof = self
            .get_root_from_merkle_proof::<HEADER_PROOF_DEPTH>(
                &last_block_id_proof.proof,
                &last_block_id_path,
                &last_block_id_leaf_hash,
            );

        // Confirm that the header from the proof of {validator_hash, next_validators_hash, data_hash, last_block_id} all match the header
        for i in 0..HASH_SIZE_BITS {
            self.connect(
                header.0[i].target,
                header_from_last_block_id_proof.0[i].target,
            );
        }

        // Extract prev header hash from the encoded leaf (starts at second byte)
        let extracted_prev_header_hash = self
            .extract_hash_from_protobuf::<HASH_START_BYTE, PROTOBUF_BLOCK_ID_SIZE_BITS>(
                &last_block_id_proof.enc_leaf.0,
            );
        for i in 0..HASH_SIZE_BITS {
            self.connect(
                prev_header.0[i].target,
                extracted_prev_header_hash.0[i].target,
            );
        }
    }

    fn skip<
        E: CubicParameters<F>,
        C: GenericConfig<D, F = F, FE = F::Extension> + 'static,
        const VALIDATOR_SET_SIZE_MAX: usize,
    >(
        &mut self,
        validators: &Vec<ValidatorTarget<Self::Curve>>,
        header: &TendermintHashTarget,
        data_hash_proof: &HashInclusionProofTarget,
        validator_hash_proof: &HashInclusionProofTarget,
        next_validators_hash_proof: &HashInclusionProofTarget,
        round_present: &BoolTarget,
        trusted_header: &TendermintHashTarget,
        trusted_validator_hash_proof: &HashInclusionProofTarget,
        trusted_validator_hash_fields: &Vec<ValidatorHashFieldTarget<Self::Curve>>,
    ) where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        self.verify_trusted_validators::<E, C, VALIDATOR_SET_SIZE_MAX>(
            validators,
            trusted_header,
            trusted_validator_hash_proof,
            trusted_validator_hash_fields,
        );

        self.verify_header::<E, C, VALIDATOR_SET_SIZE_MAX>(
            validators,
            header,
            data_hash_proof,
            validator_hash_proof,
            next_validators_hash_proof,
            round_present,
        );
    }

    fn verify_trusted_validators<
        E: CubicParameters<F>,
        C: GenericConfig<D, F = F, FE = F::Extension> + 'static,
        const VALIDATOR_SET_SIZE_MAX: usize,
    >(
        &mut self,
        validators: &Vec<ValidatorTarget<Self::Curve>>,
        trusted_header: &TendermintHashTarget,
        trusted_validator_hash_proof: &HashInclusionProofTarget,
        trusted_validator_hash_fields: &Vec<ValidatorHashFieldTarget<Self::Curve>>,
    ) where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        // Note: A trusted validator is one who is present on the trusted header
        let false_t = self._false();
        let true_t = self._true();
        let one = self.one();

        // Get the header from the validator hash merkle proof
        let val_hash_path = vec![true_t, true_t, true_t, false_t];
        let validator_hash_leaf_hash =
            self.leaf_hash::<PROTOBUF_HASH_SIZE_BITS>(&trusted_validator_hash_proof.enc_leaf.0);
        let header_from_validator_root_proof = self
            .get_root_from_merkle_proof::<HEADER_PROOF_DEPTH>(
                &trusted_validator_hash_proof.proof,
                &val_hash_path,
                &validator_hash_leaf_hash,
            );

        // Confirm the validator hash proof matches the trusted header
        for i in 0..HASH_SIZE_BITS {
            self.connect(
                trusted_header.0[i].target,
                header_from_validator_root_proof.0[i].target,
            );
        }

        let marshalled_trusted_validators: Vec<MarshalledValidatorTarget> =
            trusted_validator_hash_fields
                .iter()
                .map(|v| self.marshal_tendermint_validator(&v.pubkey.0, &v.voting_power))
                .collect();

        let trusted_validators_enabled: Vec<BoolTarget> = trusted_validator_hash_fields
            .iter()
            .map(|v| v.enabled)
            .collect();

        let trusted_byte_lengths: Vec<Target> = trusted_validator_hash_fields
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
            .extract_hash_from_protobuf::<HASH_START_BYTE, PROTOBUF_HASH_SIZE_BITS>(
                &trusted_validator_hash_proof.enc_leaf.0,
            );
        for i in 0..HASH_SIZE_BITS {
            self.connect(
                validators_hash_target.0[i].target,
                extracted_hash.0[i].target,
            );
        }

        // If a validator is present_on_trusted_header, then they should have signed.
        // Not all validators that have signed need to be present on the trusted header.
        // TODO: We should probably assert every validator that is enabled has signed.
        for i in 0..VALIDATOR_SET_SIZE_MAX {
            let present_and_signed = self.and(
                validators[i].present_on_trusted_header,
                validators[i].signed,
            );

            // If you are present, then you should have signed
            self.connect(
                validators[i].present_on_trusted_header.target,
                present_and_signed.target,
            );
        }

        // If a validator is present, then its pubkey should be present in the trusted validators
        for i in 0..VALIDATOR_SET_SIZE_MAX {
            let mut pubkey_match = self._false();
            for j in 0..VALIDATOR_SET_SIZE_MAX {
                let pubkey_match_idx = self.is_equal_affine_point(
                    &validators[i].pubkey.0,
                    &trusted_validator_hash_fields[j].pubkey.0,
                );
                pubkey_match = self.or(pubkey_match, pubkey_match_idx);
            }
            // It is possible for a validator to be present on the trusted header, but not have signed this header.
            let match_and_present = self.and(pubkey_match, validators[i].present_on_trusted_header);

            // If you are present, then you should have a matching pubkey
            self.connect(
                validators[i].present_on_trusted_header.target,
                match_and_present.target,
            );
        }

        let validator_voting_power: Vec<I64Target> =
            validators.iter().map(|v| v.voting_power).collect();
        let present_on_trusted_header: Vec<BoolTarget> = validators
            .iter()
            .map(|v| v.present_on_trusted_header)
            .collect();
        let present_on_trusted_header_u32: Vec<U32Target> = present_on_trusted_header
            .iter()
            .map(|v| {
                let zero = self.zero_u32();
                let one = self.one_u32();
                U32Target(self.select(*v, one.0, zero.0))
            })
            .collect();

        // The trusted validators must comprise at least 1/3 of the total voting power
        let total_voting_power =
            self.get_total_voting_power::<VALIDATOR_SET_SIZE_MAX>(&validator_voting_power);
        let threshold_numerator = self.constant_u32(1);
        let threshold_denominator = self.constant_u32(3);

        // Assert the voting power from the trusted validators is greater than the threshold
        let check_voting_power_bool = self.check_voting_power::<VALIDATOR_SET_SIZE_MAX>(
            &validator_voting_power,
            // Check if the trusted validators are greater than the threshold
            &present_on_trusted_header_u32,
            &total_voting_power,
            &threshold_numerator,
            &threshold_denominator,
        );
        self.connect(check_voting_power_bool.target, one);
    }
}

// TODO: Can move make circuit and set PW to another file

fn create_virtual_bool_target_array<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    size: usize,
) -> Vec<BoolTarget> {
    let mut result = Vec::new();
    for _i in 0..size {
        result.push(builder.add_virtual_bool_target_safe());
    }
    result
}

fn create_virtual_hash_inclusion_proof_target<
    F: RichField + Extendable<D>,
    const D: usize,
    const PROOF_DEPTH: usize,
>(
    builder: &mut CircuitBuilder<F, D>,
) -> HashInclusionProofTarget {
    let mut proof = Vec::new();
    for _i in 0..PROOF_DEPTH {
        proof.push(TendermintHashTarget(
            create_virtual_bool_target_array(builder, HASH_SIZE_BITS)
                .try_into()
                .unwrap(),
        ));
    }
    HashInclusionProofTarget {
        enc_leaf: EncTendermintHashTarget(
            create_virtual_bool_target_array(builder, PROTOBUF_HASH_SIZE_BITS)
                .try_into()
                .unwrap(),
        ),
        path: create_virtual_bool_target_array(builder, PROOF_DEPTH),
        proof,
    }
}

fn create_virtual_block_id_inclusion_proof_target<
    F: RichField + Extendable<D>,
    const D: usize,
    const PROOF_DEPTH: usize,
>(
    builder: &mut CircuitBuilder<F, D>,
) -> BlockIDInclusionProofTarget {
    let mut proof = Vec::new();
    for _i in 0..PROOF_DEPTH {
        proof.push(TendermintHashTarget(
            create_virtual_bool_target_array(builder, HASH_SIZE_BITS)
                .try_into()
                .unwrap(),
        ));
    }
    BlockIDInclusionProofTarget {
        enc_leaf: EncBlockIDTarget(
            create_virtual_bool_target_array(builder, PROTOBUF_BLOCK_ID_SIZE_BITS)
                .try_into()
                .unwrap(),
        ),
        path: create_virtual_bool_target_array(builder, PROOF_DEPTH),
        proof,
    }
}

pub fn make_base_circuit<
    F: RichField + Extendable<D>,
    const D: usize,
    C: Curve,
    Config: GenericConfig<D, F = F, FE = F::Extension> + 'static,
    E: CubicParameters<F>,
    const VALIDATOR_SET_SIZE_MAX: usize,
>(
    builder: &mut CircuitBuilder<F, D>,
) -> BaseBlockProofTarget<Ed25519>
where
    Config::Hasher: AlgebraicHasher<F>,
{
    type Curve = Ed25519;
    let mut validators = Vec::new();
    for _i in 0..VALIDATOR_SET_SIZE_MAX {
        let pubkey = EDDSAPublicKeyTarget(builder.add_virtual_affine_point_target());
        let signature = EDDSASignatureTarget {
            r: builder.add_virtual_affine_point_target(),
            s: builder.add_virtual_nonnative_target(),
        };
        let message =
            create_virtual_bool_target_array(builder, VALIDATOR_MESSAGE_BYTES_LENGTH_MAX * 8);
        let message = ValidatorMessageTarget(message.try_into().unwrap());

        let message_bit_length = builder.add_virtual_target();

        let voting_power = I64Target([
            builder.add_virtual_u32_target(),
            builder.add_virtual_u32_target(),
        ]);
        let validator_byte_length = builder.add_virtual_target();
        let enabled = builder.add_virtual_bool_target_safe();
        let signed = builder.add_virtual_bool_target_safe();
        let present_on_trusted_header = builder.add_virtual_bool_target_safe();

        validators.push(ValidatorTarget::<Curve> {
            pubkey,
            signature,
            message,
            message_bit_length,
            voting_power,
            validator_byte_length,
            enabled,
            signed,
            present_on_trusted_header,
        })
    }

    let header = create_virtual_bool_target_array(builder, HASH_SIZE_BITS);
    let header = TendermintHashTarget(header.try_into().unwrap());

    let data_hash_proof =
        create_virtual_hash_inclusion_proof_target::<F, D, HEADER_PROOF_DEPTH>(builder);
    let validator_hash_proof =
        create_virtual_hash_inclusion_proof_target::<F, D, HEADER_PROOF_DEPTH>(builder);
    let next_validators_hash_proof =
        create_virtual_hash_inclusion_proof_target::<F, D, HEADER_PROOF_DEPTH>(builder);

    let round_present = builder.add_virtual_bool_target_safe();

    BaseBlockProofTarget {
        validators,
        header,
        data_hash_proof,
        validator_hash_proof,
        next_validators_hash_proof,
        round_present,
    }
}

pub fn make_step_circuit<
    F: RichField + Extendable<D>,
    const D: usize,
    C: Curve,
    Config: GenericConfig<D, F = F, FE = F::Extension> + 'static,
    E: CubicParameters<F>,
    const VALIDATOR_SET_SIZE_MAX: usize,
>(
    builder: &mut CircuitBuilder<F, D>,
) -> StepProofTarget<Ed25519>
where
    Config::Hasher: AlgebraicHasher<F>,
{
    type Curve = Ed25519;
    let base = make_base_circuit::<F, D, C, Config, E, VALIDATOR_SET_SIZE_MAX>(builder);

    let prev_header = create_virtual_bool_target_array(builder, HASH_SIZE_BITS);
    let prev_header = TendermintHashTarget(prev_header.try_into().unwrap());

    let last_block_id_proof =
        create_virtual_block_id_inclusion_proof_target::<F, D, HEADER_PROOF_DEPTH>(builder);

    builder.step::<E, Config, VALIDATOR_SET_SIZE_MAX>(
        &base.validators,
        &base.header,
        &prev_header,
        &base.data_hash_proof,
        &base.validator_hash_proof,
        &base.next_validators_hash_proof,
        &last_block_id_proof,
        &base.round_present,
    );

    StepProofTarget::<Curve> {
        prev_header,
        last_block_id_proof,
        base,
    }
}

pub fn make_skip_circuit<
    F: RichField + Extendable<D>,
    const D: usize,
    C: Curve,
    Config: GenericConfig<D, F = F, FE = F::Extension> + 'static,
    E: CubicParameters<F>,
    const VALIDATOR_SET_SIZE_MAX: usize,
>(
    builder: &mut CircuitBuilder<F, D>,
) -> SkipProofTarget<Ed25519>
where
    Config::Hasher: AlgebraicHasher<F>,
{
    type Curve = Ed25519;
    let base = make_base_circuit::<F, D, C, Config, E, VALIDATOR_SET_SIZE_MAX>(builder);

    let trusted_header = create_virtual_bool_target_array(builder, HASH_SIZE_BITS);
    let trusted_header = TendermintHashTarget(trusted_header.try_into().unwrap());

    let trusted_validator_hash_proof =
        create_virtual_hash_inclusion_proof_target::<F, D, HEADER_PROOF_DEPTH>(builder);

    let mut trusted_validator_hash_fields = Vec::new();
    for _i in 0..VALIDATOR_SET_SIZE_MAX {
        let pubkey = EDDSAPublicKeyTarget(builder.add_virtual_affine_point_target());

        let voting_power = I64Target([
            builder.add_virtual_u32_target(),
            builder.add_virtual_u32_target(),
        ]);
        let validator_byte_length = builder.add_virtual_target();
        let enabled = builder.add_virtual_bool_target_safe();

        trusted_validator_hash_fields.push(ValidatorHashFieldTarget::<Curve> {
            pubkey,
            voting_power,
            validator_byte_length,
            enabled,
        })
    }

    builder.skip::<E, Config, VALIDATOR_SET_SIZE_MAX>(
        &base.validators,
        &base.header,
        &base.data_hash_proof,
        &base.validator_hash_proof,
        &base.next_validators_hash_proof,
        &base.round_present,
        &trusted_header,
        &trusted_validator_hash_proof,
        &trusted_validator_hash_fields,
    );

    SkipProofTarget::<Curve> {
        trusted_header,
        trusted_validator_hash_proof,
        trusted_validator_hash_fields,
        base,
    }
}

pub fn set_base_pw<
    F: RichField + Extendable<D>,
    const D: usize,
    C: Curve,
    const VALIDATOR_SET_SIZE_MAX: usize,
>(
    pw: &mut PartialWitness<F>,
    target: BaseBlockProofTarget<C>,
    inputs: CelestiaBaseBlockProof,
) {
    // Set target for header
    let header_bits = to_be_bits(inputs.header);
    for i in 0..HASH_SIZE_BITS {
        pw.set_bool_target(target.header.0[i], header_bits[i]);
    }

    // Set target for round present
    pw.set_bool_target(target.round_present, inputs.round_present);

    // Set the encoded leaf for each of the proofs
    let data_hash_enc_leaf = to_be_bits(inputs.data_hash_proof.enc_leaf);
    let val_hash_enc_leaf = to_be_bits(inputs.validator_hash_proof.enc_leaf);
    let next_val_hash_enc_leaf = to_be_bits(inputs.next_validators_hash_proof.enc_leaf);

    for i in 0..PROTOBUF_HASH_SIZE_BITS {
        pw.set_bool_target(target.data_hash_proof.enc_leaf.0[i], data_hash_enc_leaf[i]);
        pw.set_bool_target(
            target.validator_hash_proof.enc_leaf.0[i],
            val_hash_enc_leaf[i],
        );
        pw.set_bool_target(
            target.next_validators_hash_proof.enc_leaf.0[i],
            next_val_hash_enc_leaf[i],
        );
    }

    for i in 0..HEADER_PROOF_DEPTH {
        // Set path indices for each of the proof indices
        pw.set_bool_target(
            target.data_hash_proof.path[i],
            inputs.data_hash_proof.path[i],
        );
        pw.set_bool_target(
            target.validator_hash_proof.path[i],
            inputs.validator_hash_proof.path[i],
        );
        pw.set_bool_target(
            target.next_validators_hash_proof.path[i],
            inputs.next_validators_hash_proof.path[i],
        );

        let data_hash_aunt = to_be_bits(inputs.data_hash_proof.proof[i].to_vec());

        let val_hash_aunt = to_be_bits(inputs.validator_hash_proof.proof[i].to_vec());

        let next_val_aunt = to_be_bits(inputs.next_validators_hash_proof.proof[i].to_vec());

        // Set aunts for each of the proofs
        for j in 0..HASH_SIZE_BITS {
            pw.set_bool_target(target.data_hash_proof.proof[i].0[j], data_hash_aunt[j]);
            pw.set_bool_target(target.validator_hash_proof.proof[i].0[j], val_hash_aunt[j]);
            pw.set_bool_target(
                target.next_validators_hash_proof.proof[i].0[j],
                next_val_aunt[j],
            );
        }
    }

    // Set the targets for each of the validators
    for i in 0..VALIDATOR_SET_SIZE_MAX {
        let validator = &inputs.validators[i];
        let signature_bytes = validator.signature.clone().into_bytes();

        let voting_power_lower = (validator.voting_power & ((1 << 32) - 1)) as u32;
        let voting_power_upper = (validator.voting_power >> 32) as u32;

        let pub_key_uncompressed: AffinePoint<C> =
            AffinePoint::new_from_compressed_point(validator.pubkey.as_bytes());

        let sig_r: AffinePoint<C> = AffinePoint::new_from_compressed_point(&signature_bytes[0..32]);
        assert!(sig_r.is_valid());

        let sig_s_biguint = BigUint::from_bytes_le(&signature_bytes[32..64]);
        let _sig_s = Ed25519Scalar::from_noncanonical_biguint(sig_s_biguint.clone());

        // Set the targets for the public key
        pw.set_affine_point_target(&target.validators[i].pubkey.0, &pub_key_uncompressed);

        // Set signature targets
        pw.set_affine_point_target(&target.validators[i].signature.r, &sig_r);
        pw.set_biguint_target(&target.validators[i].signature.s.value, &sig_s_biguint);

        let message_bits = to_be_bits(validator.message.clone());
        // Set messages for each of the proofs
        for j in 0..message_bits.len() {
            pw.set_bool_target(target.validators[i].message.0[j], message_bits[j]);
        }
        for j in message_bits.len()..VALIDATOR_MESSAGE_BYTES_LENGTH_MAX * 8 {
            pw.set_bool_target(target.validators[i].message.0[j], false);
        }

        // Set voting power targets
        pw.set_u32_target(target.validators[i].voting_power.0[0], voting_power_lower);
        pw.set_u32_target(target.validators[i].voting_power.0[1], voting_power_upper);

        // Set length targets
        pw.set_target(
            target.validators[i].validator_byte_length,
            F::from_canonical_usize(validator.validator_byte_length),
        );
        let message_bit_length = validator.message_bit_length;

        pw.set_target(
            target.validators[i].message_bit_length,
            F::from_canonical_usize(message_bit_length),
        );

        // Set enabled and signed
        pw.set_bool_target(target.validators[i].enabled, validator.enabled);

        pw.set_bool_target(target.validators[i].signed, validator.signed);

        let present_on_trusted_header = validator.present_on_trusted_header;
        let present_on_trusted_header_bool = if present_on_trusted_header.is_some() {
            present_on_trusted_header.unwrap()
        } else {
            false
        };

        // Only used for skip circuit
        pw.set_bool_target(
            target.validators[i].present_on_trusted_header,
            present_on_trusted_header_bool,
        );
    }
}

pub fn set_step_pw<
    F: RichField + Extendable<D>,
    const D: usize,
    C: Curve,
    const VALIDATOR_SET_SIZE_MAX: usize,
>(
    pw: &mut PartialWitness<F>,
    target: StepProofTarget<C>,
    inputs: CelestiaStepBlockProof,
) {
    set_base_pw::<F, D, C, VALIDATOR_SET_SIZE_MAX>(pw, target.base, inputs.base);

    // Set target for prev header
    let prev_header_bits = to_be_bits(inputs.prev_header);
    for i in 0..HASH_SIZE_BITS {
        pw.set_bool_target(target.prev_header.0[i], prev_header_bits[i]);
    }

    let last_block_id_enc_leaf = to_be_bits(inputs.last_block_id_proof.enc_leaf);

    // Set targets for last block id leaf
    for i in 0..PROTOBUF_BLOCK_ID_SIZE_BITS {
        pw.set_bool_target(
            target.last_block_id_proof.enc_leaf.0[i],
            last_block_id_enc_leaf[i],
        );
    }

    for i in 0..HEADER_PROOF_DEPTH {
        // Set path indices for each of the proof indices
        pw.set_bool_target(
            target.last_block_id_proof.path[i],
            inputs.last_block_id_proof.path[i],
        );

        let last_block_id_aunt = to_be_bits(inputs.last_block_id_proof.proof[i].to_vec());

        // Set aunts for each of the proofs
        for j in 0..HASH_SIZE_BITS {
            pw.set_bool_target(
                target.last_block_id_proof.proof[i].0[j],
                last_block_id_aunt[j],
            );
        }
    }
}

pub fn set_skip_pw<
    F: RichField + Extendable<D>,
    const D: usize,
    C: Curve,
    const VALIDATOR_SET_SIZE_MAX: usize,
>(
    pw: &mut PartialWitness<F>,
    target: SkipProofTarget<C>,
    inputs: CelestiaSkipBlockProof,
) {
    set_base_pw::<F, D, C, VALIDATOR_SET_SIZE_MAX>(pw, target.base, inputs.base);

    // Set target for prev header
    let trusted_header_bits = to_be_bits(inputs.trusted_header);
    for i in 0..HASH_SIZE_BITS {
        pw.set_bool_target(target.trusted_header.0[i], trusted_header_bits[i]);
    }

    let trusted_validator_hash_enc_leaf = to_be_bits(inputs.trusted_validator_hash_proof.enc_leaf);

    // Set targets for trusted validator hash leaf
    for i in 0..PROTOBUF_HASH_SIZE_BITS {
        pw.set_bool_target(
            target.trusted_validator_hash_proof.enc_leaf.0[i],
            trusted_validator_hash_enc_leaf[i],
        );
    }

    for i in 0..HEADER_PROOF_DEPTH {
        // Set path indices for each of the proof indices
        pw.set_bool_target(
            target.trusted_validator_hash_proof.path[i],
            inputs.trusted_validator_hash_proof.path[i],
        );

        let trusted_validator_hash_aunt =
            to_be_bits(inputs.trusted_validator_hash_proof.proof[i].to_vec());

        // Set aunts for the proof
        for j in 0..HASH_SIZE_BITS {
            pw.set_bool_target(
                target.trusted_validator_hash_proof.proof[i].0[j],
                trusted_validator_hash_aunt[j],
            );
        }
    }

    // Set the targets for each of the validator hash fields
    for i in 0..VALIDATOR_SET_SIZE_MAX {
        let validator = &inputs.trusted_validator_fields[i];

        let voting_power_lower = (validator.voting_power & ((1 << 32) - 1)) as u32;
        let voting_power_upper = (validator.voting_power >> 32) as u32;

        let pub_key_uncompressed: AffinePoint<C> =
            AffinePoint::new_from_compressed_point(validator.pubkey.as_bytes());

        // Set the targets for the public key
        pw.set_affine_point_target(
            &target.trusted_validator_hash_fields[i].pubkey.0,
            &pub_key_uncompressed,
        );

        // Set voting power targets
        pw.set_u32_target(
            target.trusted_validator_hash_fields[i].voting_power.0[0],
            voting_power_lower,
        );
        pw.set_u32_target(
            target.trusted_validator_hash_fields[i].voting_power.0[1],
            voting_power_upper,
        );

        // Set length targets
        pw.set_target(
            target.trusted_validator_hash_fields[i].validator_byte_length,
            F::from_canonical_usize(validator.validator_byte_length),
        );

        // Set enabled
        pw.set_bool_target(
            target.trusted_validator_hash_fields[i].enabled,
            validator.enabled,
        );
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use curta::math::goldilocks::cubic::GoldilocksCubicParameters;
    use plonky2::field::goldilocks_field::GoldilocksField;
    use plonky2::field::types::Field;
    use plonky2::{
        iop::witness::{PartialWitness, WitnessWrite},
        plonk::{
            circuit_builder::CircuitBuilder, circuit_data::CircuitConfig,
            config::PoseidonGoldilocksConfig,
        },
    };

    use crate::inputs::{generate_skip_inputs, generate_step_inputs, CelestiaStepBlockProof};
    use crate::utils::to_be_bits;

    use log;
    use plonky2::timed;
    use plonky2::util::timing::TimingTree;
    use subtle_encoding::hex;

    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;
    const D: usize = 2;

    #[test]
    fn test_verify_hash_in_message() {
        // This is a test case generated from block 144094 of Celestia's Mocha testnet
        // Block Hash: 8909e1b73b7d987e95a7541d96ed484c17a4b0411e98ee4b7c890ad21302ff8c (needs to be lower case)
        // Signed Message (from the last validator): 6b080211de3202000000000022480a208909e1b73b7d987e95a7541d96ed484c17a4b0411e98ee4b7c890ad21302ff8c12240801122061263df4855e55fcab7aab0a53ee32cf4f29a1101b56de4a9d249d44e4cf96282a0b089dce84a60610ebb7a81932076d6f6368612d33
        // No round exists in present the message that was signed above

        let header_hash = "8909e1b73b7d987e95a7541d96ed484c17a4b0411e98ee4b7c890ad21302ff8c";
        let header_bits = to_be_bits(hex::decode(header_hash).unwrap());

        let signed_message = "6b080211de3202000000000022480a208909e1b73b7d987e95a7541d96ed484c17a4b0411e98ee4b7c890ad21302ff8c12240801122061263df4855e55fcab7aab0a53ee32cf4f29a1101b56de4a9d249d44e4cf96282a0b089dce84a60610ebb7a81932076d6f6368612d33";
        let signed_message_bits = to_be_bits(hex::decode(signed_message).unwrap());

        let mut pw = PartialWitness::new();
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let zero = builder._false();

        let mut signed_message_target = [builder._false(); VALIDATOR_MESSAGE_BYTES_LENGTH_MAX * 8];
        for i in 0..signed_message_bits.len() {
            signed_message_target[i] = builder.constant_bool(signed_message_bits[i]);
        }

        let mut header_hash_target = [builder._false(); HASH_SIZE_BITS];
        for i in 0..header_bits.len() {
            header_hash_target[i] = builder.constant_bool(header_bits[i]);
        }

        let result = builder.verify_hash_in_message(
            &ValidatorMessageTarget(signed_message_target),
            &TendermintHashTarget(header_hash_target),
            &zero,
        );

        pw.set_target(result.target, F::ONE);

        let data = builder.build::<C>();
        let proof = data.prove(pw).unwrap();

        println!("Created proof");

        data.verify(proof).unwrap();

        println!("Verified proof");
    }

    fn test_step_template<const VALIDATOR_SET_SIZE_MAX: usize>(block: usize) {
        let _ = env_logger::builder().is_test(true).try_init();
        let mut timing = TimingTree::new("Verify Celestia Step", log::Level::Debug);

        let mut pw = PartialWitness::new();
        let config = CircuitConfig::standard_ecc_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        type F = GoldilocksField;
        type Curve = Ed25519;
        type E = GoldilocksCubicParameters;
        type C = PoseidonGoldilocksConfig;
        const D: usize = 2;

        println!("Making step circuit");

        let celestia_step_proof_target =
            make_step_circuit::<GoldilocksField, D, Curve, C, E, VALIDATOR_SET_SIZE_MAX>(
                &mut builder,
            );

        // Note: Length of output is the closest power of 2 gte the number of validators for this block.
        let celestia_block_proof: CelestiaStepBlockProof =
            generate_step_inputs::<VALIDATOR_SET_SIZE_MAX>(block);
        println!("Generated inputs");
        println!(
            "Number of validators: {}",
            celestia_block_proof.base.validators.len()
        );
        timed!(timing, "assigning inputs", {
            set_step_pw::<F, D, Curve, VALIDATOR_SET_SIZE_MAX>(
                &mut pw,
                celestia_step_proof_target,
                celestia_block_proof,
            );
        });
        let inner_data = builder.build::<C>();
        timed!(timing, "Generate proof", {
            let inner_proof = timed!(
                timing,
                "Total proof with a recursive envelope",
                plonky2::plonk::prover::prove(
                    &inner_data.prover_only,
                    &inner_data.common,
                    pw,
                    &mut timing
                )
                .unwrap()
            );
            inner_data.verify(inner_proof.clone()).unwrap();
            println!("num gates: {:?}", inner_data.common.gates.len());
        });

        timing.print();
    }

    fn test_skip_template<const VALIDATOR_SET_SIZE_MAX: usize>(trusted_block: usize, block: usize) {
        let _ = env_logger::builder().is_test(true).try_init();
        let mut timing = TimingTree::new("Verify Celestia Skip", log::Level::Debug);

        let mut pw = PartialWitness::new();
        let config = CircuitConfig::standard_ecc_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        type F = GoldilocksField;
        type Curve = Ed25519;
        type E = GoldilocksCubicParameters;
        type C = PoseidonGoldilocksConfig;
        const D: usize = 2;

        println!("Making skip circuit");

        let celestia_skip_proof_target =
            make_skip_circuit::<GoldilocksField, D, Curve, C, E, VALIDATOR_SET_SIZE_MAX>(
                &mut builder,
            );

        // Note: Length of output is the closest power of 2 gte the number of validators for this block.
        let celestia_block_proof: CelestiaSkipBlockProof =
            generate_skip_inputs::<VALIDATOR_SET_SIZE_MAX>(trusted_block, block);
        println!("Generated inputs");
        println!(
            "Number of validators: {}",
            celestia_block_proof.base.validators.len()
        );
        timed!(timing, "assigning inputs", {
            set_skip_pw::<F, D, Curve, VALIDATOR_SET_SIZE_MAX>(
                &mut pw,
                celestia_skip_proof_target,
                celestia_block_proof,
            );
        });
        let inner_data = builder.build::<C>();
        timed!(timing, "Generate proof", {
            let inner_proof = timed!(
                timing,
                "Total proof with a recursive envelope",
                plonky2::plonk::prover::prove(
                    &inner_data.prover_only,
                    &inner_data.common,
                    pw,
                    &mut timing
                )
                .unwrap()
            );
            inner_data.verify(inner_proof.clone()).unwrap();
            println!("num gates: {:?}", inner_data.common.gates.len());
        });

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
    fn test_step() {
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

        let block = 60000;

        const VALIDATOR_SET_SIZE_MAX: usize = 64;

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
        // Testing skip from 11000 to 15000

        // 15000 has 16 validator max

        // For now, only test with validator_set_size_max of the same size, confirm that we can set validator_et-isze_max to an arbitrary amount and the circuit should work for all sizes below that
        let trusted_block = 11000;

        let block = 12000;

        const VALIDATOR_SET_SIZE_MAX: usize = 8;

        test_skip_template::<VALIDATOR_SET_SIZE_MAX>(trusted_block, block);
    }
}
