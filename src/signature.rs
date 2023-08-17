//! The protobuf encoding of a Tendermint validator is a deterministic function of the validator's
//! public key (32 bytes) and voting power (int64). The encoding is as follows in bytes:
//
//!     10 34 10 32 <pubkey> 16 <varint>
//
//! The `pubkey` is encoded as the raw list of bytes used in the public key. The `varint` is
//! encoded using protobuf's default integer encoding, which consist of 7 bit payloads. You can
//! read more about them here: https://protobuf.dev/programming-guides/encoding/#varints.
use curta::plonky2::field::CubicParameters;
use plonky2::field::extension::Extendable;
use plonky2::iop::target::BoolTarget;
use plonky2::plonk::config::AlgebraicHasher;
use plonky2::plonk::config::GenericConfig;
use plonky2::{hash::hash_types::RichField, plonk::circuit_builder::CircuitBuilder};
use plonky2x::ecc::ed25519::curve::curve_types::Curve;
use plonky2x::ecc::ed25519::curve::ed25519::Ed25519;
use plonky2::iop::target::Target;
use plonky2x::ecc::ed25519::gadgets::curve::CircuitBuilderCurve;
use plonky2x::ecc::ed25519::gadgets::eddsa::verify_variable_signatures_circuit;
use plonky2x::ecc::ed25519::gadgets::eddsa::{
    verify_signatures_circuit, EDDSAPublicKeyTarget, EDDSASignatureTarget,
};
use plonky2x::hash::sha::sha512::calculate_num_chunks;
use plonky2x::num::nonnative::nonnative::CircuitBuilderNonNative;

use crate::utils::{
    EncTendermintHashTarget, TendermintHashTarget, ValidatorMessageTarget, HASH_SIZE_BITS,
    VALIDATOR_MESSAGE_BYTES_LENGTH_MAX,
};

pub trait TendermintSignature<F: RichField + Extendable<D>, const D: usize> {
    type Curve: Curve;

    // Extract a hash from a protobuf-encoded hash.
    fn extract_hash_from_protobuf(
        &mut self,
        hash: &EncTendermintHashTarget,
    ) -> TendermintHashTarget;

    /// Extract the header hash from the signed message from a validator.
    fn verify_hash_in_message(
        &mut self,
        message: &ValidatorMessageTarget,
        header_hash: &TendermintHashTarget,
        // Should be the same for all validators
        round_present_in_message: &BoolTarget,
    ) -> TendermintHashTarget;

    /// Verifies the signatures of the validators in the validator set.
    fn verify_signatures<
        E: CubicParameters<F>,
        C: GenericConfig<D, F = F, FE = F::Extension> + 'static,
    >(
        &mut self,
        // This message should be range-checked before being passed in.
        messages: Vec<Vec<BoolTarget>>,
        message_bit_lengths: Vec<Target>,
        eddsa_sig_targets: Vec<&EDDSASignatureTarget<Self::Curve>>,
        eddsa_pubkey_targets: Vec<&EDDSAPublicKeyTarget<Self::Curve>>,
    ) where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>;

    /// Verifies a single signature of a Tendermint validator.
    fn verify_signature<
        E: CubicParameters<F>,
        C: GenericConfig<D, F = F, FE = F::Extension> + 'static,
    >(
        &mut self,
        // This message should be range-checked before being passed in.
        message: Vec<BoolTarget>,
        eddsa_sig_target: &EDDSASignatureTarget<Self::Curve>,
        eddsa_pubkey_target: &EDDSAPublicKeyTarget<Self::Curve>,
    ) where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>;
}

impl<F: RichField + Extendable<D>, const D: usize> TendermintSignature<F, D>
    for CircuitBuilder<F, D>
{
    type Curve = Ed25519;

    fn extract_hash_from_protobuf(
        &mut self,
        hash: &EncTendermintHashTarget,
    ) -> TendermintHashTarget {
        let mut result = [self._false(); HASH_SIZE_BITS];
        // Skip first 2 bytes
        for i in 0..HASH_SIZE_BITS {
            result[i] = hash.0[i + (8 * 2)];
        }
        TendermintHashTarget(result)
    }

    fn verify_hash_in_message(
        &mut self,
        message: &ValidatorMessageTarget,
        header_hash: &TendermintHashTarget,
        // Should be the same for all validators
        round_present_in_message: &BoolTarget,
    ) -> TendermintHashTarget {
        // Logic:
        //      Verify that header_hash is equal to the hash in the message at the correct index.
        //      If the round is missing, then the hash starts at index 16.
        //      If the round is present, then the hash starts at index 25.

        let missing_round_start_idx = 16;

        let including_round_start_idx = 25;

        let one = self.one();

        let mut vec_round_missing = [self._false(); HASH_SIZE_BITS];

        let mut vec_round_present = [self._false(); HASH_SIZE_BITS];

        for i in 0..HASH_SIZE_BITS {
            vec_round_missing[i] = message.0[(missing_round_start_idx) * 8 + i];
            vec_round_present[i] = message.0[(including_round_start_idx) * 8 + i];
            let round_missing_eq =
                self.is_equal(header_hash.0[i].target, vec_round_missing[i].target);
            let round_present_eq =
                self.is_equal(header_hash.0[i].target, vec_round_present[i].target);

            // Pick the correct bit based on whether the round is present or not.
            let hash_eq = self.select(
                *round_present_in_message,
                round_present_eq.target,
                round_missing_eq.target,
            );

            self.connect(hash_eq, one);
        }

        *header_hash
    }

    /// Verifies the signatures of the validators in the validator set.
    fn verify_signatures<
        E: CubicParameters<F>,
        C: GenericConfig<D, F = F, FE = F::Extension> + 'static,
    >(
        &mut self,
        // This message should be range-checked before being passed in.
        // Note: These are all VALIDATOR_MESSAGE_BYTES_LENGTH_MAX*8 long
        messages: Vec<Vec<BoolTarget>>,
        message_bit_lengths: Vec<Target>,
        eddsa_sig_targets: Vec<&EDDSASignatureTarget<Self::Curve>>,
        eddsa_pubkey_targets: Vec<&EDDSAPublicKeyTarget<Self::Curve>>,
    ) where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        // TODO: UPDATE message.len() to VALIDATOR_SET_SIZE_MAX
        assert!(
            messages.len() == eddsa_sig_targets.len()
                && messages.len() == eddsa_pubkey_targets.len(),
        );

        println!("messages.len(): {}", messages.len());

        const VALIDATOR_MESSAGE_BITS_LENGTH_MAX: usize =
            VALIDATOR_MESSAGE_BYTES_LENGTH_MAX * 8;

        let eddsa_target =
            verify_variable_signatures_circuit::<F, Self::Curve, E, C, D, VALIDATOR_MESSAGE_BITS_LENGTH_MAX>(self, messages.len());

        for i in 0..messages.len() {
            let message = &messages[i];
            let eddsa_sig_target = eddsa_sig_targets[i];
            let eddsa_pubkey_target = eddsa_pubkey_targets[i];
            for j in 0..VALIDATOR_MESSAGE_BYTES_LENGTH_MAX * 8 {
                self.connect(eddsa_target.msgs[i][j].target, message[j].target);
            }

            self.connect(eddsa_target.msgs_lengths[i], message_bit_lengths[i]);

            self.connect_nonnative(&eddsa_target.sigs[i].s, &eddsa_sig_target.s);
            self.connect_nonnative(&eddsa_target.sigs[i].r.x, &eddsa_sig_target.r.x);
            self.connect_nonnative(&eddsa_target.sigs[i].r.y, &eddsa_sig_target.r.y);

            self.connect_affine_point(&eddsa_target.pub_keys[i].0, &eddsa_pubkey_target.0);
        }
    }

    /// Verifies the signatures of the validators in the validator set.
    fn verify_signature<
        E: CubicParameters<F>,
        C: GenericConfig<D, F = F, FE = F::Extension> + 'static,
    >(
        &mut self,
        // This should be the messaged signed by the validator that the header hash is extracted from.
        // We should range check this outside of the circuit.
        message: Vec<BoolTarget>,
        eddsa_sig_target: &EDDSASignatureTarget<Self::Curve>,
        eddsa_pubkey_target: &EDDSAPublicKeyTarget<Self::Curve>,
    ) where
        <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
    {
        let message_bytes_len: usize = message.len() / 8;
        let eddsa_target = verify_signatures_circuit::<F, Self::Curve, E, C, D>(
            self,
            1,
            message_bytes_len as u128,
        );

        for i in 0..message.len() {
            self.connect(eddsa_target.msgs[0][i].target, message[i].target);
        }

        self.connect_nonnative(&eddsa_target.sigs[0].s, &eddsa_sig_target.s);
        self.connect_nonnative(&eddsa_target.sigs[0].r.x, &eddsa_sig_target.r.x);
        self.connect_nonnative(&eddsa_target.sigs[0].r.y, &eddsa_sig_target.r.y);

        self.connect_affine_point(&eddsa_target.pub_keys[0].0, &eddsa_pubkey_target.0);
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use curta::math::goldilocks::cubic::GoldilocksCubicParameters;
    use num::BigUint;
    use plonky2::field::goldilocks_field::GoldilocksField;
    use plonky2::field::types::Field;
    use plonky2::{
        iop::witness::{PartialWitness, WitnessWrite},
        plonk::{
            circuit_builder::CircuitBuilder, circuit_data::CircuitConfig,
            config::PoseidonGoldilocksConfig,
        },
    };
    use plonky2x::ecc::ed25519::curve::eddsa::{verify_message, EDDSAPublicKey, EDDSASignature};
    use plonky2x::ecc::ed25519::gadgets::curve::WitnessAffinePoint;
    use subtle_encoding::hex;

    use plonky2x::num::biguint::CircuitBuilderBiguint;

    use plonky2x::ecc::ed25519::curve::curve_types::AffinePoint;
    use plonky2x::ecc::ed25519::field::ed25519_scalar::Ed25519Scalar;

    use crate::utils::to_be_bits;

    #[test]
    fn test_verify_eddsa_signature() {
        // First signature from block 11000
        let msg = "6c080211f82a00000000000022480a2036f2d954fe1ba37c5036cb3c6b366d0daf68fccbaa370d9490361c51a0a38b61122408011220cddf370e891591c9d912af175c966cd8dfa44b2c517e965416b769eb4b9d5d8d2a0c08f6b097a50610dffbcba90332076d6f6368612d33";
        let pubkey = "de25aec935b10f657b43fa97e5a8d4e523bdb0f9972605f0b064eff7b17048ba";
        let sig = "091576e9e3ad0e5ba661f7398e1adb3976ba647b579b8e4a224d1d02b591ade6aedb94d3bf55d258f089d6413155a57adfd4932418a798c2d68b29850f6fb50b";

        let msg_bytes = hex::decode(msg).unwrap();
        let pub_key_bytes = hex::decode(pubkey).unwrap();
        let sig_bytes = hex::decode(sig).unwrap();

        type F = GoldilocksField;
        type Curve = Ed25519;
        type E = GoldilocksCubicParameters;
        type C = PoseidonGoldilocksConfig;
        const D: usize = 2;

        let mut pw = PartialWitness::new();
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_ecc_config());

        let msg_bits = to_be_bits(msg_bytes.to_vec());
        let mut msg_bits_target = Vec::new();
        for i in 0..msg_bits.len() {
            msg_bits_target.push(builder.constant_bool(msg_bits[i]));
        }

        let virtual_affine_point_target = builder.add_virtual_affine_point_target();

        let pub_key_uncompressed: AffinePoint<Curve> =
            AffinePoint::new_from_compressed_point(&pub_key_bytes);

        let eddsa_pub_key_target = EDDSAPublicKeyTarget(virtual_affine_point_target);

        pw.set_affine_point_target::<Curve>(&eddsa_pub_key_target.0, &pub_key_uncompressed);

        let sig_r = AffinePoint::new_from_compressed_point(&sig_bytes[0..32]);
        assert!(sig_r.is_valid());

        let sig_s_biguint = BigUint::from_bytes_le(&sig_bytes[32..64]);
        let sig_s = Ed25519Scalar::from_noncanonical_biguint(sig_s_biguint.clone());
        let sig = EDDSASignature { r: sig_r, s: sig_s };

        assert!(verify_message(
            &msg_bits,
            &sig,
            &EDDSAPublicKey(pub_key_uncompressed)
        ));
        println!("verified signature");

        let sig_r_target = builder.constant_affine_point(sig_r);
        let sig_s_biguint_target = builder.constant_biguint(&sig_s_biguint);
        let sig_s_target = builder.biguint_to_nonnative(&sig_s_biguint_target);

        let eddsa_sig_target = EDDSASignatureTarget {
            r: sig_r_target,
            s: sig_s_target,
        };

        builder.verify_signature::<E, C>(msg_bits_target, &eddsa_sig_target, &eddsa_pub_key_target);

        let inner_data = builder.build::<C>();
        let inner_proof = inner_data.prove(pw).unwrap();
        inner_data.verify(inner_proof.clone()).unwrap();

        let mut outer_builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_ecc_config());
        let inner_proof_target = outer_builder.add_virtual_proof_with_pis(&inner_data.common);
        let inner_verifier_data =
            outer_builder.add_virtual_verifier_data(inner_data.common.config.fri_config.cap_height);
        outer_builder.verify_proof::<C>(
            &inner_proof_target,
            &inner_verifier_data,
            &inner_data.common,
        );

        let outer_data = outer_builder.build::<C>();
        for gate in outer_data.common.gates.iter() {
            println!("ecddsa verify recursive gate: {:?}", gate);
        }

        let mut outer_pw = PartialWitness::new();
        outer_pw.set_proof_with_pis_target(&inner_proof_target, &inner_proof);
        outer_pw.set_verifier_data_target(&inner_verifier_data, &inner_data.verifier_only);

        let outer_proof = outer_data.prove(outer_pw).unwrap();

        outer_data
            .verify(outer_proof)
            .expect("failed to verify proof");
    }
}
