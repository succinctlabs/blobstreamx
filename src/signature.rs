//! The protobuf encoding of a Tendermint validator is a deterministic function of the validator's
//! public key (32 bytes) and voting power (int64). The encoding is as follows in bytes:
//
//!     10 34 10 32 <pubkey> 16 <varint>
//
//! The `pubkey` is encoded as the raw list of bytes used in the public key. The `varint` is
//! encoded using protobuf's default integer encoding, which consist of 7 bit payloads. You can
//! read more about them here: https://protobuf.dev/programming-guides/encoding/#varints.
use curta::math::extension::cubic::parameters::CubicParameters;
use curta::math::field::Field;
use num::BigUint;
use plonky2::field::extension::Extendable;
use plonky2::iop::target::BoolTarget;
use plonky2::iop::target::Target;
use plonky2::plonk::config::AlgebraicHasher;
use plonky2::plonk::config::GenericConfig;
use plonky2::{hash::hash_types::RichField, plonk::circuit_builder::CircuitBuilder};
use plonky2x::frontend::ecc::ed25519::curve::curve_types::AffinePoint;
use plonky2x::frontend::ecc::ed25519::curve::curve_types::Curve;
use plonky2x::frontend::ecc::ed25519::curve::ed25519::Ed25519;
use plonky2x::frontend::ecc::ed25519::field::ed25519_scalar::Ed25519Scalar;
use plonky2x::frontend::ecc::ed25519::gadgets::curve::CircuitBuilderCurve;
use plonky2x::frontend::ecc::ed25519::gadgets::eddsa::verify_variable_signatures_circuit;
use plonky2x::frontend::ecc::ed25519::gadgets::eddsa::{
    verify_signatures_circuit, EDDSAPublicKeyTarget, EDDSASignatureTarget,
};
use plonky2x::frontend::num::nonnative::nonnative::CircuitBuilderNonNative;
use plonky2x::prelude::GoldilocksField;

use crate::utils::to_be_bits;
use crate::utils::{
    TendermintHashTarget, ValidatorMessageTarget, HASH_SIZE_BITS,
    VALIDATOR_MESSAGE_BYTES_LENGTH_MAX,
};

pub struct DummySignatureTarget<C: Curve> {
    pub pubkey: EDDSAPublicKeyTarget<C>,
    pub signature: EDDSASignatureTarget<C>,
    pub message: ValidatorMessageTarget,
    pub message_bit_length: Target,
}

// Private key is [0u8; 32]
const DUMMY_PUBLIC_KEY: [u8; 32] = [
    59, 106, 39, 188, 206, 182, 164, 45, 98, 163, 168, 208, 42, 111, 13, 115, 101, 50, 21, 119, 29,
    226, 67, 166, 58, 192, 72, 161, 139, 89, 218, 41,
];
const DUMMY_MSG: [u8; 32] = [0u8; 32];
const DUMMY_MSG_LENGTH_BITS: usize = 256;
// dummy_msg signed by the dummy private key
const DUMMY_SIGNATURE: [u8; 64] = [
    61, 161, 235, 223, 169, 110, 221, 24, 29, 190, 54, 89, 209, 192, 81, 196, 49, 240, 86, 165,
    173, 106, 151, 166, 13, 92, 202, 16, 70, 4, 56, 120, 53, 70, 70, 30, 49, 40, 95, 197, 159, 145,
    199, 7, 38, 66, 116, 80, 97, 226, 69, 29, 95, 243, 59, 204, 216, 195, 199, 77, 171, 202, 246,
    10,
];

pub trait TendermintSignature<F: RichField + Extendable<D>, const D: usize> {
    type Curve: Curve;

    /// Returns the dummy targets
    fn get_dummy_targets(&mut self) -> DummySignatureTarget<Self::Curve>;

    // Extract a hash from a protobuf-encoded array of bits.
    fn extract_hash_from_protobuf<const START_BYTE: usize, const PROTOBUF_MSG_LENGTH_BITS: usize>(
        &mut self,
        hash: &[BoolTarget; PROTOBUF_MSG_LENGTH_BITS],
    ) -> TendermintHashTarget;

    /// Extract the header hash from the signed message from a validator.
    fn verify_hash_in_message(
        &mut self,
        message: &ValidatorMessageTarget,
        header_hash: &TendermintHashTarget,
        // Should be the same for all validators
        round_present_in_message: &BoolTarget,
    ) -> BoolTarget;

    /// Verifies the signatures of the validators in the validator set.
    fn verify_signatures<
        E: CubicParameters<F>,
        C: GenericConfig<D, F = F, FE = F::Extension> + 'static,
    >(
        &mut self,
        // This message should be range-checked before being passed in.
        validator_active: &Vec<BoolTarget>,
        messages: Vec<ValidatorMessageTarget>,
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

    fn get_dummy_targets(&mut self) -> DummySignatureTarget<Self::Curve> {
        // Convert the dummy public key to a target
        let pub_key_uncompressed: AffinePoint<Self::Curve> =
            AffinePoint::new_from_compressed_point(&DUMMY_PUBLIC_KEY);

        let sig_r: AffinePoint<Self::Curve> =
            AffinePoint::new_from_compressed_point(&DUMMY_SIGNATURE[0..32]);
        assert!(sig_r.is_valid());

        let sig_s_biguint = BigUint::from_bytes_le(&DUMMY_SIGNATURE[32..64]);
        let sig_s = Ed25519Scalar::from_noncanonical_biguint(sig_s_biguint.clone());

        let pubkey = EDDSAPublicKeyTarget(self.constant_affine_point(pub_key_uncompressed));

        let signature = EDDSASignatureTarget {
            r: self.constant_affine_point(sig_r),
            s: self.constant_nonnative(sig_s),
        };

        let mut message = Vec::new();
        let dummy_msg_bits = to_be_bits(DUMMY_MSG.to_vec());

        for i in 0..DUMMY_MSG_LENGTH_BITS {
            message.push(self.constant_bool(dummy_msg_bits[i]));
        }
        // Fill out the rest of the message with zeros
        message.resize(VALIDATOR_MESSAGE_BYTES_LENGTH_MAX * 8, self._false());

        let dummy_msg_length = self.constant(F::from_canonical_usize(DUMMY_MSG_LENGTH_BITS));

        let message = ValidatorMessageTarget(message.try_into().unwrap());

        DummySignatureTarget {
            pubkey,
            signature,
            message,
            message_bit_length: dummy_msg_length,
        }
    }

    fn extract_hash_from_protobuf<
        const START_BYTE: usize,
        const PROTOBUF_MSG_LENGTH_BITS: usize,
    >(
        &mut self,
        hash: &[BoolTarget; PROTOBUF_MSG_LENGTH_BITS],
    ) -> TendermintHashTarget {
        let mut result = [self._false(); HASH_SIZE_BITS];
        // Skip first 2 bytes
        for i in 0..HASH_SIZE_BITS {
            result[i] = hash[i + (8 * START_BYTE)];
        }
        TendermintHashTarget(result)
    }

    fn verify_hash_in_message(
        &mut self,
        message: &ValidatorMessageTarget,
        header_hash: &TendermintHashTarget,
        // Should be the same for all validators
        round_present_in_message: &BoolTarget,
    ) -> BoolTarget {
        // Logic:
        //      Verify that header_hash is equal to the hash in the message at the correct index.
        //      If the round is missing, then the hash starts at index 16.
        //      If the round is present, then the hash starts at index 25.

        const MISSING_ROUND_START_IDX: usize = 16;

        const INCLUDING_ROUND_START_IDX: usize = 25;

        let round_absent_in_message = self.not(*round_present_in_message);

        let mut vec_round_missing = [self._false(); HASH_SIZE_BITS];

        let mut vec_round_present = [self._false(); HASH_SIZE_BITS];

        let mut eq_so_far = self._true();

        for i in 0..HASH_SIZE_BITS {
            vec_round_present[i] = message.0[(INCLUDING_ROUND_START_IDX) * 8 + i];
            vec_round_missing[i] = message.0[(MISSING_ROUND_START_IDX) * 8 + i];

            let round_present_eq =
                self.is_equal(header_hash.0[i].target, vec_round_present[i].target);
            let round_missing_eq =
                self.is_equal(header_hash.0[i].target, vec_round_missing[i].target);

            // Pick the correct bit based on whether the round is present or not.
            // Select operation as boolean (A & B) | (!A & C) where A is the selector bit.
            let left = self.and(*round_present_in_message, round_present_eq);

            let right = self.and(round_absent_in_message, round_missing_eq);

            let hash_eq = self.or(left, right);

            // AND the check of the bits so far
            eq_so_far = self.and(eq_so_far, hash_eq);
        }

        eq_so_far
    }

    /// Verifies the signatures of the validators in the validator set.
    fn verify_signatures<
        E: CubicParameters<F>,
        C: GenericConfig<D, F = F, FE = F::Extension> + 'static,
    >(
        &mut self,
        validator_active: &Vec<BoolTarget>,
        // Variable length messages, need to be cast into VALIDATOR_MESSAGE_BYTES_LENGTH_MAX*8 long
        messages: Vec<ValidatorMessageTarget>,
        // This message should be range-checked before being passed in.
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

        const VALIDATOR_MESSAGE_BITS_LENGTH_MAX: usize = VALIDATOR_MESSAGE_BYTES_LENGTH_MAX * 8;

        let zero = self.zero();
        let one = self.one();
        let dummy_target = self.get_dummy_targets();

        let eddsa_target = verify_variable_signatures_circuit::<
            F,
            Self::Curve,
            E,
            C,
            D,
            VALIDATOR_MESSAGE_BITS_LENGTH_MAX,
        >(self, messages.len());

        for i in 0..messages.len() {
            let message = &messages[i];
            let eddsa_sig_target = eddsa_sig_targets[i];
            // Select dummy pubkey if the validator did not sign this round.
            let eddsa_pubkey_target = eddsa_pubkey_targets[i];

            // TODO: Fix clone?
            let pubkey_targets = [eddsa_pubkey_target.0.clone(), dummy_target.pubkey.0.clone()];

            let sig_r_target = [eddsa_sig_target.r.clone(), dummy_target.signature.r.clone()];

            let sig_s_target = [eddsa_sig_target.s.clone(), dummy_target.signature.s.clone()];

            let idx = self.select(validator_active[i], zero, one);

            // Select the correct pubkey based on whether the validator signed this round.
            let eddsa_pubkey_target = self.random_access_affine_point(idx, pubkey_targets.to_vec());

            // Select the correct sig r based on whether the validator signed this round
            let sig_r = self.random_access_affine_point(idx, sig_r_target.to_vec());

            // Select the correct sig s based on whether the validator signed this round
            let sig_s = self.random_access_nonnative(idx, sig_s_target.to_vec());

            let eddsa_sig_target = EDDSASignatureTarget { r: sig_r, s: sig_s };

            // Select correct message based on whether the validator signed this round
            for j in 0..VALIDATOR_MESSAGE_BITS_LENGTH_MAX {
                let bit = self.select(
                    validator_active[i],
                    message.0[j].target,
                    // All dummy message bits are zero
                    zero,
                );
                self.connect(eddsa_target.msgs[i][j].target, bit);
            }

            let bit_length = self.select(
                validator_active[i],
                message_bit_lengths[i],
                dummy_target.message_bit_length,
            );

            self.connect(eddsa_target.msgs_lengths[i], bit_length);

            // Select dummy signature if the validator did not sign this round.
            self.connect_nonnative(&eddsa_target.sigs[i].s, &eddsa_sig_target.s);
            self.connect_nonnative(&eddsa_target.sigs[i].r.x, &eddsa_sig_target.r.x);
            self.connect_nonnative(&eddsa_target.sigs[i].r.y, &eddsa_sig_target.r.y);

            self.connect_affine_point(&eddsa_target.pub_keys[i].0, &eddsa_pubkey_target);
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

        self.connect_affine_point(&eddsa_target.sigs[0].r, &eddsa_sig_target.r);
        self.connect_nonnative(&eddsa_target.sigs[0].s, &eddsa_sig_target.s);

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
    use plonky2x::frontend::ecc::ed25519::curve::eddsa::{verify_message, EDDSAPublicKey, EDDSASignature};
    use subtle_encoding::hex;

    use plonky2x::frontend::num::biguint::CircuitBuilderBiguint;

    use plonky2x::frontend::ecc::ed25519::curve::curve_types::AffinePoint;
    use plonky2x::frontend::ecc::ed25519::field::ed25519_scalar::Ed25519Scalar;
    use tendermint::crypto::ed25519::SigningKey;
    use tendermint::private_key;

    use crate::utils::to_be_bits;

    #[test]
    fn test_generate_signature() {
        let priv_key_bytes = vec![0u8; 32];
        let signing_key =
            private_key::Ed25519::try_from(&priv_key_bytes[..]).expect("failed to create key");
        let signing_key = SigningKey::try_from(signing_key).unwrap();
        let signing_key = ed25519_consensus::SigningKey::try_from(signing_key).unwrap();

        let verification_key = signing_key.verification_key();

        println!("public key: {:?}", verification_key.clone().to_bytes());

        let signature = signing_key.sign(&[0u8; 32]);
        println!("signature: {:?}", hex::encode(signature.clone().to_bytes()));
        println!("signature: {:?}", signature.clone().to_bytes());

        verification_key
            .verify(&signature, &[0u8; 32])
            .expect("failed to verify signature");
    }

    fn verify_eddsa_signature(msg_bytes: Vec<u8>, pub_key_bytes: Vec<u8>, sig_bytes: Vec<u8>) {
        type F = GoldilocksField;
        type Curve = Ed25519;
        type E = GoldilocksCubicParameters;
        type C = PoseidonGoldilocksConfig;
        const D: usize = 2;

        let pw = PartialWitness::new();
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_ecc_config());

        let msg_bits = to_be_bits(msg_bytes.to_vec());
        let msg_bit_length = msg_bits.len();
        let msg_bit_length_t = builder.constant(F::from_canonical_usize(msg_bit_length));
        let mut msg_bits_target = Vec::new();
        for i in 0..msg_bits.len() {
            msg_bits_target.push(builder.constant_bool(msg_bits[i]));
        }
        msg_bits_target.resize(VALIDATOR_MESSAGE_BYTES_LENGTH_MAX * 8, builder._false());

        let msg_bits_target = ValidatorMessageTarget(msg_bits_target.try_into().unwrap());

        let pub_key_uncompressed: AffinePoint<Curve> =
            AffinePoint::new_from_compressed_point(&pub_key_bytes);

        let eddsa_pub_key_target =
            EDDSAPublicKeyTarget(builder.constant_affine_point(pub_key_uncompressed));

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

        let validator_active = vec![builder._false()];

        builder.verify_signatures::<E, C>(
            &validator_active,
            vec![msg_bits_target],
            vec![msg_bit_length_t],
            vec![&eddsa_sig_target],
            vec![&eddsa_pub_key_target],
        );

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

    #[test]
    fn test_verify_round_absent_eddsa_signature() {
        // First signature from block 11000
        let msg = "6c080211f82a00000000000022480a2036f2d954fe1ba37c5036cb3c6b366d0daf68fccbaa370d9490361c51a0a38b61122408011220cddf370e891591c9d912af175c966cd8dfa44b2c517e965416b769eb4b9d5d8d2a0c08f6b097a50610dffbcba90332076d6f6368612d33";
        let pubkey = "de25aec935b10f657b43fa97e5a8d4e523bdb0f9972605f0b064eff7b17048ba";
        let sig = "091576e9e3ad0e5ba661f7398e1adb3976ba647b579b8e4a224d1d02b591ade6aedb94d3bf55d258f089d6413155a57adfd4932418a798c2d68b29850f6fb50b";
        let msg_bytes = hex::decode(msg).unwrap();
        let pub_key_bytes = hex::decode(pubkey).unwrap();
        let sig_bytes = hex::decode(sig).unwrap();
        verify_eddsa_signature(msg_bytes, pub_key_bytes, sig_bytes)
    }
    #[test]
    fn test_verify_round_present_eddsa_signature() {
        // First signature from block 11105 (round present)
        let msg = "74080211612b00000000000019010000000000000022480a205047a5a855854ca8bc610fb47ee849084c04fe25a2f037a07de6ae343c55216b122408011220cb05d8adc7c24d55f06d3bd0aea50620d3f0d73a9656a9073cc47a959a0961672a0b08acbd97a50610b1a5f31132076d6f6368612d33";
        let pubkey = "de25aec935b10f657b43fa97e5a8d4e523bdb0f9972605f0b064eff7b17048ba";
        let sig = "b4ea1e808fa88073ae8fe9d9d33d99ae7990cb148c81f2158e56c90aa45d9c3457aaffb875853956b0093ab1b3606b4eb450f5b476e54c508375a25c78376e0d";
        let msg_bytes = hex::decode(msg).unwrap();
        let pub_key_bytes = hex::decode(pubkey).unwrap();
        let sig_bytes = hex::decode(sig).unwrap();
        verify_eddsa_signature(msg_bytes, pub_key_bytes, sig_bytes)
    }
    #[test]
    fn test_verify_dummy_signature() {
        verify_eddsa_signature(
            DUMMY_MSG.to_vec(),
            DUMMY_PUBLIC_KEY.to_vec(),
            DUMMY_SIGNATURE.to_vec(),
        )
    }
}
