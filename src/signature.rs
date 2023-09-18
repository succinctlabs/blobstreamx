//! The protobuf encoding of a Tendermint validator is a deterministic function of the validator's
//! public key (32 bytes) and voting power (int64). The encoding is as follows in bytes:
//
//!     10 34 10 32 <pubkey> 16 <varint>
//
//! The `pubkey` is encoded as the raw list of bytes used in the public key. The `varint` is
//! encoded using protobuf's default integer encoding, which consist of 7 bit payloads. You can
//! read more about them here: https://protobuf.dev/programming-guides/encoding/#varints.
use curta::math::field::Field;
use num::BigUint;
use plonky2::field::types::PrimeField;
use plonky2x::frontend::ecc::ed25519::curve::curve_types::AffinePoint;
use plonky2x::frontend::ecc::ed25519::curve::curve_types::Curve;
use plonky2x::frontend::ecc::ed25519::curve::ed25519::Ed25519;
use plonky2x::frontend::ecc::ed25519::field::ed25519_scalar::Ed25519Scalar;
use plonky2x::frontend::ecc::ed25519::gadgets::curve::AffinePointTarget;
use plonky2x::frontend::ecc::ed25519::gadgets::curve::CircuitBuilderCurve;
use plonky2x::frontend::ecc::ed25519::gadgets::eddsa::verify_variable_signatures_circuit;
use plonky2x::frontend::ecc::ed25519::gadgets::eddsa::EDDSASignatureTarget;
use plonky2x::frontend::num::nonnative::nonnative::CircuitBuilderNonNative;
use plonky2x::frontend::num::nonnative::nonnative::NonNativeTarget;
use plonky2x::frontend::vars::U32Variable;
use plonky2x::prelude::BoolVariable;
use plonky2x::prelude::Bytes32Variable;
use plonky2x::prelude::BytesVariable;
use plonky2x::prelude::CircuitBuilder;
use plonky2x::prelude::PlonkParameters;

use crate::utils::ValidatorMessageVariable;
use crate::utils::VALIDATOR_MESSAGE_BYTES_LENGTH_MAX;

pub struct DummySignatureTarget<C: Curve> {
    // TODO: Change back to EDDSAPublicKeyTarget after type alias on EDDSAPublicKeyTarget
    pub pubkey: AffinePointTarget<C>,
    pub signature: EDDSASignatureTarget<C>,
    pub message: ValidatorMessageVariable,
    pub message_bit_length: U32Variable,
}

// Private key is [0u8; 32]
const DUMMY_PUBLIC_KEY: [u8; 32] = [
    59, 106, 39, 188, 206, 182, 164, 45, 98, 163, 168, 208, 42, 111, 13, 115, 101, 50, 21, 119, 29,
    226, 67, 166, 58, 192, 72, 161, 139, 89, 218, 41,
];
const DUMMY_MSG: [u8; 32] = [0u8; 32];
const DUMMY_MSG_LENGTH_BYTES: u32 = 32;
const DUMMY_MSG_LENGTH_BITS: u32 = 256;
// dummy_msg signed by the dummy private key
pub const DUMMY_SIGNATURE: [u8; 64] = [
    61, 161, 235, 223, 169, 110, 221, 24, 29, 190, 54, 89, 209, 192, 81, 196, 49, 240, 86, 165,
    173, 106, 151, 166, 13, 92, 202, 16, 70, 4, 56, 120, 53, 70, 70, 30, 49, 40, 95, 197, 159, 145,
    199, 7, 38, 66, 116, 80, 97, 226, 69, 29, 95, 243, 59, 204, 216, 195, 199, 77, 171, 202, 246,
    10,
];

pub trait TendermintSignature<L: PlonkParameters<D>, const D: usize> {
    type Curve: Curve;
    type ScalarField: PrimeField;

    /// Returns the dummy targets
    fn get_dummy_targets(&mut self) -> DummySignatureTarget<Self::Curve>;

    // Extract a hash from a protobuf-encoded array of bits.
    fn extract_hash_from_protobuf<const START_BYTE: usize, const PROTOBUF_MSG_LENGTH_BYTES: usize>(
        &mut self,
        hash: &BytesVariable<PROTOBUF_MSG_LENGTH_BYTES>,
    ) -> Bytes32Variable;

    /// Extract the header hash from the signed message from a validator.
    fn verify_hash_in_message(
        &mut self,
        message: &ValidatorMessageVariable,
        header_hash: Bytes32Variable,
        // Should be the same for all validators
        round_present_in_message: BoolVariable,
    ) -> BoolVariable;

    /// Verifies the signatures of the validators in the validator set.
    fn verify_signatures<const VALIDATOR_SET_SIZE_MAX: usize>(
        &mut self,
        // This message should be range-checked before being passed in.
        validator_active: &Vec<BoolVariable>,
        messages: Vec<ValidatorMessageVariable>,
        message_bit_lengths: Vec<U32Variable>,
        eddsa_sig_targets: Vec<EDDSASignatureTarget<Self::Curve>>,
        eddsa_pubkey_targets: Vec<AffinePointTarget<Self::Curve>>,
    );
}

impl<L: PlonkParameters<D>, const D: usize> TendermintSignature<L, D> for CircuitBuilder<L, D> {
    type Curve = Ed25519;
    type ScalarField = Ed25519Scalar;

    fn get_dummy_targets(&mut self) -> DummySignatureTarget<Self::Curve> {
        // Convert the dummy public key to a target
        let pub_key_uncompressed: AffinePoint<Self::Curve> =
            AffinePoint::new_from_compressed_point(&DUMMY_PUBLIC_KEY);

        let sig_r: AffinePoint<Self::Curve> =
            AffinePoint::new_from_compressed_point(&DUMMY_SIGNATURE[0..32]);
        assert!(sig_r.is_valid());

        let sig_s_biguint = BigUint::from_bytes_le(&DUMMY_SIGNATURE[32..64]);
        let sig_s = Ed25519Scalar::from_noncanonical_biguint(sig_s_biguint.clone());

        let pubkey = self.constant::<AffinePointTarget<Self::Curve>>(pub_key_uncompressed);

        let signature = EDDSASignatureTarget {
            r: self.constant::<AffinePointTarget<Self::Curve>>(sig_r),
            s: self.constant::<NonNativeTarget<Self::ScalarField>>(sig_s),
        };

        let message = self.zero::<BytesVariable<VALIDATOR_MESSAGE_BYTES_LENGTH_MAX>>();

        // TODO: Change to DUMMY_MSG_LENGTH_BYTES once we switch verify_variable_signatures.
        let dummy_msg_length = self.constant::<U32Variable>(DUMMY_MSG_LENGTH_BITS);

        DummySignatureTarget {
            pubkey: pubkey,
            signature,
            message,
            message_bit_length: dummy_msg_length,
        }
    }

    fn extract_hash_from_protobuf<
        const START_BYTE: usize,
        const PROTOBUF_MSG_LENGTH_BYTES: usize,
    >(
        &mut self,
        bytes: &BytesVariable<PROTOBUF_MSG_LENGTH_BYTES>,
    ) -> Bytes32Variable {
        Bytes32Variable(BytesVariable(
            bytes.0[START_BYTE..START_BYTE + 32].try_into().unwrap(),
        ))
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

        let round_missing_header = self.extract_hash_from_protobuf::<MISSING_ROUND_START_IDX, VALIDATOR_MESSAGE_BYTES_LENGTH_MAX>(message);

        let round_present_header = self.extract_hash_from_protobuf::<INCLUDING_ROUND_START_IDX, VALIDATOR_MESSAGE_BYTES_LENGTH_MAX>(message);

        let computed_header = self.select(
            round_present_in_message,
            round_present_header,
            round_missing_header,
        );

        self.is_equal(computed_header, header_hash)
    }

    /// Verifies the signatures of the validators in the validator set.
    fn verify_signatures<const VALIDATOR_SET_SIZE_MAX: usize>(
        &mut self,
        // This message should be range-checked before being passed in.
        validator_active: &Vec<BoolVariable>,
        messages: Vec<ValidatorMessageVariable>,
        message_bit_lengths: Vec<U32Variable>,
        eddsa_sig_targets: Vec<EDDSASignatureTarget<Self::Curve>>,
        eddsa_pubkey_targets: Vec<AffinePointTarget<Self::Curve>>,
    ) {
        const VALIDATOR_MESSAGE_BITS_LENGTH_MAX: usize = VALIDATOR_MESSAGE_BYTES_LENGTH_MAX * 8;

        let dummy_target = self.get_dummy_targets();

        let eddsa_target = verify_variable_signatures_circuit::<
            L::Field,
            Self::Curve,
            L::CubicParams,
            L::CurtaConfig,
            D,
            VALIDATOR_MESSAGE_BITS_LENGTH_MAX,
        >(&mut self.api, messages.len());

        for i in 0..VALIDATOR_SET_SIZE_MAX {
            // Select the correct pubkey based on whether the validator signed this round.
            let eddsa_pubkey = self.select(
                validator_active[i],
                eddsa_pubkey_targets[i].clone(),
                dummy_target.pubkey.clone(),
            );

            let eddsa_sig = self.select(
                validator_active[i],
                eddsa_sig_targets[i].clone(),
                dummy_target.signature.clone(),
            );

            let msg = self.select(validator_active[i], messages[i], dummy_target.message);

            let bit_length = self.select(
                validator_active[i],
                message_bit_lengths[i],
                dummy_target.message_bit_length,
            );

            // TODO: REMOVE THESE CONSTRAINTS AFTER VERIFY_VARIABLE_SIGNATURES_CIRCUIT is ported
            // TODO: Check the endianness of msg if this fails
            let msg_bool_targets = self.to_le_bits(msg);
            for j in 0..VALIDATOR_MESSAGE_BITS_LENGTH_MAX {
                self.api
                    .connect(eddsa_target.msgs[i][j].target, msg_bool_targets[j].0 .0);
            }
            self.api
                .connect(eddsa_target.msgs_lengths[i], bit_length.0 .0);

            self.api
                .connect_nonnative(&eddsa_target.sigs[i].s, &eddsa_sig.s);
            self.api
                .connect_affine_point(&eddsa_sig.r, &eddsa_target.sigs[i].r);

            self.api
                .connect_affine_point(&eddsa_pubkey, &eddsa_target.pub_keys[i].0);
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use num::BigUint;
    use plonky2::field::types::Field;
    use plonky2x::frontend::ecc::ed25519::curve::eddsa::{
        verify_message, EDDSAPublicKey, EDDSASignature,
    };
    use plonky2x::prelude::{CircuitBuilder, DefaultParameters};
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
        type L = DefaultParameters;
        type Curve = Ed25519;

        const D: usize = 2;

        let mut builder = CircuitBuilder::<L, D>::new();

        let mut new_msg_bytes = msg_bytes.clone();

        new_msg_bytes.resize(VALIDATOR_MESSAGE_BYTES_LENGTH_MAX, 0u8);

        let msg_bytes_variable = builder
            .constant::<BytesVariable<VALIDATOR_MESSAGE_BYTES_LENGTH_MAX>>(
                new_msg_bytes.clone().try_into().unwrap(),
            );

        let msg_bit_length_t = builder.constant::<U32Variable>(msg_bytes.len() as u32 * 8);

        let pub_key_uncompressed: AffinePoint<Curve> =
            AffinePoint::new_from_compressed_point(&pub_key_bytes);

        let eddsa_pub_key_target = builder.api.constant_affine_point(pub_key_uncompressed);

        let sig_r = AffinePoint::new_from_compressed_point(&sig_bytes[0..32]);
        assert!(sig_r.is_valid());

        let sig_s_biguint = BigUint::from_bytes_le(&sig_bytes[32..64]);
        let sig_s = Ed25519Scalar::from_noncanonical_biguint(sig_s_biguint.clone());
        let sig = EDDSASignature { r: sig_r, s: sig_s };

        assert!(verify_message(
            &to_be_bits(msg_bytes.clone()),
            &sig,
            &EDDSAPublicKey(pub_key_uncompressed)
        ));
        println!("verified signature");

        let sig_r_target = builder.api.constant_affine_point(sig_r);
        let sig_s_biguint_target = builder.api.constant_biguint(&sig_s_biguint);
        let sig_s_target = builder.api.biguint_to_nonnative(&sig_s_biguint_target);

        let eddsa_sig_target = EDDSASignatureTarget {
            r: sig_r_target,
            s: sig_s_target,
        };

        let validator_active = vec![builder._false()];

        builder.verify_signatures::<1>(
            &validator_active,
            vec![msg_bytes_variable],
            vec![msg_bit_length_t],
            vec![eddsa_sig_target],
            vec![eddsa_pub_key_target],
        );

        let circuit = builder.build();

        let input = circuit.input();
        let (proof, output) = circuit.prove(&input);
        circuit.verify(&proof, &input, &output);
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
