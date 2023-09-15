//! The protobuf encoding of a Tendermint validator is a deterministic function of the validator's
//! public key (32 bytes) and voting power (int64). The encoding is as follows in bytes:
//
//!     10 34 10 32 <pubkey> 16 <varint>
//
//! The `pubkey` is encoded as the raw list of bytes used in the public key. The `varint` is
//! encoded using protobuf's default integer encoding, which consist of 7 bit payloads. You can
//! read more about them here: https://protobuf.dev/programming-guides/encoding/#varints.
use curta::chip::hash::sha::sha256::builder_gadget::{
    CurtaBytes, SHA256Builder, SHA256BuilderGadget,
};
use curta::math::extension::cubic::parameters::CubicParameters;
use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::target::BoolTarget;
use plonky2::iop::target::Target;
use plonky2x::frontend::ecc::ed25519::curve::curve_types::Curve;
use plonky2x::frontend::ecc::ed25519::curve::ed25519::Ed25519;
use plonky2x::frontend::ecc::ed25519::gadgets::curve::{AffinePointTarget, CircuitBuilderCurve};
use plonky2x::frontend::hash::sha::sha256::pad_single_sha256_chunk;
use plonky2x::frontend::num::u32::gadgets::arithmetic_u32::CircuitBuilderU32;
use plonky2x::frontend::uint::uint64::U64Variable;
use tendermint::merkle::HASH_SIZE;

use crate::utils::{
    MarshalledValidatorTarget, TendermintHashTarget, HASH_SIZE_BITS, VALIDATOR_BIT_LENGTH_MAX,
    VALIDATOR_BYTE_LENGTH_MAX, VOTING_POWER_BITS_LENGTH_MAX, VOTING_POWER_BYTES_LENGTH_MAX,
};

use plonky2x::prelude::{BoolVariable, ByteVariable, CircuitBuilder, PlonkParameters, Variable};

pub trait TendermintValidator<L: PlonkParameters<D>, const D: usize> {
    type Curve: Curve;

    /// Serializes an int64 as a protobuf varint.
    fn marshal_int64_varint(
        &mut self,
        num: &U64Variable,
    ) -> [BoolTarget; VOTING_POWER_BITS_LENGTH_MAX];

    /// Serializes the validator public key and voting power to bytes.
    fn marshal_tendermint_validator(
        &mut self,
        pubkey: &AffinePointTarget<Self::Curve>,
        voting_power: &U64Variable,
    ) -> MarshalledValidatorTarget;

    /// Hashes validator bytes to get the leaf according to the Tendermint spec. (0x00 || validatorBytes)
    /// Note: This function differs from leaf_hash_stark because the validator bytes length is variable.
    fn hash_validator_leaf(
        &mut self,
        validator: &MarshalledValidatorTarget,
        validator_byte_length: Target,
    ) -> TendermintHashTarget;

    /// Hashes multiple validators to get their leaves according to the Tendermint spec using hash_validator_leaf.
    fn hash_validator_leaves<const VALIDATOR_SET_SIZE_MAX: usize>(
        &mut self,
        validators: &Vec<MarshalledValidatorTarget>,
        validator_byte_lengths: &Vec<Target>,
    ) -> Vec<TendermintHashTarget>;

    /// Compute the expected validator hash from the validator set.
    fn hash_validator_set<const VALIDATOR_SET_SIZE_MAX: usize>(
        &mut self,
        validators: &Vec<MarshalledValidatorTarget>,
        validator_byte_lengths: &Vec<Target>,
        validator_enabled: &Vec<BoolTarget>,
    ) -> TendermintHashTarget;
}

impl<L: PlonkParameters<D>, const D: usize> TendermintValidator<L, D> for CircuitBuilder<L, D> {
    type Curve = Ed25519;

    fn marshal_int64_varint(
        &mut self,
        voting_power: &U64Variable,
    ) -> [BoolTarget; VOTING_POWER_BITS_LENGTH_MAX] {
        let zero = self.zero();
        let one = self.one();

        // The remaining bytes of the serialized validator are the voting power as a "varint".
        // Note: need to be careful regarding U64 and I64 differences.
        let voting_power_bits_lower = self.u32_to_bits_le(voting_power.0[0]);
        let voting_power_bits_upper = self.u32_to_bits_le(voting_power.0[1]);
        let voting_power_bits = [voting_power_bits_lower, voting_power_bits_upper].concat();

        // Check that the MSB of the voting power is zero.
        self.assert_zero(voting_power_bits[voting_power_bits.len() - 1].target);

        // The septet (7 bit) payloads  of the "varint".
        let septets = (0..VOTING_POWER_BYTES_LENGTH_MAX)
            .map(|i| {
                let mut base = F::ONE;
                let mut septet = self.zero();
                for j in 0..7 {
                    let bit = voting_power_bits[i * 7 + j];
                    septet = self.mul_const_add(base, bit.target, septet);
                    base *= F::TWO;
                }
                septet
            })
            .collect::<Vec<_>>();

        // Calculates whether the septet is not zero.
        let is_zero_septets = (0..VOTING_POWER_BYTES_LENGTH_MAX)
            .map(|i| self.is_equal(septets[i], zero).target)
            .collect::<Vec<_>>();

        // Calculates the index of the last non-zero septet.
        let mut last_seen_non_zero_septet_idx = self.zero();
        for i in 0..VOTING_POWER_BYTES_LENGTH_MAX {
            let is_nonzero_septet = self.sub(one, is_zero_septets[i]);
            let condition = BoolTarget::new_unsafe(is_nonzero_septet);
            let idx = self.constant(F::from_canonical_usize(i));
            last_seen_non_zero_septet_idx =
                self.select(condition, idx, last_seen_non_zero_septet_idx);
        }

        // If the index of a septet is elss than the last non-zero septet, set the most significant
        // bit of the byte to 1 and copy the septet bits into the lower 7 bits. Otherwise, still
        // copy the bit but the set the most significant bit to zero.
        let mut buffer = [self._false(); VOTING_POWER_BYTES_LENGTH_MAX * 8];
        for i in 0..VOTING_POWER_BYTES_LENGTH_MAX {
            // If the index is less than the last non-zero septet index, `diff` will be in
            // [0, VOTING_POWER_BYTES_LENGTH_MAX).
            let idx = self.constant(F::from_canonical_usize(i + 1));
            let diff = self.sub(last_seen_non_zero_septet_idx, idx);

            // Calculates whether we've seen at least one `diff` in [0, VOTING_POWER_BYTES_LENGTH_MAX).
            let mut is_lt_last_non_zero_septet_idx = BoolTarget::new_unsafe(zero);
            for j in 0..VOTING_POWER_BYTES_LENGTH_MAX {
                let candidate_idx = self.constant(F::from_canonical_usize(j));
                let is_candidate = self.is_equal(diff, candidate_idx);
                is_lt_last_non_zero_septet_idx =
                    self.or(is_lt_last_non_zero_septet_idx, is_candidate);
            }

            // Copy septet bits into the buffer.
            for j in 0..7 {
                let bit = voting_power_bits[i * 7 + j];
                buffer[i * 8 + j] = bit;
            }

            // Set the most significant bit of the byte to 1 if the index is less than the last
            // non-zero septet index.
            buffer[i * 8 + 7] = is_lt_last_non_zero_septet_idx;
        }

        return buffer;
    }

    fn marshal_tendermint_validator(
        &mut self,
        pubkey: &AffinePointTarget<Self::Curve>,
        voting_power: &U64Variable,
    ) -> MarshalledValidatorTarget {
        let mut ptr = 0;
        let mut buffer = [self._false(); VALIDATOR_BYTE_LENGTH_MAX * 8];

        // The first four prefix bytes of the serialized validator are `10 34 10 32`.
        let prefix_pubkey_bytes = [10, 34, 10, 32];
        for i in 0..prefix_pubkey_bytes.len() {
            for j in 0..8 {
                let bit = self.constant(F::from_canonical_u64((prefix_pubkey_bytes[i] >> j) & 1));
                buffer[ptr] = BoolTarget::new_unsafe(bit);
                ptr += 1;
            }
        }

        self.curve_assert_valid(pubkey);

        let mut compressed_point = self.compress_point(pubkey);

        // Reverse to le bytes and le bits
        compressed_point.bit_targets.reverse();

        for i in 0..compressed_point.bit_targets.len() {
            buffer[ptr] = compressed_point.bit_targets[i];
            ptr += 1;
        }

        // The next byte of the serialized validator is `16`.
        let prefix_voting_power_byte = 16;
        for j in 0..8 {
            let bit = self.constant(F::from_canonical_u64((prefix_voting_power_byte >> j) & 1));
            buffer[ptr] = BoolTarget::new_unsafe(bit);
            ptr += 1;
        }

        // The remaining bytes of the serialized validator are the voting power as a "varint".
        let voting_power_bits = self.marshal_int64_varint(voting_power);
        for i in 0..VOTING_POWER_BYTES_LENGTH_MAX {
            for j in 0..8 {
                buffer[ptr] = voting_power_bits[i * 8 + j];
                ptr += 1;
            }
        }

        // Flip the bit order.
        let mut temp_buffer = [self._false(); VALIDATOR_BYTE_LENGTH_MAX * 8];
        let mut temp_ptr = 0;
        for (_, bits) in buffer.chunks_mut(8).enumerate() {
            for (bit_num, _) in bits.iter().enumerate() {
                temp_buffer[temp_ptr] = bits[7 - bit_num];
                temp_ptr += 1;
            }
        }

        MarshalledValidatorTarget(temp_buffer)
    }

    fn hash_validator_leaf(
        &mut self,
        validator: &MarshalledValidatorTarget,
        validator_byte_length: Target,
    ) -> TendermintHashTarget {
        let one = self.one();
        let eight = self.constant(F::from_canonical_usize(8));

        // self.curta_sha256_variable(input, last_chunk, input_byte_length)

        // Add one to account for the 0x00 byte.
        let enc_validator_byte_length = self.add(one, validator_byte_length);
        // Multiply by 8 to get the bit length.
        let enc_validator_bit_length = self.mul(enc_validator_byte_length, eight);

        // Encode leaf 0x00 || validator_bits.
        let mut enc_validator_bits = [self._false(); VALIDATOR_BIT_LENGTH_MAX + 8];
        for i in 0..VALIDATOR_BIT_LENGTH_MAX {
            enc_validator_bits[i + 8] = validator.0[i];
        }

        // Pad the leaf according to the SHA256 spec.
        let padded_msg =
            pad_single_sha256_chunk(self, &enc_validator_bits, enc_validator_bit_length);

        // Convert the [BoolTarget; N] into Curta bytes.
        let bytes = CurtaBytes(self.add_virtual_target_arr::<64>());
        const SHA256_SINGLE_CHUNK_BITS_SIZE: usize = 512;

        for i in (0..SHA256_SINGLE_CHUNK_BITS_SIZE).step_by(8) {
            let mut byte = self.zero();
            for j in 0..8 {
                let bit = padded_msg[i + j];
                // MSB is first.
                byte = self.mul_const_add(F::from_canonical_u8(1 << (7 - j)), bit.target, byte);
            }
            self.connect(byte, bytes.0[i / 8]);
        }

        let hash = self.sha256(&bytes, gadget);

        self.convert_from_curta_bytes(&hash)
    }

    fn hash_validator_leaves<const VALIDATOR_SET_SIZE_MAX: usize>(
        &mut self,
        validators: &Vec<MarshalledValidatorTarget>,
        validator_byte_lengths: &Vec<Target>,
    ) -> Vec<TendermintHashTarget> {
        let num_validators = self.constant(F::from_canonical_usize(validators.len()));
        let num_validator_byte_lengths =
            self.constant(F::from_canonical_usize(validator_byte_lengths.len()));
        let validator_set_size_max = self.constant(F::from_canonical_usize(VALIDATOR_SET_SIZE_MAX));

        // Assert the validators length is VALIDATOR_SET_SIZE_MAX.
        self.connect(num_validators, validator_set_size_max);

        // Assert the validator_byte_length length is VALIDATOR_SET_SIZE_MAX.
        self.connect(num_validator_byte_lengths, validator_set_size_max);

        // For each validator
        // 1) Generate the SHA256 hash for each potential byte length of the validator from VALIDATOR_BYTE_LENGTH_MIN to VALIDATOR_BYTE_LENGTH_MAX.
        // 2) Select the hash of the correct byte length.
        // 3) Return the correct hash.

        // Hash each of the validators into a leaf hash.
        let mut validators_leaf_hashes =
            [TendermintHashTarget([self._false(); HASH_SIZE_BITS]); VALIDATOR_SET_SIZE_MAX];
        for i in 0..VALIDATOR_SET_SIZE_MAX {
            validators_leaf_hashes[i] =
                self.hash_validator_leaf(gadget, &validators[i], validator_byte_lengths[i]);
        }

        validators_leaf_hashes.to_vec()
    }

    fn hash_validator_set<const VALIDATOR_SET_SIZE_MAX: usize>(
        &mut self,
        validators: &Vec<MarshalledValidatorTarget>,
        validator_byte_lengths: &Vec<Target>,
        validator_enabled: &Vec<BoolTarget>,
    ) -> TendermintHashTarget {
        let num_validators = self.constant(F::from_canonical_usize(validators.len()));
        let num_validator_byte_lengths =
            self.constant(F::from_canonical_usize(validator_byte_lengths.len()));
        let num_validator_enabled = self.constant(F::from_canonical_usize(validator_enabled.len()));
        let validator_set_size_max = self.constant(F::from_canonical_usize(VALIDATOR_SET_SIZE_MAX));

        // Assert validators length is VALIDATOR_SET_SIZE_MAX
        self.connect(num_validators, validator_set_size_max);

        // Assert validator_byte_length length is VALIDATOR_SET_SIZE_MAX
        self.connect(num_validator_byte_lengths, validator_set_size_max);

        // Assert validator_enabled length is VALIDATOR_SET_SIZE_MAX
        self.connect(num_validator_enabled, validator_set_size_max);

        // Hash each of the validators to get their corresponding leaf hash.
        let mut current_validator_hashes = self.hash_validator_leaves::<E, VALIDATOR_SET_SIZE_MAX>(
            gadget,
            validators,
            validator_byte_lengths,
        );

        // Whether to treat the validator as empty.
        let mut current_validator_enabled = validator_enabled.clone();

        let mut merkle_layer_size = VALIDATOR_SET_SIZE_MAX;

        // Hash each layer of nodes to get the root according to the Tendermint spec, starting from the leaves.
        while merkle_layer_size > 1 {
            (current_validator_hashes, current_validator_enabled) = self.hash_merkle_layer::<E>(
                gadget,
                &mut current_validator_hashes,
                &mut current_validator_enabled,
                merkle_layer_size,
            );
            merkle_layer_size /= 2;
        }

        // Return the root hash.
        current_validator_hashes[0]
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use curta::chip::hash::sha::sha256::SHA256Gadget;
    use curta::math::goldilocks::cubic::GoldilocksCubicParameters;
    use curta::plonky2::stark::config::CurtaPoseidonGoldilocksConfig;
    use plonky2::field::types::Field;
    use plonky2::plonk::prover::prove;
    use plonky2::timed;
    use plonky2::util::timing::TimingTree;
    use plonky2::{
        iop::witness::{PartialWitness, WitnessWrite},
        plonk::{
            circuit_builder::CircuitBuilder,
            circuit_data::CircuitConfig,
            config::{GenericConfig, PoseidonGoldilocksConfig},
        },
    };
    use subtle_encoding::hex;

    use plonky2x::frontend::ecc::ed25519::curve::curve_types::AffinePoint;

    use plonky2x::frontend::num::u32::gadgets::arithmetic_u32::U32Target;

    use crate::{
        utils::{f_bits_to_bytes, to_be_bits},
        validator::TendermintValidator,
    };

    type C = PoseidonGoldilocksConfig;
    type SC = CurtaPoseidonGoldilocksConfig;
    type E = GoldilocksCubicParameters;
    type F = <C as GenericConfig<D>>::F;
    type Curve = Ed25519;
    const D: usize = 2;

    #[test]
    fn test_starky_sha_gadget() {
        env_logger::init();

        let mut timing = TimingTree::new("Sha256 Plonky2 gadget", log::Level::Debug);

        // Create a new plonky2 circuit
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        // Initialize the SHA gadget
        let mut gadget: SHA256BuilderGadget<F, E, D> = builder.init_sha256();

        // We will hash 256 messages of padded length 128 bytes.

        // Initialize targets
        let long_padded_msg_targets = (0..512)
            .map(|_| CurtaBytes(builder.add_virtual_target_arr::<128>()))
            .collect::<Vec<_>>();

        let mut digest_targets = Vec::new();
        let mut expected_digests = Vec::new();

        for long_padded_msg in long_padded_msg_targets.iter() {
            // Get the hash of the padded message
            let digest = builder.sha256(long_padded_msg, &mut gadget);
            digest_targets.push(digest);
            let expected_digest = CurtaBytes(builder.add_virtual_target_arr::<32>());
            expected_digests.push(expected_digest);
        }

        // Connect the expected and output digests
        for (digest, expected) in digest_targets.iter().zip(expected_digests.iter()) {
            for (d, e) in digest.0.iter().zip(expected.0.iter()) {
                builder.connect(*d, *e);
            }
        }

        // Register the SHA constraints in the builder
        builder.constrain_sha256_gadget::<SC>(gadget);

        // Build the circuit
        let data = builder.build::<C>();

        // Assign input values and make the proof
        let mut pw = PartialWitness::new();

        // We will use two types of a short message and one long message

        let long_msg = hex::decode("243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89452821e638d01377be5466cf34e90c6cc0ac29b7c97c50dd3f84d5b5b5470917").unwrap();
        let expected_digest_long =
            "aca16131a2e4c4c49e656d35aac1f0e689b3151bb108fa6cf5bcc3ac08a09bf9";

        let long_messages = (0..512).map(|_| long_msg.clone()).collect::<Vec<_>>();

        // Pad the long messages
        let padded_long_messages = long_messages
            .iter()
            .map(|m| {
                SHA256Gadget::pad(m)
                    .into_iter()
                    .map(F::from_canonical_u8)
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();

        // Get the expected digest values
        let expected_digests_long_message = (0..512)
            .map(|_| expected_digest_long)
            .map(|digest| {
                hex::decode(digest)
                    .unwrap()
                    .into_iter()
                    .map(F::from_canonical_u8)
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();

        let expected_digests_values = expected_digests_long_message;

        // Assign the inputs
        for (msg_target, long_msg) in long_padded_msg_targets
            .iter()
            .zip(padded_long_messages.iter())
        {
            pw.set_target_arr(&msg_target.0, long_msg);
        }

        for (digest, value) in expected_digests.iter().zip(expected_digests_values.iter()) {
            pw.set_target_arr(&digest.0, value);
        }

        // Generate the proof
        let proof = timed!(
            timing,
            "Generate proof",
            prove(&data.prover_only, &data.common, pw, &mut timing)
        )
        .unwrap();
        timing.print();

        // Verify the proof
        data.verify(proof).unwrap();
    }

    #[test]
    fn test_marshal_int64_varint() {
        // These are test cases generated from `celestia-core`.
        //
        // allZerosPubkey := make(ed25519.PubKey, ed25519.PubKeySize)
        // votingPower := int64(9999999999999)
        // validator := NewValidator(allZerosPubkey, votingPower)
        // fmt.Println(validator.Bytes()[37:])
        //
        // The tuples hold the form: (voting_power_i64, voting_power_varint_bytes).
        let test_cases = [
            (1i64, vec![1u8]),
            (3804i64, vec![220u8, 29u8]),
            (1234567890i64, vec![210, 133, 216, 204, 4]),
            (38957235239i64, vec![167, 248, 160, 144, 145, 1]),
            (9999999999999i64, vec![255, 191, 202, 243, 132, 163, 2]),
            (
                724325643436111i64,
                vec![207, 128, 183, 165, 211, 216, 164, 1],
            ),
            (
                9223372036854775807i64,
                vec![255, 255, 255, 255, 255, 255, 255, 255, 127],
            ),
        ];

        for test_case in test_cases {
            let pw = PartialWitness::new();
            let config = CircuitConfig::standard_recursion_config();
            let mut builder = CircuitBuilder::<F, D>::new(config);

            // TODO: Need to add check in marshal that this is not negative
            let voting_power_i64 = test_case.0;
            let voting_power_variable = builder.constant::<U64Variable>(voting_power_i64 as u64);
            let result = builder.marshal_int64_varint(&voting_power_target);

            for i in 0..result.len() {
                builder.register_public_input(result[i].target);
            }

            let data = builder.build::<C>();
            let proof = data.prove(pw).unwrap();

            let marshalled_bytes = f_bits_to_bytes(&proof.public_inputs);
            let expected_bytes = test_case.1;

            println!("Voting Power: {:?}", test_case.0);
            println!("Expected Varint Encoding (Bytes): {:?}", expected_bytes);
            println!("Produced Varint Encoding (Bytes): {:?}", marshalled_bytes);

            for i in 0..marshalled_bytes.len() {
                if i >= expected_bytes.len() {
                    assert_eq!(marshalled_bytes[i], 0);
                    continue;
                }
                assert_eq!(marshalled_bytes[i], expected_bytes[i]);
            }
        }
    }

    #[test]
    fn test_marshal_tendermint_validator() {
        // This is a test cases generated from a validator in block 11000 of the mocha-3 testnet.
        let voting_power_i64 = 100010 as i64;
        let pubkey = "de25aec935b10f657b43fa97e5a8d4e523bdb0f9972605f0b064eff7b17048ba";
        let expected_marshal =
            "0a220a20de25aec935b10f657b43fa97e5a8d4e523bdb0f9972605f0b064eff7b17048ba10aa8d06";

        let pw = PartialWitness::new();
        let config = CircuitConfig::standard_ecc_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let voting_power_variable = builder.constant::<U64Variable>(voting_power_i64 as u64);
        let pub_key_uncompressed: AffinePoint<Curve> =
            AffinePoint::new_from_compressed_point(&hex::decode(pubkey).unwrap());

        let pub_key_affine_t = builder.constant_affine_point(pub_key_uncompressed);

        let pub_key = pub_key_uncompressed.compress_point();

        // Convert pub_key to bytes from biguint
        let pub_key_bytes = pub_key.to_bytes_le();

        println!("pub_key: {:?}", pub_key_bytes);
        println!("expected marshal: {:?}", hex::decode(expected_marshal));

        let result =
            builder.marshal_tendermint_validator(&pub_key_affine_t, &voting_power_variable);

        let expected_bits = to_be_bits(hex::decode(expected_marshal).unwrap().to_vec());

        // Only check the hash bits
        for i in 0..result.0.len() {
            if i < expected_bits.len() {
                let expected_bit_t = builder.constant_bool(expected_bits[i]);
                builder.connect(result.0[i].target, expected_bit_t.target);
            } else {
                let expected_bit_t = builder.constant_bool(false);
                builder.connect(result.0[i].target, expected_bit_t.target);
            }
        }

        let data = builder.build::<C>();
        let proof = data.prove(pw).unwrap();

        println!("Created proof");

        data.verify(proof).unwrap();

        println!("Verified proof");
    }

    // TODO: Add these tests back once the interface for using Curta's SHA gadget is straightforward. Currently, we'd need to compute the total number of SHA's done in each of these tests, and fill out the rest of the SHA's similar to how it's done in test_skip & test_step.

    // #[test]
    // fn test_hash_validator_leaves() {
    //     let mut pw = PartialWitness::new();
    //     let config = CircuitConfig::standard_recursion_config();
    //     let mut builder = CircuitBuilder::<F, D>::new(config);

    //     let mut gadget: SHA256BuilderGadget<F, E, D> = builder.init_sha256();

    //     let validators: Vec<&str> = vec!["6694200ba0e084f7184255abedc39af04463a4ff11e0e0c1326b1b82ea1de50c6b35cf6efa8f7ed3", "739d312e54353379a852b43de497ca4ec52bb49f59b7294a4d6cf19dd648e16cb530b7a7a1e35875d4ab4d90", "4277f2f871f3e041bcd4643c0cf18e5a931c2bfe121ce8983329a289a2b0d2161745a2ddf99bade9a1"];

    //     // Convert validators[0] to CurtaBytes.

    //     // let validators = validators
    //     //     .iter()
    //     //     .map(|x| String::from(*x))
    //     //     .collect::<Vec<_>>();

    //     // let validators_bytes: Vec<Vec<u8>> = validators
    //     //     .iter()
    //     //     .map(|x| hex::decode(x).unwrap())
    //     //     .collect::<Vec<_>>();

    //     // let expected_digests_bytes = hash_all_leaves::<Sha256>(&validators_bytes);

    //     // // Convert the expected hashes to hex strings.
    //     // let expected_digests: Vec<String> = expected_digests_bytes
    //     //     .iter()
    //     //     .map(|x| String::from_utf8(hex::encode(x)).expect("Invalid UTF-8"))
    //     //     .collect::<Vec<_>>();

    //     // // Convert the expected hashes bytes to bits.
    //     // let digests_bits: Vec<Vec<bool>> = expected_digests
    //     //     .iter()
    //     //     .map(|x| to_be_bits(hex::decode(x).unwrap()))
    //     //     .collect();

    //     // let (validators_target, validator_byte_length, _) =
    //     //     generate_inputs::<VALIDATOR_SET_SIZE_MAX>(&mut builder, &validators);

    //     // let mut gadget: SHA256BuilderGadget<F, E, D> = builder.init_sha256();

    //     // let result = builder.hash_validator_leaves::<E, VALIDATOR_SET_SIZE_MAX>(
    //     //     &mut gadget,
    //     //     &validators_target,
    //     //     &validator_byte_length,
    //     // );

    //     // let zero = builder.zero();
    //     // for _ in 0..(1024 - VALIDATOR_SET_SIZE_MAX) {
    //     //     let bytes = CurtaBytes(builder.add_virtual_target_arr::<64>());
    //     //     for i in 0..64 {
    //     //         builder.connect(bytes.0[i], zero);
    //     //     }

    //     //     builder.sha256(&bytes, &mut gadget);
    //     // }

    //     // println!("Got all leaf hashes: {}", result.len());
    //     // for i in 0..validators.len() {
    //     //     for j in 0..HASH_SIZE_BITS {
    //     //         if digests_bits[i][j] {
    //     //             pw.set_target(result[i].0[j].target, F::ONE);
    //     //         } else {
    //     //             pw.set_target(result[i].0[j].target, F::ZERO);
    //     //         }
    //     //     }
    //     // }

    //     // let data = builder.build::<C>();
    //     // let proof = data.prove(pw).unwrap();

    //     // data.verify(proof).unwrap();

    //     // println!("Verified proof");
    // }

    // #[test]
    // fn test_generate_val_hash() {
    //     struct TestCase {
    //         validators: Vec<String>,
    //         expected_digest: String,
    //     }

    //     // Validators from block 11000 on Celestia mocha-3 testnet encoded as bytes.
    //     let validators_arr: Vec<Vec<&str>> = vec![vec![
    //         "0a220a20de25aec935b10f657b43fa97e5a8d4e523bdb0f9972605f0b064eff7b17048ba10aa8d06",
    //         "0a220a208de6ad1a569a223e7bb0dade194abb9487221210e1fa8154bf654a10fe6158a610aa8d06",
    //         "0a220a20e9b7638ca1c42da37d728970632fda77ec61dcc520395ab5d3a645b9c2b8e8b1100a",
    //         "0a220a20bd60452e7f056b22248105e7fd298961371da0d9332ef65fa81691bf51b2e5051001",
    //     ], vec!["364db94241a02b701d0dc85ac016fab2366fba326178e6f11d8294931969072b7441fd6b0ff5129d6867", "6fa0cef8f328eb8e2aef2084599662b1ee0595d842058966166029e96bd263e5367185f19af67b099645ec08aa"]];

    //     let digest_arr: Vec<&str> = vec![
    //         "BB5B8B1239565451DCD5AB52B47C26032016CDF1EF2D2115FF104DC9DDE3988C",
    //         "be110ff9abb6bdeaebf48ac8e179a76fda1f6eaef0150ca6159587f489722204",
    //     ];

    //     let test_cases: Vec<TestCase> = validators_arr
    //         .iter()
    //         .zip(digest_arr.iter())
    //         .map(|(validators, expected_digest)| TestCase {
    //             validators: validators
    //                 .iter()
    //                 .map(|x| String::from(*x).to_lowercase())
    //                 .collect(),
    //             expected_digest: String::from(*expected_digest).to_lowercase(),
    //         })
    //         .collect();

    //     for test_case in test_cases {
    //         let mut pw = PartialWitness::new();
    //         let config = CircuitConfig::standard_recursion_config();
    //         let mut builder = CircuitBuilder::<F, D>::new(config);

    //         let (validators_target, validator_byte_length, validator_enabled) =
    //             generate_inputs::<VALIDATOR_SET_SIZE_MAX>(&mut builder, &test_case.validators);

    //         let digest_bits =
    //             to_be_bits(hex::decode(test_case.expected_digest.as_bytes()).unwrap());

    //         println!(
    //             "Expected Val Hash: {:?}",
    //             String::from_utf8(hex::encode(
    //                 hex::decode(test_case.expected_digest.as_bytes()).unwrap()
    //             ))
    //         );

    //         let result = builder.hash_validator_set::<E, VALIDATOR_SET_SIZE_MAX>(
    //             &validators_target,
    //             &validator_byte_length,
    //             &validator_enabled,
    //         );

    //         for i in 0..HASH_SIZE_BITS {
    //             pw.set_bool_target(result.0[i], digest_bits[i]);
    //         }

    //         let data = builder.build::<C>();
    //         let proof = data.prove(pw).unwrap();

    //         println!("Created proof");

    //         data.verify(proof).unwrap();

    //         println!("Verified proof");
    //     }
    // }

    // #[test]
    // fn test_hash_header_leaf() {
    //     let block = tendermint::Block::from(
    //         serde_json::from_str::<tendermint::block::Block>(include_str!(
    //             "./fixtures/celestia_block.json"
    //         ))
    //         .unwrap(),
    //     );

    //     let encoded_validators_hash_bits = to_be_bits(block.header.validators_hash.encode_vec());
    //     // Note: Make sure to encode_vec()
    //     let validators_leaf_hash =
    //         leaf_hash::<Sha256>(&block.header.validators_hash.encode_vec()).to_vec();

    //     let validators_hash_bits = to_be_bits(validators_leaf_hash);

    //     let mut pw = PartialWitness::new();
    //     let config = CircuitConfig::standard_recursion_config();
    //     let mut builder = CircuitBuilder::<F, D>::new(config);

    //     let mut validators_hash_bits_target = [builder._false(); PROTOBUF_HASH_SIZE_BITS];
    //     for i in 0..encoded_validators_hash_bits.len() {
    //         if encoded_validators_hash_bits[i] {
    //             validators_hash_bits_target[i] = builder._true();
    //         }
    //     }

    //     let result = builder.leaf_hash::<E, PROTOBUF_HASH_SIZE_BITS>(&validators_hash_bits_target);

    //     for i in 0..HASH_SIZE_BITS {
    //         if validators_hash_bits[i] {
    //             pw.set_target(result.0[i].target, F::ONE);
    //         } else {
    //             pw.set_target(result.0[i].target, F::ZERO);
    //         }
    //     }

    //     let data = builder.build::<C>();
    //     let proof = data.prove(pw).unwrap();

    //     println!("Created proof");

    //     data.verify(proof).unwrap();

    //     println!("Verified proof");
    // }

    // #[test]
    // fn test_get_root_from_merkle_proof() {
    //     // Generate test cases from Celestia block:
    //     let block = tendermint::Block::from(
    //         serde_json::from_str::<tendermint::block::Block>(include_str!(
    //             "./fixtures/celestia_block.json"
    //         ))
    //         .unwrap(),
    //     );

    //     let header_hash = block.header.hash().to_string();
    //     let header_bits = to_be_bits(hex::decode(header_hash.to_lowercase()).unwrap());

    //     let mut pw = PartialWitness::new();
    //     let config = CircuitConfig::standard_recursion_config();
    //     let mut builder = CircuitBuilder::<F, D>::new(config);

    //     let (_, proofs) = generate_proofs_from_header(&block.header);

    //     // Can test with leaf_index 6, 7 or 8 (data_hash, validators_hash, next_validators_hash)
    //     let leaf_index = 4;

    //     // Note: Make sure to encode_vec()
    //     // let leaf = block.header.data_hash.expect("data hash present").encode_vec();
    //     // let leaf = block.header.validators_hash.encode_vec();
    //     // let leaf = block.header.next_validators_hash.encode_vec();
    //     let leaf =
    //         Protobuf::<RawBlockId>::encode_vec(block.header.last_block_id.unwrap_or_default());

    //     let leaf_bits = to_be_bits(leaf);

    //     let path_indices = get_path_indices(leaf_index as u64, proofs[0].total);

    //     let path_indices = path_indices
    //         .iter()
    //         .map(|x| builder.constant_bool(*x))
    //         .collect::<Vec<_>>();

    //     let mut leaf_target = [builder._false(); PROTOBUF_BLOCK_ID_SIZE_BITS];
    //     for i in 0..PROTOBUF_BLOCK_ID_SIZE_BITS {
    //         leaf_target[i] = if leaf_bits[i] {
    //             builder._true()
    //         } else {
    //             builder._false()
    //         };
    //     }

    //     let mut aunts_target =
    //         vec![TendermintHashTarget([builder._false(); HASH_SIZE_BITS]); HEADER_PROOF_DEPTH];
    //     for i in 0..HEADER_PROOF_DEPTH {
    //         let bool_vector = to_be_bits(proofs[leaf_index].aunts[i].to_vec());

    //         for j in 0..HASH_SIZE_BITS {
    //             aunts_target[i].0[j] = if bool_vector[j] {
    //                 builder._true()
    //             } else {
    //                 builder._false()
    //             };
    //         }
    //     }

    //     let leaf_hash = builder.leaf_hash::<E, PROTOBUF_BLOCK_ID_SIZE_BITS>(&leaf_target);

    //     let result = builder.get_root_from_merkle_proof::<E, HEADER_PROOF_DEPTH>(
    //         &aunts_target.try_into().unwrap(),
    //         &path_indices.try_into().unwrap(),
    //         &leaf_hash,
    //     );

    //     for i in 0..HASH_SIZE_BITS {
    //         if header_bits[i] {
    //             pw.set_target(result.0[i].target, F::ONE);
    //         } else {
    //             pw.set_target(result.0[i].target, F::ZERO);
    //         }
    //     }

    //     let data = builder.build::<C>();
    //     let proof = data.prove(pw).unwrap();

    //     println!("Created proof");

    //     data.verify(proof).unwrap();

    //     println!("Verified proof");
    // }

    // #[test]
    // fn test_get_leaf_hash() {
    //     let mut pw = PartialWitness::new();
    //     let config = CircuitConfig::standard_recursion_config();
    //     let mut builder = CircuitBuilder::<F, D>::new(config);

    //     // Computed the leaf hashes corresponding to the first validator bytes. SHA256(0x00 || validatorBytes)
    //     let expected_digest = "84f633a570a987326947aafd434ae37f151e98d5e6d429137a4cc378d4a7988e";
    //     let digest_bits = to_be_bits(hex::decode(expected_digest).unwrap());

    //     let validators: Vec<String> = vec![
    //         String::from(
    //             "de6ad0941095ada2a7996e6a888581928203b8b69e07ee254d289f5b9c9caea193c2ab01902d",
    //         ),
    //         String::from(
    //             "92fbe0c52937d80c5ea643c7832620b84bfdf154ec7129b8b471a63a763f2fe955af1ac65fd3",
    //         ),
    //         String::from(
    //             "e902f88b2371ff6243bf4b0ebe8f46205e00749dd4dad07b2ea34350a1f9ceedb7620ab913c2",
    //         ),
    //     ];

    //     let (validators_target, validator_byte_length, _) =
    //         generate_inputs::<VALIDATOR_SET_SIZE_MAX>(&mut builder, &validators);

    //     let result = builder.hash_validator_leaf(&validators_target[0], validator_byte_length[0]);

    //     // Set the target bits to the expected digest bits.
    //     for i in 0..HASH_SIZE_BITS {
    //         if digest_bits[i] {
    //             pw.set_target(result.0[i].target, F::ONE);
    //         } else {
    //             pw.set_target(result.0[i].target, F::ZERO);
    //         }
    //     }

    //     let data = builder.build::<C>();
    //     let proof = data.prove(pw).unwrap();

    //     data.verify(proof).unwrap();

    //     println!("Verified proof");
    // }
}
