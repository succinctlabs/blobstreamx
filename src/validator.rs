//! The protobuf encoding of a Tendermint validator is a deterministic function of the validator's
//! public key (32 bytes) and voting power (int64). The encoding is as follows in bytes:
//
//!     10 34 10 32 <pubkey> 16 <varint>
//
//! The `pubkey` is encoded as the raw list of bytes used in the public key. The `varint` is
//! encoded using protobuf's default integer encoding, which consist of 7 bit payloads. You can
//! read more about them here: https://protobuf.dev/programming-guides/encoding/#varints.
use crate::utils::TendermintHashVariable;
use crate::utils::{
    MarshalledValidatorVariable, TendermintHashTarget, HASH_SIZE_BITS, VALIDATOR_BIT_LENGTH_MAX,
    VALIDATOR_BYTE_LENGTH_MAX, VOTING_POWER_BITS_LENGTH_MAX, VOTING_POWER_BYTES_LENGTH_MAX,
};
use crate::voting;
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
use plonky2x::frontend::num::u32::gadgets::arithmetic_u32::U32Target;
use plonky2x::frontend::uint::uint64::U64Variable;
use plonky2x::frontend::vars::U32Variable;
use plonky2x::prelude::Field;
use tendermint::merkle::HASH_SIZE;

use plonky2x::prelude::{
    BoolVariable, ByteVariable, BytesVariable, CircuitBuilder, CircuitVariable, PlonkParameters,
    Variable,
};

pub trait TendermintValidator<L: PlonkParameters<D>, const D: usize> {
    type Curve: Curve;

    /// Serializes an int64 as a protobuf varint.
    fn marshal_int64_varint(
        &mut self,
        num: &U64Variable,
    ) -> [ByteVariable; VOTING_POWER_BYTES_LENGTH_MAX];

    /// Serializes the validator public key and voting power to bytes.
    fn marshal_tendermint_validator(
        &mut self,
        pubkey: &AffinePointTarget<Self::Curve>,
        voting_power: &U64Variable,
    ) -> MarshalledValidatorVariable;

    /// Hashes validator bytes to get the leaf according to the Tendermint spec. (0x00 || validatorBytes)
    /// Note: This function differs from leaf_hash_stark because the validator bytes length is variable.
    fn hash_validator_leaf(
        &mut self,
        validator: &MarshalledValidatorVariable,
        validator_byte_length: Variable,
    ) -> TendermintHashVariable;

    /// Hashes multiple validators to get their leaves according to the Tendermint spec using hash_validator_leaf.
    fn hash_validator_leaves<const VALIDATOR_SET_SIZE_MAX: usize>(
        &mut self,
        validators: &Vec<MarshalledValidatorVariable>,
        validator_byte_lengths: &Vec<Variable>,
    ) -> Vec<TendermintHashVariable>;

    /// Compute the expected validator hash from the validator set.
    fn hash_validator_set<const VALIDATOR_SET_SIZE_MAX: usize>(
        &mut self,
        validators: &Vec<MarshalledValidatorVariable>,
        validator_byte_lengths: &Vec<Variable>,
        validator_enabled: &Vec<BoolVariable>,
    ) -> TendermintHashVariable;
}

impl<L: PlonkParameters<D>, const D: usize> TendermintValidator<L, D> for CircuitBuilder<L, D> {
    type Curve = Ed25519;

    fn marshal_int64_varint(
        &mut self,
        voting_power: &U64Variable,
    ) -> [ByteVariable; VOTING_POWER_BYTES_LENGTH_MAX] {
        let zero = self.zero::<Variable>();
        let one = self.one::<Variable>();

        // The remaining bytes of the serialized validator are the voting power as a "varint".
        // Note: need to be careful regarding U64 and I64 differences.
        let voting_power_bits = self.to_le_bits(*voting_power);

        // Check that the MSB of the voting power is zero.
        self.api
            .assert_zero(voting_power_bits[voting_power_bits.len() - 1].0 .0);

        // The septet (7 bit) payloads  of the "varint".
        let septets = (0..VOTING_POWER_BYTES_LENGTH_MAX)
            .map(|i| {
                let mut base = L::Field::ONE;
                let mut septet = self.zero::<Variable>();
                for j in 0..7 {
                    let bit = voting_power_bits[i * 7 + j];
                    septet = Variable(self.api.mul_const_add(base, bit.0 .0, septet.0));
                    base *= L::Field::TWO;
                }
                septet
            })
            .collect::<Vec<_>>();

        // Calculates whether the septet is not zero.
        let is_zero_septets = (0..VOTING_POWER_BYTES_LENGTH_MAX)
            .map(|i| self.is_equal(septets[i], zero))
            .collect::<Vec<_>>();

        // Calculates the index of the last non-zero septet.
        let mut last_seen_non_zero_septet_idx = self.zero();
        for i in 0..VOTING_POWER_BYTES_LENGTH_MAX {
            // Ok to cast as BoolVraiable sinec is_zero_septets[i] is 0 or 1 so result is either 0 or 1
            let is_nonzero_septet = BoolVariable(self.sub(one, is_zero_septets[i].0));
            let idx = self.constant::<Variable>(L::Field::from_canonical_usize(i));
            last_seen_non_zero_septet_idx =
                self.select(is_nonzero_septet, idx, last_seen_non_zero_septet_idx);
        }

        let mut res = [self.zero(); VOTING_POWER_BYTES_LENGTH_MAX];

        // If the index of a septet is elss than the last non-zero septet, set the most significant
        // bit of the byte to 1 and copy the septet bits into the lower 7 bits. Otherwise, still
        // copy the bit but the set the most significant bit to zero.
        for i in 0..VOTING_POWER_BYTES_LENGTH_MAX {
            // If the index is less than the last non-zero septet index, `diff` will be in
            // [0, VOTING_POWER_BYTES_LENGTH_MAX).
            let idx = self.constant(L::Field::from_canonical_usize(i + 1));
            let diff = self.sub(last_seen_non_zero_septet_idx, idx);

            // Calculates whether we've seen at least one `diff` in [0, VOTING_POWER_BYTES_LENGTH_MAX).
            let mut is_lt_last_non_zero_septet_idx = self._false();
            for j in 0..VOTING_POWER_BYTES_LENGTH_MAX {
                let candidate_idx = self.constant(L::Field::from_canonical_usize(j));
                let is_candidate = self.is_equal(diff, candidate_idx);
                is_lt_last_non_zero_septet_idx =
                    self.or(is_lt_last_non_zero_septet_idx, is_candidate);
            }

            let mut buffer = [self._false(); 8];
            // Copy septet bits into the buffer.
            for j in 0..7 {
                let bit = voting_power_bits[i * 7 + j];
                buffer[j] = bit;
            }

            // Set the most significant bit of the byte to 1 if the index is less than the last
            // non-zero septet index.
            buffer[7] = is_lt_last_non_zero_septet_idx;

            res[i] = ByteVariable::from_variables_unsafe(
                &buffer.iter().map(|x| x.0).collect::<Vec<Variable>>(),
            );
        }

        return res;
    }

    fn marshal_tendermint_validator(
        &mut self,
        pubkey: &AffinePointTarget<Self::Curve>,
        voting_power: &U64Variable,
    ) -> MarshalledValidatorVariable {
        let mut res = Vec::new();
        res.push(self.constant::<ByteVariable>(10u8));
        res.push(self.constant::<ByteVariable>(34u8));
        res.push(self.constant::<ByteVariable>(10u8));
        res.push(self.constant::<ByteVariable>(32u8));

        let mut compressed_point = self.api.compress_point(pubkey);

        // TODO: in the future compressed_point should probably return a Bytes32Variable
        for i in 0..32 {
            let byte_variable = ByteVariable::from_variables_unsafe(
                &compressed_point.bit_targets[i * 8..(i + 1) * 8]
                    .iter()
                    .map(|x| Variable(x.target))
                    .collect::<Vec<Variable>>(),
            );
            res.push(byte_variable);
        }

        res.push(self.constant::<ByteVariable>(16u8));

        // The remaining bytes of the serialized validator are the voting power as a "varint".
        let voting_power_serialized = self.marshal_int64_varint(voting_power);
        res.extend_from_slice(&voting_power_serialized);

        assert_eq!(res.len(), VALIDATOR_BYTE_LENGTH_MAX);

        BytesVariable::<VALIDATOR_BYTE_LENGTH_MAX>(res.try_into().unwrap())
    }

    fn hash_validator_leaf(
        &mut self,
        validator: &MarshalledValidatorVariable,
        validator_byte_length: Variable,
    ) -> TendermintHashVariable {
        let mut prepended_validator_bytes = vec![self.zero::<ByteVariable>()];
        prepended_validator_bytes.extend(validator.0.to_vec());

        let one = self.one::<Variable>();
        let enc_validator_byte_length = self.add(one, validator_byte_length);
        // TODO: note this is a bit unsafe, so perhaps we should change `curta_sha256_variable` to take in a Variable
        // instead of a U32Variable
        let input_byte_length = U32Variable(validator_byte_length);

        let zero = self.zero::<U32Variable>();

        // VALIDATOR_BYTE_LENGTH_MAX = 46 so we only need 1 chunk
        self.curta_sha256_variable::<1>(&prepended_validator_bytes, zero, input_byte_length)
    }

    fn hash_validator_leaves<const VALIDATOR_SET_SIZE_MAX: usize>(
        &mut self,
        validators: &Vec<MarshalledValidatorVariable>,
        validator_byte_lengths: &Vec<Variable>,
    ) -> Vec<TendermintHashVariable> {
        assert_eq!(validators.len(), VALIDATOR_SET_SIZE_MAX);
        assert_eq!(validator_byte_lengths.len(), VALIDATOR_SET_SIZE_MAX);

        // For each validator
        // 1) Generate the SHA256 hash for each potential byte length of the validator from VALIDATOR_BYTE_LENGTH_MIN to VALIDATOR_BYTE_LENGTH_MAX.
        // 2) Select the hash of the correct byte length.
        // 3) Return the correct hash.

        // Hash each of the validators into a leaf hash.
        let mut validators_leaf_hashes = Vec::new();
        for i in 0..VALIDATOR_SET_SIZE_MAX {
            validators_leaf_hashes
                .push(self.hash_validator_leaf(&validators[i], validator_byte_lengths[i]))
        }
        validators_leaf_hashes
    }

    fn hash_validator_set<const VALIDATOR_SET_SIZE_MAX: usize>(
        &mut self,
        validators: &Vec<MarshalledValidatorVariable>,
        validator_byte_lengths: &Vec<Variable>,
        validator_enabled: &Vec<BoolVariable>,
    ) -> TendermintHashVariable {
        assert_eq!(validators.len(), VALIDATOR_SET_SIZE_MAX);
        assert_eq!(validator_byte_lengths.len(), VALIDATOR_SET_SIZE_MAX);
        assert_eq!(validator_enabled.len(), VALIDATOR_SET_SIZE_MAX);

        // Hash each of the validators to get their corresponding leaf hash.
        let mut current_validator_hashes = self
            .hash_validator_leaves::<VALIDATOR_SET_SIZE_MAX>(validators, validator_byte_lengths);

        // Whether to treat the validator as empty.
        let mut current_validator_enabled = validator_enabled.clone();

        let mut merkle_layer_size = VALIDATOR_SET_SIZE_MAX;
        // Hash each layer of nodes to get the root according to the Tendermint spec, starting from the leaves.
        while merkle_layer_size > 1 {
            (current_validator_hashes, current_validator_enabled) = self.hash_merkle_layer(
                current_validator_hashes,
                current_validator_enabled,
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
    use plonky2x::frontend::ecc::ed25519::curve::curve_types::AffinePoint;
    use plonky2x::prelude::DefaultBuilder;
    use subtle_encoding::hex;

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

        // Define the circuit
        let mut builder = DefaultBuilder::new();
        let voting_power_variable = builder.read::<U64Variable>();
        let result = builder.marshal_int64_varint(&voting_power_variable);
        for i in 0..9 {
            builder.write(result[i]);
        }
        let circuit = builder.build();

        for test_case in test_cases {
            let mut input = circuit.input();
            input.write::<U64Variable>((test_case.0 as u64).into());
            let (proof, mut output) = circuit.prove(&input);

            let expected_bytes = test_case.1;

            println!("Voting Power: {:?}", test_case.0);
            println!("Expected Varint Encoding (Bytes): {:?}", expected_bytes);

            for byte in expected_bytes {
                let output_byte = output.read::<ByteVariable>();
                assert_eq!(output_byte, byte);
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

        // Define the circuit
        let mut builder = DefaultBuilder::new();
        let voting_power_variable = builder.read::<U64Variable>();
        let pub_key = builder.read::<AffinePointTarget<Curve>>();
        let result = builder.marshal_tendermint_validator(&pub_key, &voting_power_variable);
        builder.write(result);
        let circuit = builder.build();

        let mut input = circuit.input();
        input.write::<U64Variable>((voting_power_i64 as u64).into());
        let pub_key_uncompressed: AffinePoint<Curve> =
            AffinePoint::new_from_compressed_point(&hex::decode(pubkey).unwrap());
        input.write::<AffinePointTarget<Curve>>(pub_key_uncompressed);
        let (proof, mut output) = circuit.prove(&input);
        let output_bytes = output.read::<BytesVariable<VALIDATOR_BYTE_LENGTH_MAX>>();

        let pub_key = pub_key_uncompressed.compress_point();
        // Convert pub_key to bytes from biguint
        let pub_key_bytes = pub_key.to_bytes_le();
        for i in 0..46 {
            assert_eq!(output_bytes[i], pub_key_bytes[i]);
        }
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
