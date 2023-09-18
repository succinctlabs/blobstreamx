use crate::utils::TendermintHashVariable;
use crate::utils::{
    MarshalledValidatorVariable, VALIDATOR_BYTE_LENGTH_MAX, VOTING_POWER_BYTES_LENGTH_MAX,
};
use plonky2x::frontend::ecc::ed25519::curve::curve_types::Curve;
use plonky2x::frontend::ecc::ed25519::curve::ed25519::Ed25519;
use plonky2x::frontend::ecc::ed25519::gadgets::curve::{AffinePointTarget, CircuitBuilderCurve};
use plonky2x::frontend::uint::uint64::U64Variable;
use plonky2x::frontend::vars::U32Variable;
use plonky2x::prelude::Field;

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
    /// The protobuf encoding of a Tendermint validator is a deterministic function of the validator's
    /// public key (32 bytes) and voting power (int64). The encoding is as follows in bytes:
    /// 10 34 10 32 <pubkey> 16 <varint>
    /// The `pubkey` is encoded as the raw list of bytes used in the public key. The `varint` is
    /// encoded using protobuf's default integer encoding, which consist of 7 bit payloads. You can
    /// read more about them here: https://protobuf.dev/programming-guides/encoding/#varints.  
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
        validator_enabled: Vec<BoolVariable>,
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
            // Ok to cast as BoolVariable since is_zero_septets[i] is 0 or 1 so result is either 0 or 1
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

            // Reverse the buffer to BE since ByteVariable interprets variables as BE
            buffer.reverse();

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

        let compressed_point = self.api.compress_point(pubkey);

        // TODO: in the future compressed_point should probably return a Bytes32Variable
        // We iterate in reverse order because the marshalling expects little-endian
        // and the bytes are returned as big-endian.
        for i in (0..32).rev() {
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
        let input_byte_length = U32Variable(enc_validator_byte_length);

        let zero = self.zero::<U32Variable>();
        prepended_validator_bytes.resize(64, self.zero::<ByteVariable>());

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
        validator_enabled: Vec<BoolVariable>,
    ) -> TendermintHashVariable {
        assert_eq!(validators.len(), VALIDATOR_SET_SIZE_MAX);
        assert_eq!(validator_byte_lengths.len(), VALIDATOR_SET_SIZE_MAX);
        assert_eq!(validator_enabled.len(), VALIDATOR_SET_SIZE_MAX);

        // Hash each of the validators to get their corresponding leaf hash.
        let current_validator_hashes = self
            .hash_validator_leaves::<VALIDATOR_SET_SIZE_MAX>(validators, validator_byte_lengths);

        let computed_root = self.get_root_from_hashed_leaves::<VALIDATOR_SET_SIZE_MAX>(
            current_validator_hashes,
            validator_enabled,
        );

        // Return the root hash.
        computed_root
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::env;

    use super::*;
    use crate::inputs::{convert_to_h256, get_path_indices, get_signed_block_from_fixture};
    use crate::utils::{
        generate_proofs_from_header, hash_all_leaves, proofs_from_byte_slices, HEADER_PROOF_DEPTH,
        PROTOBUF_BLOCK_ID_SIZE_BYTES,
    };
    use crate::validator::TendermintValidator;
    use ethers::types::H256;
    use ethers::utils::hex;
    use itertools::Itertools;
    use plonky2::field::types::PrimeField;
    use plonky2x::frontend::ecc::ed25519::curve::curve_types::AffinePoint;
    use plonky2x::frontend::merkle::tree::{InclusionProof, MerkleInclusionProofVariable};
    use plonky2x::prelude::{ArrayVariable, Bytes32Variable, DefaultBuilder, GoldilocksField};
    use sha2::Sha256;
    use tendermint_proto::types::BlockId as RawBlockId;
    use tendermint_proto::Protobuf;

    type Curve = Ed25519;

    #[test]
    fn test_marshal_int64_varint() {
        env_logger::try_init().unwrap();
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
            let (_, mut output) = circuit.prove(&input);

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
        // env::set_var("RUST_LOG", "debug");
        env_logger::try_init().unwrap_or_default();

        // This is a test cases generated from a validator in block 11000 of the mocha-3 testnet.
        let voting_power_i64 = 100010 as i64;
        let pubkey = "de25aec935b10f657b43fa97e5a8d4e523bdb0f9972605f0b064eff7b17048ba";
        let expected_marshal = hex::decode(
            "0a220a20de25aec935b10f657b43fa97e5a8d4e523bdb0f9972605f0b064eff7b17048ba10aa8d06",
        )
        .unwrap();

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
        let (_, mut output) = circuit.prove(&input);
        let output_bytes = output.read::<BytesVariable<VALIDATOR_BYTE_LENGTH_MAX>>();

        // Debug print output
        println!("pub_key_uncompressed: {:?}", pub_key_uncompressed);
        println!(
            "pub_key.x: {:?}",
            pub_key_uncompressed
                .x
                .to_canonical_biguint()
                .to_u32_digits()
        );
        println!(
            "pub_key.y: {:?}",
            pub_key_uncompressed
                .y
                .to_canonical_biguint()
                .to_u32_digits()
        );
        let pub_key = pub_key_uncompressed.compress_point();
        println!("pub_key_compressed: {:?}", pub_key.to_u32_digits());
        let pub_key_bytes = pub_key.to_bytes_le();
        println!("pub_key_bytes: {:?}", pub_key_bytes);

        for i in 0..46 {
            let expected_value = *expected_marshal.get(i).unwrap_or(&0);
            assert_eq!(output_bytes[i], expected_value);
        }
    }

    #[test]
    fn test_hash_validator_leaves() {
        const VALIDATOR_SET_SIZE_MAX: usize = 4;

        env::set_var("RUST_LOG", "debug");
        env_logger::try_init().unwrap_or_default();

        // Define the circuit
        let mut builder = DefaultBuilder::new();
        let messages =
            builder.read::<ArrayVariable<MarshalledValidatorVariable, VALIDATOR_SET_SIZE_MAX>>();
        let val_byte_lengths = builder.read::<ArrayVariable<Variable, VALIDATOR_SET_SIZE_MAX>>();
        let hashed_leaves = builder.hash_validator_leaves::<VALIDATOR_SET_SIZE_MAX>(
            &messages.as_vec(),
            &val_byte_lengths.as_vec(),
        );
        let hashed_leaves: ArrayVariable<TendermintHashVariable, VALIDATOR_SET_SIZE_MAX> =
            hashed_leaves.into();
        builder.write(hashed_leaves);
        let circuit = builder.build();

        let validators: Vec<&str> = vec!["6694200ba0e084f7184255abedc39af04463a4ff11e0e0c1326b1b82ea1de50c6b35cf6efa8f7ed3", "739d312e54353379a852b43de497ca4ec52bb49f59b7294a4d6cf19dd648e16cb530b7a7a1e35875d4ab4d90", "4277f2f871f3e041bcd4643c0cf18e5a931c2bfe121ce8983329a289a2b0d2161745a2ddf99bade9a1", "4277f2f871f3e041bcd4643c0cf18e5a931c2bfe121ce8983329a289a2b0d2161745a2ddf99bade9a1"];
        let validators_bytes = validators
            .iter()
            .map(|x| hex::decode(x).unwrap())
            .collect::<Vec<_>>();

        let validator_byte_lengths = validators_bytes
            .iter()
            .map(|x| GoldilocksField::from_canonical_usize(x.len()))
            .collect::<Vec<_>>();

        let expected_digests_bytes = hash_all_leaves::<Sha256>(&validators_bytes);
        let expected_digests_bytes = expected_digests_bytes
            .iter()
            .map(|x| H256::from_slice(x))
            .collect::<Vec<_>>();

        // Pad validator bytes to VALIDATOR_BYTE_LENGTH_MAX
        let padded_validators_bytes: Vec<[u8; VALIDATOR_BYTE_LENGTH_MAX]> = validators_bytes
            .iter()
            .map(|x| {
                let mut validator_bytes = x.clone();
                validator_bytes.resize(VALIDATOR_BYTE_LENGTH_MAX, 0u8);
                validator_bytes.try_into().unwrap()
            })
            .collect::<Vec<_>>();

        let mut input = circuit.input();
        input.write::<ArrayVariable<MarshalledValidatorVariable, VALIDATOR_SET_SIZE_MAX>>(
            padded_validators_bytes,
        );
        input.write::<ArrayVariable<Variable, VALIDATOR_SET_SIZE_MAX>>(validator_byte_lengths);
        let (_, mut output) = circuit.prove(&input);
        let output_leaves = output.read::<ArrayVariable<Bytes32Variable, VALIDATOR_SET_SIZE_MAX>>();

        assert_eq!(output_leaves, expected_digests_bytes);
    }

    #[test]
    fn test_generate_validators_hash() {
        const VALIDATOR_SET_SIZE_MAX: usize = 4;

        env::set_var("RUST_LOG", "debug");
        env_logger::try_init().unwrap_or_default();

        // Define the circuit
        let mut builder = DefaultBuilder::new();
        let messages =
            builder.read::<ArrayVariable<MarshalledValidatorVariable, VALIDATOR_SET_SIZE_MAX>>();
        let val_byte_lengths = builder.read::<ArrayVariable<Variable, VALIDATOR_SET_SIZE_MAX>>();
        let val_enabled = builder.read::<ArrayVariable<BoolVariable, VALIDATOR_SET_SIZE_MAX>>();

        let root = builder.hash_validator_set::<VALIDATOR_SET_SIZE_MAX>(
            &messages.as_vec(),
            &val_byte_lengths.as_vec(),
            val_enabled.as_vec(),
        );
        builder.write(root);
        let circuit = builder.build();

        let validators_arr: Vec<Vec<&str>> = vec![vec![
            "0a220a20de25aec935b10f657b43fa97e5a8d4e523bdb0f9972605f0b064eff7b17048ba10aa8d06",
            "0a220a208de6ad1a569a223e7bb0dade194abb9487221210e1fa8154bf654a10fe6158a610aa8d06",
            "0a220a20e9b7638ca1c42da37d728970632fda77ec61dcc520395ab5d3a645b9c2b8e8b1100a",
            "0a220a20bd60452e7f056b22248105e7fd298961371da0d9332ef65fa81691bf51b2e5051001",
        ], vec!["364db94241a02b701d0dc85ac016fab2366fba326178e6f11d8294931969072b7441fd6b0ff5129d6867", "6fa0cef8f328eb8e2aef2084599662b1ee0595d842058966166029e96bd263e5367185f19af67b099645ec08aa", "0a220a20bd60452e7f056b22248105e7fd298961371da0d9332ef65fa81691bf51b2e5051001", "0a220a20bd60452e7f056b22248105e7fd298961371da0d9332ef65fa81691bf51b2e5051001"]];

        let validators: Vec<Vec<Vec<u8>>> = validators_arr
            .iter()
            .map(|x| {
                x.iter()
                    .map(|y| {
                        hex::decode(y).unwrap()
                        // val_bytes.resize(VALIDATOR_BYTE_LENGTH_MAX, 0u8);
                        // val_bytes.try_into().unwrap()
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let validators_byte_lengths = validators
            .iter()
            .map(|x| {
                x.iter()
                    .map(|y| GoldilocksField::from_canonical_usize(y.len()))
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let validators_enabled = vec![vec![true, true, true, true], vec![true, true, true, true]];

        let roots: Vec<H256> = validators
            .iter()
            .map(|batch| H256::from(proofs_from_byte_slices(batch.to_vec()).0))
            .collect::<Vec<_>>();

        // TODO: Due to issues with Curta serialization across multiple runOnce calls: https://github.com/succinctlabs/curta/issues/78, we can only call
        // runOnce once per test. Thus, we need to build a new circuit for each batch of validators.
        let mut input = circuit.input();
        input.write::<ArrayVariable<MarshalledValidatorVariable, VALIDATOR_SET_SIZE_MAX>>(
            validators[0]
                .iter()
                .map(|x| {
                    let mut validator_bytes = x.clone();
                    validator_bytes.resize(VALIDATOR_BYTE_LENGTH_MAX, 0u8);
                    let arr: [u8; VALIDATOR_BYTE_LENGTH_MAX] = validator_bytes.try_into().unwrap();
                    arr
                })
                .collect_vec(),
        );
        input.write::<ArrayVariable<Variable, VALIDATOR_SET_SIZE_MAX>>(
            validators_byte_lengths[0].clone(),
        );
        input.write::<ArrayVariable<BoolVariable, VALIDATOR_SET_SIZE_MAX>>(
            validators_enabled[0].clone(),
        );
        let (_, mut output) = circuit.prove(&input);
        let computed_root = output.read::<Bytes32Variable>();
        assert_eq!(roots[0], computed_root);
    }

    #[test]
    fn test_get_root_from_merkle_proof() {
        env_logger::try_init().unwrap_or_default();

        // Define the circuit
        let mut builder = DefaultBuilder::new();
        let proof = builder
            .read::<MerkleInclusionProofVariable<HEADER_PROOF_DEPTH, PROTOBUF_BLOCK_ID_SIZE_BYTES>>(
            );
        let root = builder.get_root_from_merkle_proof(&proof);
        builder.write(root);
        let circuit = builder.build();

        // Generate test cases from Celestia block:
        let block = get_signed_block_from_fixture(10000);

        let (root, proofs) = generate_proofs_from_header(&block.header);

        // Can test with leaf_index 4, 6, 7 or 8 (last_block_id_hash, data_hash, validators_hash, next_validators_hash)
        // TODO: Once Curta runOnce is fixed, we can test all leaf indices in separate test cases
        let leaf_index = 4;

        // Note: Must convert to protobuf encoding (get_proofs_from_header is a good reference)
        let leaf =
            Protobuf::<RawBlockId>::encode_vec(block.header.last_block_id.unwrap_or_default());

        let path_indices = get_path_indices(leaf_index as u64, proofs[0].total);

        let proof = InclusionProof {
            aunts: convert_to_h256(proofs[leaf_index].clone().aunts),
            path_indices: path_indices,
            leaf: leaf.try_into().unwrap(),
        };

        let mut input = circuit.input();
        input.write::<MerkleInclusionProofVariable<HEADER_PROOF_DEPTH, PROTOBUF_BLOCK_ID_SIZE_BYTES>>(
            proof,
        );
        let (_, mut output) = circuit.prove(&input);
        let computed_root = output.read::<Bytes32Variable>();

        assert_eq!(H256::from(root), computed_root);
    }
}
