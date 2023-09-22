//! This file containts methods used for dealing with Tendermint validators within a circuit.

use plonky2x::frontend::ecc::ed25519::curve::curve_types::Curve;
use plonky2x::frontend::ecc::ed25519::curve::ed25519::Ed25519;
use plonky2x::frontend::ecc::ed25519::gadgets::curve::{AffinePointTarget, CircuitBuilderCurve};
use plonky2x::frontend::uint::uint64::U64Variable;
use plonky2x::frontend::vars::U32Variable;
use plonky2x::prelude::{
    BoolVariable, ByteVariable, BytesVariable, CircuitBuilder, CircuitVariable, PlonkParameters,
    Variable,
};

use crate::circuits::{
    MarshalledValidatorVariable, TendermintHashVariable, TendermintHeaderBuilder,
};
use crate::constants::VALIDATOR_BYTE_LENGTH_MAX;

pub trait TendermintValidatorBuilder<L: PlonkParameters<D>, const D: usize> {
    type Curve: Curve;

    /// Serializes the validator public key and voting power to bytes.
    fn marshal_tendermint_validator(
        &mut self,
        pubkey: &AffinePointTarget<Self::Curve>,
        voting_power: &U64Variable,
    ) -> MarshalledValidatorVariable;

    /// Hashes validator bytes to get the leaf according to the Tendermint spec:
    ///
    ///     (0x00 || validatorBytes)
    ///
    /// Note: This function differs from `leaf_hash_stark` because the validator length is variable.
    fn hash_validator_leaf(
        &mut self,
        validator: &MarshalledValidatorVariable,
        validator_byte_length: Variable,
    ) -> TendermintHashVariable;

    /// Hashes multiple validators to get their leaves according to the Tendermint spec using
    /// `hash_validator_leaf`.
    fn hash_validator_leaves<const VALIDATOR_SET_SIZE_MAX: usize>(
        &mut self,
        validators: &[MarshalledValidatorVariable],
        validator_byte_lengths: &[Variable],
    ) -> Vec<TendermintHashVariable>;

    /// Compute the expected validator hash from the validator set.
    fn hash_validator_set<const VALIDATOR_SET_SIZE_MAX: usize>(
        &mut self,
        validators: &[MarshalledValidatorVariable],
        validator_byte_lengths: &[Variable],
        validator_enabled: Vec<BoolVariable>,
    ) -> TendermintHashVariable;
}

impl<L: PlonkParameters<D>, const D: usize> TendermintValidatorBuilder<L, D>
    for CircuitBuilder<L, D>
{
    type Curve = Ed25519;

    fn marshal_tendermint_validator(
        &mut self,
        pubkey: &AffinePointTarget<Self::Curve>,
        voting_power: &U64Variable,
    ) -> MarshalledValidatorVariable {
        let mut res = self
            .constant::<BytesVariable<4>>([10u8, 34u8, 10u8, 32u8])
            .0
            .to_vec();

        let compressed_point = self.api.compress_point(pubkey);

        // TODO: in the future compressed_point should probably return a Bytes32Variable. We iterate
        // in reverse order because the marshalling expects little-endian and the bytes are returned
        // as big-endian.
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
        // instead of a U32Variable.
        let input_byte_length = U32Variable(enc_validator_byte_length);

        let zero = self.zero::<U32Variable>();
        prepended_validator_bytes.resize(64, self.zero::<ByteVariable>());

        // VALIDATOR_BYTE_LENGTH_MAX = 46 so we only need 1 chunk.
        self.curta_sha256_variable::<1>(&prepended_validator_bytes, zero, input_byte_length)
    }

    fn hash_validator_leaves<const VALIDATOR_SET_SIZE_MAX: usize>(
        &mut self,
        validators: &[MarshalledValidatorVariable],
        validator_byte_lengths: &[Variable],
    ) -> Vec<TendermintHashVariable> {
        assert_eq!(validators.len(), VALIDATOR_SET_SIZE_MAX);
        assert_eq!(validator_byte_lengths.len(), VALIDATOR_SET_SIZE_MAX);

        // Hash each of the validators to get their corresponding leaf hash.
        let mut validators_leaf_hashes = Vec::new();
        for i in 0..VALIDATOR_SET_SIZE_MAX {
            validators_leaf_hashes
                .push(self.hash_validator_leaf(&validators[i], validator_byte_lengths[i]))
        }
        validators_leaf_hashes
    }

    fn hash_validator_set<const VALIDATOR_SET_SIZE_MAX: usize>(
        &mut self,
        validators: &[MarshalledValidatorVariable],
        validator_byte_lengths: &[Variable],
        validator_enabled: Vec<BoolVariable>,
    ) -> TendermintHashVariable {
        assert_eq!(validators.len(), VALIDATOR_SET_SIZE_MAX);
        assert_eq!(validator_byte_lengths.len(), VALIDATOR_SET_SIZE_MAX);
        assert_eq!(validator_enabled.len(), VALIDATOR_SET_SIZE_MAX);

        // Hash each of the validators to get their corresponding leaf hash.
        let current_validator_hashes = self
            .hash_validator_leaves::<VALIDATOR_SET_SIZE_MAX>(validators, validator_byte_lengths);

        // Return the root hash.
        self.get_root_from_hashed_leaves::<VALIDATOR_SET_SIZE_MAX>(
            current_validator_hashes,
            validator_enabled,
        )
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use ethers::types::H256;
    use ethers::utils::hex;
    use itertools::Itertools;
    use plonky2::field::types::PrimeField;
    use plonky2x::frontend::ecc::ed25519::curve::curve_types::AffinePoint;
    use plonky2x::frontend::merkle::tree::{InclusionProof, MerkleInclusionProofVariable};
    use plonky2x::prelude::{
        ArrayVariable, Bytes32Variable, DefaultBuilder, Field, GoldilocksField,
    };
    use sha2::Sha256;
    use tendermint_proto::types::BlockId as RawBlockId;
    use tendermint_proto::Protobuf;

    use super::*;
    use crate::circuits::TendermintValidatorBuilder;
    use crate::constants::{HEADER_PROOF_DEPTH, PROTOBUF_BLOCK_ID_SIZE_BYTES};
    use crate::input_data::tendermint_utils::{
        generate_proofs_from_header, hash_all_leaves, proofs_from_byte_slices,
    };
    use crate::input_data::utils::{convert_to_h256, get_path_indices};
    // TODO: Remove dependency on inputs.
    use crate::inputs::get_signed_block_from_fixture;

    type Curve = Ed25519;

    #[test]
    fn test_marshal_tendermint_validator() {
        env_logger::try_init().unwrap_or_default();

        // This is a test cases generated from a validator in block 11000 of the mocha-3 testnet.
        let voting_power_i64 = 100010_i64;
        let pubkey = "de25aec935b10f657b43fa97e5a8d4e523bdb0f9972605f0b064eff7b17048ba";
        let expected_marshal = hex::decode(
            "0a220a20de25aec935b10f657b43fa97e5a8d4e523bdb0f9972605f0b064eff7b17048ba10aa8d06",
        )
        .unwrap();

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

        for i in 0..VALIDATOR_BYTE_LENGTH_MAX {
            let expected_value = *expected_marshal.get(i).unwrap_or(&0);
            assert_eq!(output_bytes[i], expected_value);
        }
    }

    #[test]
    #[cfg_attr(feature = "ci", ignore)]
    fn test_hash_validator_leaves() {
        const VALIDATOR_SET_SIZE_MAX: usize = 4;
        env_logger::try_init().unwrap_or_default();

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

        let validators: Vec<&str> = vec![
            "6694200ba0e084f7184255abedc39af04463a4ff11e0e0c1326b1b82ea1de50c6b35cf6efa8f7ed3", 
            "739d312e54353379a852b43de497ca4ec52bb49f59b7294a4d6cf19dd648e16cb530b7a7a1e35875d4ab4d90", 
            "4277f2f871f3e041bcd4643c0cf18e5a931c2bfe121ce8983329a289a2b0d2161745a2ddf99bade9a1", 
            "4277f2f871f3e041bcd4643c0cf18e5a931c2bfe121ce8983329a289a2b0d2161745a2ddf99bade9a1"
        ];
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
    #[cfg_attr(feature = "ci", ignore)]
    fn test_generate_validators_hash() {
        const VALIDATOR_SET_SIZE_MAX: usize = 4;
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
                    .map(|y| hex::decode(y).unwrap())
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

        // Compute the expected hash_validator_set roots.
        let expected_roots: Vec<H256> = validators
            .iter()
            .map(|batch| H256::from(proofs_from_byte_slices(batch.to_vec()).0))
            .collect::<Vec<_>>();

        // TODO: Due to issues with Curta serialization across multiple runOnce calls: https://github.com/succinctlabs/curta/issues/78, we can only call
        // runOnce once per test. Thus, to run multiple test cases, we need to build the circuit each time.
        let mut input = circuit.input();
        input.write::<ArrayVariable<MarshalledValidatorVariable, VALIDATOR_SET_SIZE_MAX>>(
            validators[0]
                .iter()
                .map(|x| {
                    // Resize the input bytes to VALIDATOR_BYTE_LENGTH_MAX.
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
        assert_eq!(expected_roots[0], computed_root);
    }

    #[test]
    #[cfg_attr(feature = "ci", ignore)]
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
            path_indices,
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
