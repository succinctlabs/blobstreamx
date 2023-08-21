//! The protobuf encoding of a Tendermint validator is a deterministic function of the validator's
//! public key (32 bytes) and voting power (int64). The encoding is as follows in bytes:
//
//!     10 34 10 32 <pubkey> 16 <varint>
//
//! The `pubkey` is encoded as the raw list of bytes used in the public key. The `varint` is
//! encoded using protobuf's default integer encoding, which consist of 7 bit payloads. You can
//! read more about them here: https://protobuf.dev/programming-guides/encoding/#varints.
use plonky2::field::extension::Extendable;
use plonky2::iop::target::BoolTarget;
use plonky2::iop::target::Target;
use plonky2::{hash::hash_types::RichField, plonk::circuit_builder::CircuitBuilder};
use plonky2x::ecc::ed25519::curve::curve_types::Curve;
use plonky2x::ecc::ed25519::curve::ed25519::Ed25519;
use plonky2x::ecc::ed25519::gadgets::curve::{AffinePointTarget, CircuitBuilderCurve};
use plonky2x::hash::sha::sha256::{sha256, sha256_variable_length_single_chunk};
use plonky2x::num::u32::gadgets::arithmetic_u32::CircuitBuilderU32;

use crate::utils::{
    EncTendermintHashTarget, I64Target, MarshalledValidatorTarget, TendermintHashTarget,
    HASH_SIZE_BITS, PROTOBUF_HASH_SIZE_BITS, VALIDATOR_BIT_LENGTH_MAX, VALIDATOR_BYTE_LENGTH_MAX,
    VALIDATOR_SET_SIZE_MAX, VOTING_POWER_BITS_LENGTH_MAX, VOTING_POWER_BYTES_LENGTH_MAX,
};

pub trait TendermintMarshaller<F: RichField + Extendable<D>, const D: usize> {
    type Curve: Curve;

    /// Serializes an int64 as a protobuf varint.
    fn marshal_int64_varint(
        &mut self,
        num: &I64Target,
    ) -> [BoolTarget; VOTING_POWER_BITS_LENGTH_MAX];

    /// Serializes the validator public key and voting power to bytes.
    fn marshal_tendermint_validator(
        &mut self,
        pubkey: &AffinePointTarget<Self::Curve>,
        voting_power: &I64Target,
    ) -> MarshalledValidatorTarget;

    /// Verify a merkle proof against the specified root hash.
    /// Note: This function will only work for leaves with a length of 34 bytes (protobuf-encoded SHA256 hash)
    /// Output is the merkle root
    fn get_root_from_merkle_proof(
        &mut self,
        aunts: &Vec<TendermintHashTarget>,
        merkle_proof_enabled: &Vec<BoolTarget>,
        leaf: &EncTendermintHashTarget,
    ) -> TendermintHashTarget;

    /// Hashes leaf bytes to get the leaf hash according to the Tendermint spec. (0x00 || leafBytes)
    /// Note: This function will only work for leaves with a length of 34 bytes (protobuf-encoded SHA256 hash)
    fn hash_header_leaf(&mut self, leaf: &EncTendermintHashTarget) -> TendermintHashTarget;

    /// Hashes validator bytes to get the leaf according to the Tendermint spec. (0x00 || validatorBytes)
    fn hash_validator_leaf(
        &mut self,
        validator: &MarshalledValidatorTarget,
        validator_byte_length: Target,
    ) -> TendermintHashTarget;

    /// Hashes multiple validators to get their leaves according to the Tendermint spec using hash_validator_leaf.
    fn hash_validator_leaves(
        &mut self,
        validators: &Vec<MarshalledValidatorTarget>,
        validator_byte_lengths: &Vec<Target>,
    ) -> Vec<TendermintHashTarget>;

    /// Hashes two nodes to get the inner node according to the Tendermint spec. (0x01 || left || right)
    fn inner_hash(
        &mut self,
        left: &TendermintHashTarget,
        right: &TendermintHashTarget,
    ) -> TendermintHashTarget;

    /// Hashes a layer of the Merkle tree according to the Tendermint spec. (0x01 || left || right)
    /// If in a pair the right node is not enabled (empty), then the left node is passed up to the next layer.
    /// If neither the left nor right node in a pair is enabled (empty), then the parent node is set to not enabled (empty).
    fn hash_merkle_layer(
        &mut self,
        merkle_hashes: &mut Vec<TendermintHashTarget>,
        merkle_hash_enabled: &mut Vec<BoolTarget>,
        num_hashes: usize,
    ) -> (Vec<TendermintHashTarget>, Vec<BoolTarget>);

    /// Compute the expected validator hash from the validator set.
    fn hash_validator_set(
        &mut self,
        validators: &Vec<MarshalledValidatorTarget>,
        validator_byte_lengths: &Vec<Target>,
        validator_enabled: &Vec<BoolTarget>,
    ) -> TendermintHashTarget;
}

impl<F: RichField + Extendable<D>, const D: usize> TendermintMarshaller<F, D>
    for CircuitBuilder<F, D>
{
    type Curve = Ed25519;

    fn get_root_from_merkle_proof(
        &mut self,
        aunts: &Vec<TendermintHashTarget>,
        // TODO: Should we hard-code path_indices to correspond to dataHash, validatorsHash and nextValidatorsHash?
        path_indices: &Vec<BoolTarget>,
        leaf: &EncTendermintHashTarget,
    ) -> TendermintHashTarget {
        let hash_leaf = self.hash_header_leaf(&leaf);

        let mut hash_so_far = hash_leaf;
        for i in 0..aunts.len() {
            let aunt = aunts[i];
            let path_index = path_indices[i];
            let left_hash_pair = self.inner_hash(&hash_so_far, &aunt);
            let right_hash_pair = self.inner_hash(&aunt, &hash_so_far);

            let mut hash_pair = [self._false(); HASH_SIZE_BITS];
            for j in 0..HASH_SIZE_BITS {
                // If the path index is 0, then the right hash is the aunt.
                hash_pair[j] = BoolTarget::new_unsafe(self.select(
                    path_index,
                    right_hash_pair.0[j].target,
                    left_hash_pair.0[j].target,
                ));
            }
            hash_so_far = TendermintHashTarget(hash_pair);
        }
        hash_so_far
    }

    fn hash_header_leaf(&mut self, leaf: &EncTendermintHashTarget) -> TendermintHashTarget {
        // Calculate the length of the message for the leaf hash.
        // 0x00 || leafBytes
        let bits_length = 8 + (PROTOBUF_HASH_SIZE_BITS);

        // Calculate the message for the leaf hash.
        let mut leaf_msg_bits = vec![self._false(); bits_length];

        // 0x00
        for k in 0..8 {
            leaf_msg_bits[k] = self._false();
        }

        // validatorBytes
        for k in 8..bits_length {
            leaf_msg_bits[k] = leaf.0[k - 8];
        }

        // Load the output of the hash.
        let hash = sha256(self, &leaf_msg_bits);
        let mut return_hash = [self._false(); HASH_SIZE_BITS];
        for k in 0..HASH_SIZE_BITS {
            return_hash[k] = hash[k];
        }
        TendermintHashTarget(return_hash)
    }

    fn marshal_int64_varint(
        &mut self,
        voting_power: &I64Target,
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
        voting_power: &I64Target,
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

        // Add one to account for the 0x00 byte.
        let enc_validator_byte_length = self.add(one, validator_byte_length);
        // Multiply by 8 to get the bit length.
        let enc_validator_bit_length = self.mul(enc_validator_byte_length, eight);

        // Encode leaf 0x00 || validator_bits
        let mut enc_validator_bits = [self._false(); VALIDATOR_BIT_LENGTH_MAX + 8];
        for i in 0..VALIDATOR_BIT_LENGTH_MAX {
            enc_validator_bits[i + 8] = validator.0[i];
        }
        let hash = sha256_variable_length_single_chunk(
            self,
            &enc_validator_bits,
            enc_validator_bit_length,
        );

        TendermintHashTarget(hash.try_into().unwrap())
    }

    fn hash_validator_leaves(
        &mut self,
        validators: &Vec<MarshalledValidatorTarget>,
        validator_byte_lengths: &Vec<Target>,
    ) -> Vec<TendermintHashTarget> {
        let num_validators = self.constant(F::from_canonical_usize(validators.len()));
        let num_validator_byte_lengths =
            self.constant(F::from_canonical_usize(validator_byte_lengths.len()));
        let validator_set_size_max = self.constant(F::from_canonical_usize(VALIDATOR_SET_SIZE_MAX));

        // Assert validators length is VALIDATOR_SET_SIZE_MAX
        self.connect(num_validators, validator_set_size_max);

        // Assert validator_byte_length length is VALIDATOR_SET_SIZE_MAX
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
                self.hash_validator_leaf(&validators[i], validator_byte_lengths[i]);
        }

        validators_leaf_hashes.to_vec()
    }

    fn inner_hash(
        &mut self,
        left: &TendermintHashTarget,
        right: &TendermintHashTarget,
    ) -> TendermintHashTarget {
        // Calculate the length of the message for the inner hash.
        // 0x01 || left || right
        let bits_length = 8 + (HASH_SIZE_BITS * 2);

        // Calculate the message for the inner hash.
        let mut message_bits = vec![self._false(); bits_length];

        // 0x01
        for k in 0..7 {
            message_bits[k] = self._false();
        }
        message_bits[7] = self._true();

        // left
        for k in 8..8 + HASH_SIZE_BITS {
            message_bits[k] = left.0[k - 8];
        }

        // right
        for k in 8 + HASH_SIZE_BITS..bits_length {
            message_bits[k] = right.0[k - (8 + HASH_SIZE_BITS)];
        }

        // Load the output of the hash.
        // Note: Calculate the inner hash as if both validators are enabled.
        let inner_hash = sha256(self, &message_bits);
        let mut ret_inner_hash = [self._false(); HASH_SIZE_BITS];
        for k in 0..HASH_SIZE_BITS {
            ret_inner_hash[k] = inner_hash[k];
        }
        TendermintHashTarget(ret_inner_hash)
    }

    fn hash_merkle_layer(
        &mut self,
        merkle_hashes: &mut Vec<TendermintHashTarget>,
        merkle_hash_enabled: &mut Vec<BoolTarget>,
        num_hashes: usize,
    ) -> (Vec<TendermintHashTarget>, Vec<BoolTarget>) {
        let zero = self.zero();
        let one = self.one();

        for i in (0..num_hashes).step_by(2) {
            let both_nodes_enabled = self.and(merkle_hash_enabled[i], merkle_hash_enabled[i + 1]);

            let first_node_disabled = self.not(merkle_hash_enabled[i]);
            let second_node_disabled = self.not(merkle_hash_enabled[i + 1]);
            let both_nodes_disabled = self.and(first_node_disabled, second_node_disabled);

            // Calculuate the inner hash.
            let inner_hash = self.inner_hash(
                &TendermintHashTarget(merkle_hashes[i].0),
                &TendermintHashTarget(merkle_hashes[i + 1].0),
            );

            for k in 0..HASH_SIZE_BITS {
                // If the left node is enabled and the right node is disabled, we pass up the left hash instead of the inner hash.
                merkle_hashes[i / 2].0[k] = BoolTarget::new_unsafe(self.select(
                    both_nodes_enabled,
                    inner_hash.0[k].target,
                    merkle_hashes[i].0[k].target,
                ));
            }

            // Set the inner node one level up to disabled if both nodes are disabled.
            merkle_hash_enabled[i / 2] =
                BoolTarget::new_unsafe(self.select(both_nodes_disabled, zero, one));
        }

        // Return the hashes and enabled nodes for the next layer up.
        (merkle_hashes.to_vec(), merkle_hash_enabled.to_vec())
    }

    fn hash_validator_set(
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
        let mut current_validator_hashes =
            self.hash_validator_leaves(validators, validator_byte_lengths);

        // Whether to treat the validator as empty.
        let mut current_validator_enabled = validator_enabled.clone();

        let mut merkle_layer_size = VALIDATOR_SET_SIZE_MAX;

        // Hash each layer of nodes to get the root according to the Tendermint spec, starting from the leaves.
        while merkle_layer_size > 1 {
            (current_validator_hashes, current_validator_enabled) = self.hash_merkle_layer(
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
    use plonky2::field::types::Field;
    use plonky2::iop::target::BoolTarget;
    use plonky2::{
        iop::witness::{PartialWitness, WitnessWrite},
        plonk::{
            circuit_builder::CircuitBuilder,
            circuit_data::CircuitConfig,
            config::{GenericConfig, PoseidonGoldilocksConfig},
        },
    };
    use subtle_encoding::hex;

    use plonky2x::ecc::ed25519::curve::curve_types::AffinePoint;
    use sha2::Sha256;
    use tendermint_proto::Protobuf;

    use crate::utils::{VALIDATOR_BIT_LENGTH_MAX, VALIDATOR_SET_SIZE_MAX};

    use crate::utils::{generate_proofs_from_header, hash_all_leaves, leaf_hash};

    use plonky2x::num::u32::gadgets::arithmetic_u32::U32Target;

    use crate::{
        utils::{f_bits_to_bytes, to_be_bits},
        validator::{I64Target, TendermintMarshaller},
    };

    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;
    type Curve = Ed25519;
    const D: usize = 2;

    // Generate the inputs from the validator byte arrays.
    fn generate_inputs(
        builder: &mut CircuitBuilder<F, D>,
        validators: &Vec<String>,
    ) -> (Vec<MarshalledValidatorTarget>, Vec<Target>, Vec<BoolTarget>) {
        let mut validator_byte_length: Vec<Target> = Vec::new();

        let mut validator_enabled: Vec<BoolTarget> = vec![builder._false(); VALIDATOR_SET_SIZE_MAX];

        let mut validators_target: Vec<MarshalledValidatorTarget> =
            vec![
                MarshalledValidatorTarget([builder._false(); VALIDATOR_BIT_LENGTH_MAX]);
                VALIDATOR_SET_SIZE_MAX
            ];

        // Convert the hex strings to bytes.
        for i in 0..validators.len() {
            let val_byte_length = validators[i].len() / 2;
            let validator_bits = to_be_bits(hex::decode(&validators[i]).unwrap().to_vec());
            for j in 0..validator_bits.len() {
                validators_target[i].0[j] = builder.constant_bool(validator_bits[j]);
            }
            validator_byte_length.push(builder.constant(F::from_canonical_usize(val_byte_length)));
            validator_enabled[i] = builder._true();
        }

        for _ in validators.len()..VALIDATOR_SET_SIZE_MAX {
            validator_byte_length.push(builder.constant(F::from_canonical_usize(0)));
        }
        return (validators_target, validator_byte_length, validator_enabled);
    }

    #[test]
    fn test_hash_header_leaf() {
        let block = tendermint::Block::from(
            serde_json::from_str::<tendermint::block::Block>(include_str!(
                "./fixtures/celestia_block.json"
            ))
            .unwrap(),
        );

        let encoded_validators_hash_bits = to_be_bits(block.header.validators_hash.encode_vec());
        // Note: Make sure to encode_vec()
        let validators_leaf_hash =
            leaf_hash::<Sha256>(&block.header.validators_hash.encode_vec()).to_vec();

        let validators_hash_bits = to_be_bits(validators_leaf_hash);

        let mut pw = PartialWitness::new();
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let mut validators_hash_bits_target = [builder._false(); PROTOBUF_HASH_SIZE_BITS];
        for i in 0..encoded_validators_hash_bits.len() {
            if encoded_validators_hash_bits[i] {
                validators_hash_bits_target[i] = builder._true();
            }
        }

        let result =
            builder.hash_header_leaf(&EncTendermintHashTarget(validators_hash_bits_target));

        for i in 0..HASH_SIZE_BITS {
            if validators_hash_bits[i] {
                pw.set_target(result.0[i].target, F::ONE);
            } else {
                pw.set_target(result.0[i].target, F::ZERO);
            }
        }

        let data = builder.build::<C>();
        let proof = data.prove(pw).unwrap();

        println!("Created proof");

        data.verify(proof).unwrap();

        println!("Verified proof");
    }

    #[test]
    fn test_get_root_from_merkle_proof() {
        // Generate test cases from Celestia block:
        let block = tendermint::Block::from(
            serde_json::from_str::<tendermint::block::Block>(include_str!(
                "./fixtures/celestia_block.json"
            ))
            .unwrap(),
        );

        let header_hash = block.header.hash().to_string();
        let header_bits = to_be_bits(hex::decode(header_hash.to_lowercase()).unwrap());

        let mut pw = PartialWitness::new();
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let (_, proofs) = generate_proofs_from_header(&block.header);

        // Can test with leaf_index 6, 7 or 8 (data_hash, validators_hash, next_validators_hash)
        let leaf_index = 8;

        // Note: Make sure to encode_vec()
        // let leaf = block.header.data_hash.expect("data hash present").encode_vec();
        // let leaf = block.header.validators_hash.encode_vec();
        let leaf = block.header.next_validators_hash.encode_vec();

        let leaf_bits = to_be_bits(leaf);

        let mut path_indices = vec![];

        let mut current_total = proofs[leaf_index].total as usize;
        let mut current_index = leaf_index as usize;
        while current_total >= 1 {
            path_indices.push(builder.constant_bool(current_index % 2 == 1));
            current_total = current_total / 2;
            current_index = current_index / 2;
        }

        let mut leaf_target = [builder._false(); PROTOBUF_HASH_SIZE_BITS];
        for i in 0..PROTOBUF_HASH_SIZE_BITS {
            leaf_target[i] = if leaf_bits[i] {
                builder._true()
            } else {
                builder._false()
            };
        }

        let mut aunts_target = vec![
            TendermintHashTarget([builder._false(); HASH_SIZE_BITS]);
            proofs[leaf_index].aunts.len()
        ];
        for i in 0..proofs[leaf_index].aunts.len() {
            let bool_vector = to_be_bits(proofs[leaf_index].aunts[i].to_vec());

            for j in 0..HASH_SIZE_BITS {
                aunts_target[i].0[j] = if bool_vector[j] {
                    builder._true()
                } else {
                    builder._false()
                };
            }
        }

        let result = builder.get_root_from_merkle_proof(
            &aunts_target,
            &path_indices,
            &EncTendermintHashTarget(leaf_target),
        );

        for i in 0..HASH_SIZE_BITS {
            if header_bits[i] {
                pw.set_target(result.0[i].target, F::ONE);
            } else {
                pw.set_target(result.0[i].target, F::ZERO);
            }
        }

        let data = builder.build::<C>();
        let proof = data.prove(pw).unwrap();

        println!("Created proof");

        data.verify(proof).unwrap();

        println!("Verified proof");
    }

    #[test]
    fn test_get_leaf_hash() {
        let mut pw = PartialWitness::new();
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        // Computed the leaf hashes corresponding to the first validator bytes. SHA256(0x00 || validatorBytes)
        let expected_digest = "84f633a570a987326947aafd434ae37f151e98d5e6d429137a4cc378d4a7988e";
        let digest_bits = to_be_bits(hex::decode(expected_digest).unwrap());

        let validators: Vec<String> = vec![
            String::from(
                "de6ad0941095ada2a7996e6a888581928203b8b69e07ee254d289f5b9c9caea193c2ab01902d",
            ),
            String::from(
                "92fbe0c52937d80c5ea643c7832620b84bfdf154ec7129b8b471a63a763f2fe955af1ac65fd3",
            ),
            String::from(
                "e902f88b2371ff6243bf4b0ebe8f46205e00749dd4dad07b2ea34350a1f9ceedb7620ab913c2",
            ),
        ];

        let (validators_target, validator_byte_length, _) =
            generate_inputs(&mut builder, &validators);

        let result = builder.hash_validator_leaf(&validators_target[0], validator_byte_length[0]);

        // Set the target bits to the expected digest bits.
        for i in 0..HASH_SIZE_BITS {
            if digest_bits[i] {
                pw.set_target(result.0[i].target, F::ONE);
            } else {
                pw.set_target(result.0[i].target, F::ZERO);
            }
        }

        let data = builder.build::<C>();
        let proof = data.prove(pw).unwrap();

        data.verify(proof).unwrap();

        println!("Verified proof");
    }

    #[test]
    fn test_hash_validator_leaves() {
        let mut pw = PartialWitness::new();
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let validators: Vec<&str> = vec!["6694200ba0e084f7184255abedc39af04463a4ff11e0e0c1326b1b82ea1de50c6b35cf6efa8f7ed3", "739d312e54353379a852b43de497ca4ec52bb49f59b7294a4d6cf19dd648e16cb530b7a7a1e35875d4ab4d90", "4277f2f871f3e041bcd4643c0cf18e5a931c2bfe121ce8983329a289a2b0d2161745a2ddf99bade9a1"];

        let validators = validators
            .iter()
            .map(|x| String::from(*x))
            .collect::<Vec<_>>();

        let validators_bytes: Vec<Vec<u8>> = validators
            .iter()
            .map(|x| hex::decode(x).unwrap())
            .collect::<Vec<_>>();

        let expected_digests_bytes = hash_all_leaves::<Sha256>(&validators_bytes);

        // Convert the expected hashes to hex strings.
        let expected_digests: Vec<String> = expected_digests_bytes
            .iter()
            .map(|x| String::from_utf8(hex::encode(x)).expect("Invalid UTF-8"))
            .collect::<Vec<_>>();

        // Convert the expected hashes bytes to bits.
        let digests_bits: Vec<Vec<bool>> = expected_digests
            .iter()
            .map(|x| to_be_bits(hex::decode(x).unwrap()))
            .collect();

        let (validators_target, validator_byte_length, _) =
            generate_inputs(&mut builder, &validators);

        let result = builder.hash_validator_leaves(&validators_target, &validator_byte_length);
        println!("Got all leaf hashes: {}", result.len());
        for i in 0..validators.len() {
            for j in 0..HASH_SIZE_BITS {
                if digests_bits[i][j] {
                    pw.set_target(result[i].0[j].target, F::ONE);
                } else {
                    pw.set_target(result[i].0[j].target, F::ZERO);
                }
            }
        }

        let data = builder.build::<C>();
        let proof = data.prove(pw).unwrap();

        data.verify(proof).unwrap();

        println!("Verified proof");
    }

    #[test]
    fn test_generate_val_hash() {
        struct TestCase {
            validators: Vec<String>,
            expected_digest: String,
        }

        // Validators from block 11000 on Celestia mocha-3 testnet encoded as bytes.
        let validators_arr: Vec<Vec<&str>> = vec![vec![
            "0a220a20de25aec935b10f657b43fa97e5a8d4e523bdb0f9972605f0b064eff7b17048ba10aa8d06",
            "0a220a208de6ad1a569a223e7bb0dade194abb9487221210e1fa8154bf654a10fe6158a610aa8d06",
            "0a220a20e9b7638ca1c42da37d728970632fda77ec61dcc520395ab5d3a645b9c2b8e8b1100a",
            "0a220a20bd60452e7f056b22248105e7fd298961371da0d9332ef65fa81691bf51b2e5051001",
        ], vec!["364db94241a02b701d0dc85ac016fab2366fba326178e6f11d8294931969072b7441fd6b0ff5129d6867", "6fa0cef8f328eb8e2aef2084599662b1ee0595d842058966166029e96bd263e5367185f19af67b099645ec08aa"]];

        let digest_arr: Vec<&str> = vec![
            "BB5B8B1239565451DCD5AB52B47C26032016CDF1EF2D2115FF104DC9DDE3988C",
            "be110ff9abb6bdeaebf48ac8e179a76fda1f6eaef0150ca6159587f489722204",
        ];

        let test_cases: Vec<TestCase> = validators_arr
            .iter()
            .zip(digest_arr.iter())
            .map(|(validators, expected_digest)| TestCase {
                validators: validators
                    .iter()
                    .map(|x| String::from(*x).to_lowercase())
                    .collect(),
                expected_digest: String::from(*expected_digest).to_lowercase(),
            })
            .collect();

        for test_case in test_cases {
            let mut pw = PartialWitness::new();
            let config = CircuitConfig::standard_recursion_config();
            let mut builder = CircuitBuilder::<F, D>::new(config);

            let (validators_target, validator_byte_length, validator_enabled) =
                generate_inputs(&mut builder, &test_case.validators);

            let digest_bits =
                to_be_bits(hex::decode(test_case.expected_digest.as_bytes()).unwrap());

            println!(
                "Expected Val Hash: {:?}",
                String::from_utf8(hex::encode(
                    hex::decode(test_case.expected_digest.as_bytes()).unwrap()
                ))
            );

            let result = builder.hash_validator_set(
                &validators_target,
                &validator_byte_length,
                &validator_enabled,
            );

            for i in 0..HASH_SIZE_BITS {
                pw.set_bool_target(result.0[i], digest_bits[i]);
            }

            let data = builder.build::<C>();
            let proof = data.prove(pw).unwrap();

            println!("Created proof");

            data.verify(proof).unwrap();

            println!("Verified proof");
        }
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
            let voting_power_lower = voting_power_i64 & ((1 << 32) - 1);
            let voting_power_upper = voting_power_i64 >> 32;

            let voting_power_lower_target =
                U32Target(builder.constant(F::from_canonical_usize(voting_power_lower as usize)));
            let voting_power_upper_target =
                U32Target(builder.constant(F::from_canonical_usize(voting_power_upper as usize)));
            let voting_power_target =
                I64Target([voting_power_lower_target, voting_power_upper_target]);
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

        let voting_power_lower = voting_power_i64 & ((1 << 32) - 1);
        let voting_power_upper = voting_power_i64 >> 32;

        let voting_power_lower_target =
            U32Target(builder.constant(F::from_canonical_usize(voting_power_lower as usize)));
        let voting_power_upper_target =
            U32Target(builder.constant(F::from_canonical_usize(voting_power_upper as usize)));
        let voting_power_target = I64Target([voting_power_lower_target, voting_power_upper_target]);

        let pub_key_uncompressed: AffinePoint<Curve> =
            AffinePoint::new_from_compressed_point(&hex::decode(pubkey).unwrap());

        let pub_key_affine_t = builder.constant_affine_point(pub_key_uncompressed);

        let pub_key = pub_key_uncompressed.compress_point();

        // Convert pub_key to bytes from biguint
        let pub_key_bytes = pub_key.to_bytes_le();

        println!("pub_key: {:?}", pub_key_bytes);
        println!("expected marshal: {:?}", hex::decode(expected_marshal));

        let result = builder.marshal_tendermint_validator(&pub_key_affine_t, &voting_power_target);

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
}
