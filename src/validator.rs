//! The protobuf encoding of a Tendermint validator is a deterministic function of the validator's
//! public key (32 bytes) and voting power (int64). The encoding is as follows in bytes:
//
//!     10 34 10 32 <pubkey> 16 <varint>
//
//! The `pubkey` is encoded as the raw list of bytes used in the public key. The `varint` is
//! encoded using protobuf's default integer encoding, which consist of 7 bit payloads. You can
//! read more about them here: https://protobuf.dev/programming-guides/encoding/#varints.
use plonky2::iop::target::{BoolTarget, Target};
use plonky2::{hash::hash_types::RichField, plonk::circuit_builder::CircuitBuilder};
use plonky2_field::extension::Extendable;

use crate::merkle::{HASH_SIZE, HASH_SIZE_BITS};
use crate::u32::{U32Builder, U32Target};
use crate::sha256::sha256;

/// The maximum length of a protobuf-encoded Tendermint validator in bytes.
const VALIDATOR_BYTE_LENGTH_MAX: usize = 47;

/// The maximum length of a protobuf-encoded Tendermint validator in bits.
const VALIDATOR_BIT_LENGTH_MAX: usize = VALIDATOR_BYTE_LENGTH_MAX * 8;

/// The minimum length of a protobuf-encoded Tendermint validator in bytes.
const VALIDATOR_BYTE_LENGTH_MIN: usize = 38;

/// The minimum length of a protobuf-encoded Tendermint validator in bits.
const VALIDATOR_BIT_LENGTH_MIN: usize = VALIDATOR_BYTE_LENGTH_MIN * 8;

/// The number of possible byte lengths of a protobuf-encoded Tendermint validator.
const NUM_POSSIBLE_VALIDATOR_BYTE_LENGTHS: usize = VALIDATOR_BYTE_LENGTH_MAX - VALIDATOR_BYTE_LENGTH_MIN + 1;

// The number of bytes in a Tendermint validator's public key.
const PUBKEY_BYTES_LEN: usize = 32;

// The maximum number of bytes in a Tendermint validator's voting power.
const VOTING_POWER_BYTES_LENGTH_MAX: usize = 9;

// The maximum number of bits in a Tendermint validator's voting power.
const VOTING_POWER_BITS_LENGTH_MAX: usize = VOTING_POWER_BYTES_LENGTH_MAX * 8;

// The maximum number of validators in a Tendermint validator set.
const VALIDATOR_SET_SIZE_MAX: usize = 4;

/// The Ed25519 public key as a list of 32 byte targets.
#[derive(Debug, Clone, Copy)]
pub struct Ed25519PubkeyTarget(pub [BoolTarget; 256]);

/// The Tendermint hash as a 32 byte target.
#[derive(Debug, Clone, Copy)]
pub struct TendermintHashTarget(pub [Target; HASH_SIZE]);

/// The voting power as a list of 2 u32 targets.
#[derive(Debug, Clone, Copy)]
pub struct I64Target(pub [U32Target; 2]);

/// The bytes, public key, and voting power targets inside of a Tendermint validator.
#[derive(Debug, Clone)]
struct TendermintValidator {
    pub pubkey: Ed25519PubkeyTarget,
    pub voting_power: I64Target,
}

pub trait TendermintMarshaller {
    /// Serializes an int64 as a protobuf varint.
    fn marshal_int64_varint(&mut self, num: I64Target) -> [BoolTarget; VOTING_POWER_BITS_LENGTH_MAX];

    /// Serializes the validator public key and voting power to bytes.
    fn marshal_tendermint_validator(
        &mut self,
        pubkey: Ed25519PubkeyTarget,
        voting_power: I64Target,
    ) -> [BoolTarget; VALIDATOR_BIT_LENGTH_MAX];

    /// Hashes validator bytes to get the leaf according to the Tendermint spec. (0x00 || validatorBytes)
    fn hash_validator_leaf(
        &mut self,
        validator: &[BoolTarget; VALIDATOR_BIT_LENGTH_MAX],
        validator_byte_length: &U32Target,
    ) -> [BoolTarget; HASH_SIZE_BITS];

    /// Hashes multiple validators to get their leaves according to the Tendermint spec using hash_validator_leaf.
    fn hash_validator_leaves(
        &mut self,
        validators: &Vec<[BoolTarget; VALIDATOR_BIT_LENGTH_MAX]>,
        validator_byte_lengths: &Vec<U32Target>,
    ) -> Vec<[BoolTarget; HASH_SIZE_BITS]>;

    /// Hashes a layer of the Merkle tree according to the Tendermint spec. (0x01 || left || right)
    /// If in a pair the right node is not enabled (empty), then the left node is passed up to the next layer.
    /// If neither the left nor right node in a pair is enabled (empty), then the parent node is set to not enabled (empty).
    fn hash_merkle_layer(
        &mut self,
        merkle_hashes: &mut Vec<[BoolTarget; 256]>,
        merkle_hash_enabled: &mut Vec<BoolTarget>,
        num_hashes: usize,
    ) -> (Vec<[BoolTarget; 256]>, Vec<BoolTarget>);
    
    /// Compute the expected validator hash from the validator set.
    fn hash_validator_set(
        &mut self, 
        validators: &Vec<[BoolTarget; VALIDATOR_BIT_LENGTH_MAX]>,
        validator_byte_length: &Vec<U32Target>,
        validator_enabled: &Vec<BoolTarget>,
    ) -> [BoolTarget; HASH_SIZE * 8];
}

impl<F: RichField + Extendable<D>, const D: usize> TendermintMarshaller for CircuitBuilder<F, D> {
    fn marshal_int64_varint(
        &mut self,
        voting_power: I64Target,
    ) -> [BoolTarget; VOTING_POWER_BITS_LENGTH_MAX] {
        let zero = self.zero();
        let one = self.one();

        // The remaining bytes of the serialized validator are the voting power as a "varint".
        // Note: need to be careful regarding U64 and I64 differences.
        let voting_power_bits_lower = self.u32_to_bits_le(voting_power.0[0]);
        let voting_power_bits_upper = self.u32_to_bits_le(voting_power.0[1]);
        let voting_power_bits = [voting_power_bits_lower, voting_power_bits_upper].concat();

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
        pubkey: Ed25519PubkeyTarget,
        voting_power: I64Target,
    ) -> [BoolTarget; VALIDATOR_BYTE_LENGTH_MAX * 8] {
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

        // The next 32 bytes of the serialized validator are the public key.
        for i in 0..PUBKEY_BYTES_LEN {
            for j in 0..8 {
                buffer[ptr] = pubkey.0[i * 8 + j];
                ptr += 1;
            }
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

        buffer
    }

    fn hash_validator_leaf(
        &mut self,
        validator: &[BoolTarget; VALIDATOR_BIT_LENGTH_MAX],
        validator_byte_length: &U32Target,
    ) -> [BoolTarget; HASH_SIZE_BITS] {
        // Range check the validator byte length is between [VALIDATOR_BYTE_LENGTH_MIN, VALIDATOR_BYTE_LENGTH_MAX]
        let min_validator_bytes_length = self.constant(F::from_canonical_usize(VALIDATOR_BYTE_LENGTH_MIN));
        let max_validator_bytes_length = self.constant(F::from_canonical_usize(VALIDATOR_BYTE_LENGTH_MAX));

        // len - min
        let diff_with_min_length = self.sub(validator_byte_length.0, min_validator_bytes_length);

        // max - len
        let diff_with_max_length = self.sub(max_validator_bytes_length, validator_byte_length.0);

        // Check that diff_with_min_len and diff_with_max_len are both small (if outside of range, one would be a large element of F).
        self.range_check(diff_with_min_length, 4);
        self.range_check(diff_with_max_length, 4);

        // Note: Because the byte length of each validator is variable, need to hash the validator bytes for each potential byte length.
        let mut validator_bytes_hashes = [[self._false(); HASH_SIZE_BITS]; NUM_POSSIBLE_VALIDATOR_BYTE_LENGTHS];
        for j in 0..NUM_POSSIBLE_VALIDATOR_BYTE_LENGTHS {
            // Calculate the length of the message for the leaf hash.
            // 0x00 || validatorBytes
            let bits_length = 8 + (VALIDATOR_BYTE_LENGTH_MIN + j) * 8;

            // Calculate the message for the leaf hash.
            let mut validator_bits = vec![self._false(); bits_length];

            // 0x00
            for k in 0..8 {
                validator_bits[k] = self._false();
            }

            // validatorBytes
            for k in 8..bits_length {
                validator_bits[k] = validator[k - 8];
            }
            
            // Load the output of the hash.
            let hash = sha256(self, validator_bits);
            for k in 0..HASH_SIZE_BITS {
                validator_bytes_hashes[j][k] = hash[k];
            }

        }
        let validator_byte_length_min_constant = self.constant(F::from_canonical_u32(VALIDATOR_BYTE_LENGTH_MIN as u32));

        // Calculate the index of the validator's bytes length in the range [0, NUM_POSSIBLE_VALIDATOR_BYTE_LENGTHS).
        let length_index = self.sub(validator_byte_length.0, validator_byte_length_min_constant);
        
        // Create a bitmap, with a selector bit set to 1 if the current index corresponds to the index of the validator's bytes length.
        let mut validator_byte_hash_selector = [self._false(); NUM_POSSIBLE_VALIDATOR_BYTE_LENGTHS];
        for j in 0..NUM_POSSIBLE_VALIDATOR_BYTE_LENGTHS {
            let byte_length_index = self.constant(F::from_canonical_u32(j as u32));
            validator_byte_hash_selector[j] = self.is_equal(length_index, byte_length_index);
        }


        let mut ret_validator_leaf_hash = [self._false(); HASH_SIZE_BITS];
        for j in 0..NUM_POSSIBLE_VALIDATOR_BYTE_LENGTHS {
            for k in 0..HASH_SIZE_BITS {
                // Select the correct byte hash for the validator's byte length. 
                // Copy the bits from the correct byte hash into the return hash if the selector bit for that byte length is set to 1. 
                // In all other cases, keep the existing bits in the return hash, yielding desired behavior.
                ret_validator_leaf_hash[k] = BoolTarget::new_unsafe(self.select(validator_byte_hash_selector[j], 
                    validator_bytes_hashes[j][k].target, 
                    ret_validator_leaf_hash[k].target));
            }
        }

        ret_validator_leaf_hash
    }

    fn hash_validator_leaves(
        &mut self,
        validators: &Vec<[BoolTarget; VALIDATOR_BIT_LENGTH_MAX]>,
        validator_byte_lengths: &Vec<U32Target>,
    ) -> Vec<[BoolTarget; HASH_SIZE_BITS]> {
        let num_validators = self.constant(F::from_canonical_usize(validators.len()));
        let num_validator_byte_lengths = self.constant(F::from_canonical_usize(validator_byte_lengths.len()));
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
        let mut validators_leaf_hashes = [[self._false(); HASH_SIZE_BITS]; VALIDATOR_SET_SIZE_MAX];
        for i in 0..VALIDATOR_SET_SIZE_MAX {
            validators_leaf_hashes[i] = self.hash_validator_leaf(&validators[i], &validator_byte_lengths[i]);
        }

        validators_leaf_hashes.to_vec()
    }

    fn hash_merkle_layer(
        &mut self,
        merkle_hashes: &mut Vec<[BoolTarget; 256]>,
        merkle_hash_enabled: &mut Vec<BoolTarget>,
        num_hashes: usize,
    ) -> (Vec<[BoolTarget; 256]>, Vec<BoolTarget>) {
        let zero = self.zero();
        let one = self.one();

        for i in (0..num_hashes).step_by(2) {
            let both_nodes_enabled = self.and(merkle_hash_enabled[i], merkle_hash_enabled[i + 1]);

            let first_node_disabled = self.not(merkle_hash_enabled[i]);
            let second_node_disabled = self.not(merkle_hash_enabled[i + 1]);
            let both_nodes_disabled = self.and(first_node_disabled, second_node_disabled);

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
            for k in 8..8+HASH_SIZE_BITS {
                message_bits[k] = merkle_hashes[i][k - 8];
            }

            // right
            for k in 8+HASH_SIZE_BITS..bits_length {
                message_bits[k] = merkle_hashes[i + 1][k - (8 + HASH_SIZE_BITS)];
            }
            
            // Load the output of the hash.
            // Note: Calculate the inner hash as if both validators are enabled.
            let inner_hash = sha256(self, message_bits);

            for k in 0..HASH_SIZE_BITS {
                // If the left node is enabled and the right node is disabled, we pass up the left hash.
                merkle_hashes[i / 2][k] = BoolTarget::new_unsafe(self.select(both_nodes_enabled, inner_hash[k].target, merkle_hashes[i][k].target));
            }

            // Set the inner node one level up to disabled if both nodes are disabled.
            merkle_hash_enabled[i / 2] = BoolTarget::new_unsafe(self.select(both_nodes_disabled, zero, one));
        }

        // Return the hashes and enabled nodes for the next layer up.
        (merkle_hashes.to_vec(), merkle_hash_enabled.to_vec())
    }

    fn hash_validator_set(
        &mut self,
        validators: &Vec<[BoolTarget; VALIDATOR_BIT_LENGTH_MAX]>,
        validator_byte_lengths: &Vec<U32Target>,
        validator_enabled: &Vec<BoolTarget>,
    ) -> [BoolTarget; HASH_SIZE_BITS] {
        let num_validators = self.constant(F::from_canonical_usize(validators.len()));
        let num_validator_byte_lengths = self.constant(F::from_canonical_usize(validator_byte_lengths.len()));
        let num_validator_enabled = self.constant(F::from_canonical_usize(validator_enabled.len()));
        let validator_set_size_max = self.constant(F::from_canonical_usize(VALIDATOR_SET_SIZE_MAX));
            
        // Assert validators length is VALIDATOR_SET_SIZE_MAX
        self.connect(num_validators, validator_set_size_max);

        // Assert validator_byte_length length is VALIDATOR_SET_SIZE_MAX
        self.connect(num_validator_byte_lengths, validator_set_size_max);

        // Assert validator_enabled length is VALIDATOR_SET_SIZE_MAX
        self.connect(num_validator_enabled, validator_set_size_max);

        // Hash each of the validators to get their corresponding leaf hash.
        let mut current_validator_hashes = self.hash_validator_leaves(validators, validator_byte_lengths);

        // Whether to treat the validator as empty.
        let mut current_validator_enabled = validator_enabled.clone();

        let mut merkle_layer_size = VALIDATOR_SET_SIZE_MAX;

        // Hash each layer of nodes to get the root according to the Tendermint spec, starting from the leaves.
        while merkle_layer_size > 1 {
            (current_validator_hashes, current_validator_enabled) = self.hash_merkle_layer(&mut current_validator_hashes, &mut current_validator_enabled, merkle_layer_size);
            merkle_layer_size /= 2;
        }

        // Return the root hash.
        return current_validator_hashes[0];
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use plonky2::{
        iop::witness::{PartialWitness, WitnessWrite},
        plonk::{
            circuit_builder::CircuitBuilder,
            circuit_data::CircuitConfig,
            config::{GenericConfig, PoseidonGoldilocksConfig},
        },
    };
    use plonky2::iop::target::{BoolTarget};
    use plonky2_field::types::Field;
    use subtle_encoding::hex;

    use crate::validator::{
        VALIDATOR_BIT_LENGTH_MAX,
        VALIDATOR_SET_SIZE_MAX
    };

    use crate::merkle::HASH_SIZE_BITS;

    use crate::{
        u32::U32Target,
        utils::{bits_to_bytes, f_bits_to_bytes},
        validator::{I64Target, TendermintMarshaller},
    };

    use super::{Ed25519PubkeyTarget, VALIDATOR_BYTE_LENGTH_MIN};

    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;
    const D: usize = 2;

    fn to_bits(msg: Vec<u8>) -> Vec<bool> {
        let mut res = Vec::new();
        for i in 0..msg.len() {
            let char = msg[i];
            for j in 0..8 {
                if (char & (1 << 7 - j)) != 0 {
                    res.push(true);
                } else {
                    res.push(false);
                }
            }
        }
        res
    }

    #[test]
    fn test_get_leaf_hash() {
        let mut pw = PartialWitness::new();
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        // Computed the leaf hashes corresponding to the first validator bytes. SHA256(0x00 || validatorBytes)
        let expected_digest = "84f633a570a987326947aafd434ae37f151e98d5e6d429137a4cc378d4a7988e";
        let digest_bits = to_bits(hex::decode(expected_digest).unwrap());

        let validators: Vec<&str> = vec!["de6ad0941095ada2a7996e6a888581928203b8b69e07ee254d289f5b9c9caea193c2ab01902d", "92fbe0c52937d80c5ea643c7832620b84bfdf154ec7129b8b471a63a763f2fe955af1ac65fd3", "e902f88b2371ff6243bf4b0ebe8f46205e00749dd4dad07b2ea34350a1f9ceedb7620ab913c2"];

        let vec_validator_byte_len: Vec<usize> = vec![
            38,
            38,
            38,
        ];

        let mut validator_byte_length: Vec<U32Target> = vec![U32Target(builder.constant(F::from_canonical_usize(VALIDATOR_BYTE_LENGTH_MIN))); VALIDATOR_SET_SIZE_MAX];

        let mut validator_enabled: Vec<BoolTarget> = vec![builder._false(); VALIDATOR_SET_SIZE_MAX];

        let mut validator_bits: Vec<Vec<bool>> = (0..256)
        .map(|_| Vec::<bool>::new())
        .collect();

        let mut validators_target: Vec<[BoolTarget; VALIDATOR_BIT_LENGTH_MAX]> = vec![[builder._false(); VALIDATOR_BIT_LENGTH_MAX]; VALIDATOR_SET_SIZE_MAX];

        // Convert the hex strings to bytes.
        for i in 0..validators.len() {
            validator_bits[i] = to_bits(hex::decode(validators[i]).unwrap());
            for j in 0..(vec_validator_byte_len[i]*8) {
                if validator_bits[i][j] {
                    validators_target[i][j] = builder._true();
                } else {
                    validators_target[i][j] = builder._false();
                }
            }
            validator_byte_length[i] = U32Target(builder.constant(F::from_canonical_usize(vec_validator_byte_len[i])));
            validator_enabled[i] = builder._true();
        }

        let result = builder.hash_validator_leaf(&validators_target[0], &validator_byte_length[0]);

        // Set the target bits to the expected digest bits.
        for i in 0..HASH_SIZE_BITS {
            if digest_bits[i] {
                pw.set_target(result[i].target, F::ONE);
            } else {
                pw.set_target(result[i].target, F::ZERO);
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

        let validators: Vec<&str> = vec!["de6ad0941095ada2a7996e6a888581928203b8b69e07ee254d289f5b9c9caea193c2ab01902d", "92fbe0c52937d80c5ea643c7832620b84bfdf154ec7129b8b471a63a763f2fe955af1ac65fd3", "e902f88b2371ff6243bf4b0ebe8f46205e00749dd4dad07b2ea34350a1f9ceedb7620ab913c2"];

        // Computed the leaf hashes corresponding to the above validators. SHA256(0x00 || validatorBytes)
        let expected_digests: Vec<&str> = vec!["84f633a570a987326947aafd434ae37f151e98d5e6d429137a4cc378d4a7988e",
        "3d03b065d15243f543ba9498f1c4ee954ef954c9a03049d62fd2df9e48017409"
        ,"987d7777f7809fc17efa5951fa1de336d55e6b357b0df6605be616b53191ee02"
        ];
        let digests_bits: Vec<Vec<bool>> = expected_digests.iter().map(|x| to_bits(hex::decode(x).unwrap())).collect();


        let vec_validator_byte_len: Vec<usize> = vec![
            38,
            38,
            38,
        ];

        let mut validator_byte_length: Vec<U32Target> = vec![U32Target(builder.constant(F::from_canonical_usize(VALIDATOR_BYTE_LENGTH_MIN))); VALIDATOR_SET_SIZE_MAX];

        let mut validator_enabled: Vec<BoolTarget> = vec![builder._false(); VALIDATOR_SET_SIZE_MAX];

        let mut validator_bits: Vec<Vec<bool>> = (0..256)
        .map(|_| Vec::<bool>::new())
        .collect();

        let mut validators_target: Vec<[BoolTarget; VALIDATOR_BIT_LENGTH_MAX]> = vec![[builder._false(); VALIDATOR_BIT_LENGTH_MAX]; VALIDATOR_SET_SIZE_MAX];

        // Convert the hex strings to bytes.
        for i in 0..validators.len() {
            validator_bits[i] = to_bits(hex::decode(validators[i]).unwrap());
            for j in 0..(vec_validator_byte_len[i]*8) {
                if validator_bits[i][j] {
                    validators_target[i][j] = builder._true();
                } else {
                    validators_target[i][j] = builder._false();
                }
            }
            validator_byte_length[i] = U32Target(builder.constant(F::from_canonical_usize(vec_validator_byte_len[i])));
            validator_enabled[i] = builder._true();
        }
        let result = builder.hash_validator_leaves(&validators_target, &validator_byte_length);
        println!("Got all leaf hashes: {}", result.len());
        for i in 0..validators.len() {
            for j in 0..HASH_SIZE_BITS {
                if digests_bits[i][j] {
                    pw.set_target(result[i][j].target, F::ONE);
                } else {
                    pw.set_target(result[i][j].target, F::ZERO);
                }
            }
        }

        let data = builder.build::<C>();
        let proof = data.prove(pw).unwrap();

        data.verify(proof).unwrap();

        println!("Verified proof");

    }

    #[test]
    fn test_validator_inclusion() {
        let mut pw = PartialWitness::new();
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        // Generated random byte arrays of length 38 (to mimic validator bytes), and computed the validator hash corresponding to a merkle tree of depth 2 formed by these validator bytes.
        let validators: Vec<&str> = vec!["de6ad0941095ada2a7996e6a888581928203b8b69e07ee254d289f5b9c9caea193c2ab01902d", "92fbe0c52937d80c5ea643c7832620b84bfdf154ec7129b8b471a63a763f2fe955af1ac65fd3", "e902f88b2371ff6243bf4b0ebe8f46205e00749dd4dad07b2ea34350a1f9ceedb7620ab913c2"];

        let expected_digest = "5541a94a9cf19e568401a2eed59f4ac8118c945d37803632aad655c6ee4f3ed6";
        let digest_bits = to_bits(hex::decode(expected_digest).unwrap());


        println!("Expected Val Hash Encoding (Bytes): {:?}", hex::decode(expected_digest).unwrap());

        let vec_validator_byte_len: Vec<usize> = vec![
            38,
            38,
            38,
        ];

        let mut validator_byte_length: Vec<U32Target> = vec![U32Target(builder.constant(F::from_canonical_usize(VALIDATOR_BYTE_LENGTH_MIN))); VALIDATOR_SET_SIZE_MAX];

        let mut validator_enabled: Vec<BoolTarget> = vec![builder._false(); VALIDATOR_SET_SIZE_MAX];

        let mut validator_bits: Vec<Vec<bool>> = (0..256)
        .map(|_| Vec::<bool>::new())
        .collect();

        let mut validators_target: Vec<[BoolTarget; VALIDATOR_BIT_LENGTH_MAX]> = vec![[builder._false(); VALIDATOR_BIT_LENGTH_MAX]; VALIDATOR_SET_SIZE_MAX];

        // Convert the hex strings to bytes.
        for i in 0..validators.len() {
            validator_bits[i] = to_bits(hex::decode(validators[i]).unwrap());
            for j in 0..(vec_validator_byte_len[i]*8) {
                if validator_bits[i][j] {
                    validators_target[i][j] = builder._true();
                } else {
                    validators_target[i][j] = builder._false();
                }
            }
            validator_byte_length[i] = U32Target(builder.constant(F::from_canonical_usize(vec_validator_byte_len[i])));
            validator_enabled[i] = builder._true();
        }
        let result = builder.hash_validator_set(&validators_target, &validator_byte_length, &validator_enabled);

        for i in 0..HASH_SIZE_BITS {
            if digest_bits[i] {
                pw.set_target(result[i].target, F::ONE);
            } else {
                pw.set_target(result[i].target, F::ZERO);
            }
        }

        let data = builder.build::<C>();
        let proof = data.prove(pw).unwrap();

        println!("Created proof");

        data.verify(proof).unwrap();

        println!("Verified proof");

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

            let voting_power_i64 = test_case.0;
            let voting_power_lower = voting_power_i64 & ((1 << 32) - 1);
            let voting_power_upper = voting_power_i64 >> 32;

            let voting_power_lower_target =
                U32Target(builder.constant(F::from_canonical_usize(voting_power_lower as usize)));
            let voting_power_upper_target =
                U32Target(builder.constant(F::from_canonical_usize(voting_power_upper as usize)));
            let voting_power_target =
                I64Target([voting_power_lower_target, voting_power_upper_target]);
            let result = builder.marshal_int64_varint(voting_power_target);

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
        // This is a test cases generated from `celestia-core`.
        //
        // allZerosPubkey := make(ed25519.PubKey, ed25519.PubKeySize)
        // minimumVotingPower := int64(724325643436111)
        // minValidator := NewValidator(allZerosPubkey, minimumVotingPower)
        // fmt.Println(minValidator.Bytes())
        //
        // The tuples hold the form: (voting_power_i64, voting_power_varint_bytes).
        let voting_power_i64 = 724325643436111i64;
        let pubkey_bits = [false; 256];
        let expected_marshal = [
            10u8, 34, 10, 32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 16, 207, 128, 183, 165, 211, 216, 164, 1,
        ];

        let pw = PartialWitness::new();
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let voting_power_lower = voting_power_i64 & ((1 << 32) - 1);
        let voting_power_upper = voting_power_i64 >> 32;

        let voting_power_lower_target =
            U32Target(builder.constant(F::from_canonical_usize(voting_power_lower as usize)));
        let voting_power_upper_target =
            U32Target(builder.constant(F::from_canonical_usize(voting_power_upper as usize)));
        let voting_power_target = I64Target([voting_power_lower_target, voting_power_upper_target]);

        let mut pubkey = [builder._false(); 256];
        for i in 0..256 {
            pubkey[i] = if pubkey_bits[i] {
                builder._true()
            } else {
                builder._false()
            };
        }
        let pubkey = Ed25519PubkeyTarget(pubkey);
        let result = builder.marshal_tendermint_validator(pubkey, voting_power_target);

        for i in 0..result.len() {
            builder.register_public_input(result[i].target);
        }

        let data = builder.build::<C>();
        let proof = data.prove(pw).unwrap();

        let marshalled_bytes = f_bits_to_bytes(&proof.public_inputs);
        let expected_bytes = expected_marshal;

        println!("Voting Power: {:?}", voting_power_i64);
        println!("Public Key: {:?}", bits_to_bytes(&pubkey_bits));
        println!("Expected Validator Encoding (Bytes): {:?}", expected_bytes);
        println!(
            "Produced Validator Encoding (Bytes): {:?}",
            marshalled_bytes
        );

        for i in 0..marshalled_bytes.len() {
            if i >= expected_bytes.len() {
                assert_eq!(marshalled_bytes[i], 0);
                continue;
            }
            assert_eq!(marshalled_bytes[i], expected_bytes[i]);
        }
    }
}
