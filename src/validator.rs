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

use crate::helper::{uint32_to_bits, _right_rotate, _shr};
use crate::merkle::{HASH_SIZE, HASH_LEN_BITS};
use crate::u32::{U32Builder, U32Target};
use crate::sha256::{make_sha256_circuit};

/// The maximum length of a protobuf-encoded Tendermint validator in bytes.
const VALIDATOR_BYTES_LEN_MAX: usize = 46;

/// The maximum length of a protobuf-encoded Tendermint validator in bits.
const VALIDATOR_BITS_LEN_MAX: usize = VALIDATOR_BYTES_LEN_MAX * 8;

/// The minimum length of a protobuf-encoded Tendermint validator in bytes.
const VALIDATOR_BYTES_LEN_MIN: usize = 38;

/// The minimum length of a protobuf-encoded Tendermint validator in bits.
const VALIDATOR_BITS_LEN_MIN: usize = VALIDATOR_BYTES_LEN_MIN * 8;

/// The number of possible byte lengths of a protobuf-encoded Tendermint validator.
const NUM_VALIDATOR_BYTES_LENGTHS: usize = VALIDATOR_BYTES_LEN_MAX - VALIDATOR_BYTES_LEN_MIN + 1;

// The number of bytes in a Tendermint validator's public key.
const PUBKEY_BYTES_LEN: usize = 32;

// The maximum number of bytes in a Tendermint validator's voting power.
const VOTING_POWER_BYTES_LEN_MAX: usize = 9;

// The maximum number of bits in a Tendermint validator's voting power.
const VOTING_POWER_BITS_LEN_MAX: usize = VOTING_POWER_BYTES_LEN_MAX * 8;

// The maximum number of validators in a Tendermint validator set.
const VALIDATOR_SET_LEN_MAX: usize = 128;

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
    fn marshal_int64_varint(&mut self, num: I64Target) -> [BoolTarget; VOTING_POWER_BITS_LEN_MAX];

    /// Serializes the validator public key and voting power to bytes.
    fn marshal_tendermint_validator(
        &mut self,
        pubkey: Ed25519PubkeyTarget,
        voting_power: I64Target,
    ) -> [BoolTarget; VALIDATOR_BITS_LEN_MAX];
}

pub trait TendermintValidatorSet {
    /// Gets all of the leaf hashes for validators in the validator set with variable length.
    fn get_all_leaf_hashes(
        &mut self,
        validators: [[BoolTarget; VALIDATOR_BITS_LEN_MAX]; VALIDATOR_SET_LEN_MAX],
        validator_byte_lengths: [U32Target; VALIDATOR_SET_LEN_MAX],
    ) -> [[BoolTarget; HASH_LEN_BITS]; VALIDATOR_SET_LEN_MAX];
    
    /// Checks that the validator hash matches the expected hash from the validators.
    fn simple_hash_from_byte_vectors(
        &mut self, 
        validators: [[BoolTarget; VALIDATOR_BITS_LEN_MAX]; VALIDATOR_SET_LEN_MAX],
        validator_lengths: [U32Target; VALIDATOR_SET_LEN_MAX],
        validator_enabled: [BoolTarget; VALIDATOR_SET_LEN_MAX],
    ) -> [BoolTarget; HASH_SIZE * 8];
}

impl<F: RichField + Extendable<D>, const D: usize> TendermintMarshaller for CircuitBuilder<F, D> {
    fn marshal_int64_varint(
        &mut self,
        voting_power: I64Target,
    ) -> [BoolTarget; VOTING_POWER_BITS_LEN_MAX] {
        let zero = self.zero();
        let one = self.one();

        // The remaining bytes of the serialized validator are the voting power as a "varint".
        // Note: need to be careful regarding U64 and I64 differences.
        let voting_power_bits_lower = self.u32_to_bits_le(voting_power.0[0]);
        let voting_power_bits_upper = self.u32_to_bits_le(voting_power.0[1]);
        let voting_power_bits = [voting_power_bits_lower, voting_power_bits_upper].concat();

        // The septet (7 bit) payloads  of the "varint".
        let septets = (0..VOTING_POWER_BYTES_LEN_MAX)
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
        let is_zero_septets = (0..VOTING_POWER_BYTES_LEN_MAX)
            .map(|i| self.is_equal(septets[i], zero).target)
            .collect::<Vec<_>>();

        // Calculates the index of the last non-zero septet.
        let mut last_seen_non_zero_septet_idx = self.zero();
        for i in 0..VOTING_POWER_BYTES_LEN_MAX {
            let is_nonzero_septet = self.sub(one, is_zero_septets[i]);
            let condition = BoolTarget::new_unsafe(is_nonzero_septet);
            let idx = self.constant(F::from_canonical_usize(i));
            last_seen_non_zero_septet_idx =
                self.select(condition, idx, last_seen_non_zero_septet_idx);
        }

        // If the index of a septet is elss than the last non-zero septet, set the most significant
        // bit of the byte to 1 and copy the septet bits into the lower 7 bits. Otherwise, still
        // copy the bit but the set the most significant bit to zero.
        let mut buffer = [self._false(); VOTING_POWER_BYTES_LEN_MAX * 8];
        for i in 0..VOTING_POWER_BYTES_LEN_MAX {
            // If the index is less than the last non-zero septet index, `diff` will be in
            // [0, VOTING_POWER_BYTES_LEN_MAX).
            let idx = self.constant(F::from_canonical_usize(i + 1));
            let diff = self.sub(last_seen_non_zero_septet_idx, idx);

            // Calculates whether we've seen at least one `diff` in [0, VOTING_POWER_BYTES_LEN_MAX).
            let mut is_lt_last_non_zero_septet_idx = BoolTarget::new_unsafe(zero);
            for j in 0..VOTING_POWER_BYTES_LEN_MAX {
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
    ) -> [BoolTarget; VALIDATOR_BYTES_LEN_MAX * 8] {
        let mut ptr = 0;
        let mut buffer = [self._false(); VALIDATOR_BYTES_LEN_MAX * 8];

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
        for i in 0..VOTING_POWER_BYTES_LEN_MAX {
            for j in 0..8 {
                buffer[ptr] = voting_power_bits[i * 8 + j];
                ptr += 1;
            }
        }

        buffer
    }
}

impl<F: RichField + Extendable<D>, const D: usize> TendermintValidatorSet for CircuitBuilder<F, D> {
    fn get_all_leaf_hashes(
        &mut self,
        validators: [[BoolTarget; VALIDATOR_BITS_LEN_MAX]; VALIDATOR_SET_LEN_MAX],
        validator_byte_lengths: [U32Target; VALIDATOR_SET_LEN_MAX],
    ) -> [[BoolTarget; HASH_LEN_BITS]; VALIDATOR_SET_LEN_MAX] {
        let zero = self.zero();
        let one = self.one();
        // PSEUDOCODE

        /*
        validator: [Target; MAX_VALIDATOR_SIZE]
        let cases = [HashTarget; MAX_VALIDATOR_SIZE - MIN_VALIDATOR_SIZE + 1];
        for i in 0..len(cases) {
            cases[i] = sha256(validator[:i+MIN_VALIDATOR_SIZE);
        }
        let output = builder.select_array(length - MIN_VALIDATOR_SIZE, cases);
         */
        // Loop over all validators.
        // Generate the SHA256 hash of each potential byte length of the validator.
        // Select the hash of the correct byte length.
        // Return the leaf hash for all validators.

        let mut validators_leaf_hashes = [[self._false(); HASH_LEN_BITS]; VALIDATOR_SET_LEN_MAX];
        // Hash each of the validators into a leaf hash.
        for i in 0..VALIDATOR_SET_LEN_MAX {
            let mut validator_bytes_hashes = [[self._false(); HASH_LEN_BITS]; NUM_VALIDATOR_BYTES_LENGTHS];
            for j in 0..NUM_VALIDATOR_BYTES_LENGTHS {
                // Calculate the length of the message for the leaf hash.
                // 0x00 || validatorBytes
                let bits_length = 8 + (VALIDATOR_BYTES_LEN_MIN + j) * 8;
                
                let sha_target = make_sha256_circuit(self, bits_length as u128);
                // 0x00
                for k in 0..8 {
                    self.connect(sha_target.message[k].target, zero);
                }
                // validatorBytes
                for k in 8..bits_length {
                    self.connect(validators[i][k].target, sha_target.message[k].target);
                }
                // Load the output of the hash.
                for l in 0..HASH_LEN_BITS {
                    validator_bytes_hashes[i][l] = self.add_virtual_bool_target_safe();
                    self.connect(sha_target.digest[i].target, validator_bytes_hashes[i][l].target);
                }
            }
            let val_bytes_len_min = self.constant(F::from_canonical_u32(VALIDATOR_BYTES_LEN_MIN as u32));
            let length_index = self.sub(validator_byte_lengths[i].0, val_bytes_len_min);
            
            // Create a bitmap, with a single bit set to 1 that corresponds to the length of the validator's bytes.
            let mut validator_byte_hash_selector = [self._false(); NUM_VALIDATOR_BYTES_LENGTHS];
            for j in 0..NUM_VALIDATOR_BYTES_LENGTHS {
                let byte_length = self.constant(F::from_canonical_u32(j as u32));
                validator_byte_hash_selector[j] = self.is_equal(length_index, byte_length);
            }

            // Select the validator's byte hash that we want to use from this array.
            let mut temp_validator_leaf_hash = [self._false(); HASH_LEN_BITS];
            for j in 0..NUM_VALIDATOR_BYTES_LENGTHS {
                for k in 0..HASH_LEN_BITS {
                    temp_validator_leaf_hash[k] = BoolTarget::new_unsafe(self.select(validator_byte_hash_selector[j], 
                        validator_bytes_hashes[j][k].target, 
                        temp_validator_leaf_hash[k].target));
                }
            }
            
            // Set the validator's leaf hash to the selected hash.
            for j in 0..HASH_LEN_BITS {
                self.connect(temp_validator_leaf_hash[j].target, validators_leaf_hashes[i][j].target);
            }

        }
        validators_leaf_hashes
    }

    fn simple_hash_from_byte_vectors(
        &mut self, 
        validators: [[BoolTarget; VALIDATOR_BITS_LEN_MAX]; VALIDATOR_SET_LEN_MAX],
        validator_byte_lengths: [U32Target; VALIDATOR_SET_LEN_MAX],
        validator_enabled: [BoolTarget; VALIDATOR_SET_LEN_MAX],
    ) -> [BoolTarget; HASH_LEN_BITS] {
        let zero = self.zero();
        let one = self.one();

        let mut temp_validators = self.get_all_leaf_hashes(validators, validator_byte_lengths);
        let mut temp_validator_enabled = validator_enabled;

        // Initialize temp_validators of [BoolTarget; HASH_LEN_BITS] of length VALIDATOR_SET_LEN_MAX
        // Initialize temp_validator_enabled of [BoolTarget] of length VALIDATOR_SET_LEN_MAX
        // Loop over validators with VALIDATOR_SET_LEN_MAX
        //   If validator_enabled[i] is true && validator_enabled[i + 1] is true
        //     Concatenate validators[i] and validators[i + 1] & hash into a single [BoolTarget; HASH_LEN_BITS]
        //   If validator_enabled[i] is true && validator_enabled[i + 1] is false
        //     Concatenate validators[i] and zero & hash into a single [BoolTarget; HASH_LEN_BITS]
        //   If validator_enabled[i] is false && validator_enabled[i + 1] is false
        //     Set temp_validators_enabled[i / 2] to false


        // Loop from size VALIDATOR_SET_LEN_MAX to 2
        let mut size = VALIDATOR_SET_LEN_MAX;
        while size > 1 {
            // Loop over validators with VALIDATOR_SET_LEN_MAX, i += 2
            for i in (0..size).step_by(2) {
                let both_enabled = self.and(validator_enabled[i], validator_enabled[i + 1]);

                let disabled_1 = self.not(validator_enabled[i]);
                let disabled_2 = self.not(validator_enabled[i + 1]);
                let both_disabled = self.and(disabled_1, disabled_2);

                // If validator_enabled[i] is true && validator_enabled[i + 1] is true
                let mut temp_validator_both_true = [self._false(); HASH_LEN_BITS];
                // Calculate the length of the message for the leaf hash.
                // 0x01 || left || right
                let bits_length = 8 + (HASH_LEN_BITS * 2);
                
                let sha_target = make_sha256_circuit(self, bits_length as u128);
                // 0x01
                for k in 0..7 {
                    self.connect(sha_target.message[k].target, zero);
                }
                self.connect(sha_target.message[7].target, one);
                // left
                for k in 8..8+HASH_LEN_BITS {
                    self.connect(validators[i][k].target, sha_target.message[k].target);
                }
                // right
                for k in 8+HASH_LEN_BITS..bits_length {
                    self.connect(validators[i + 1][k].target, sha_target.message[k].target);
                }

                // Load the output of the hash.
                for l in 0..HASH_LEN_BITS {
                    temp_validator_both_true[l] = self.add_virtual_bool_target_safe();
                    self.connect(sha_target.digest[i].target, temp_validator_both_true[l].target);
                }

                // If temp_validator_enabled[i] is true && temp_validator_enabled[i + 1] is false, we pass up the left hash.
                for l in 0..HASH_LEN_BITS {
                    temp_validators[i / 2][l] = BoolTarget::new_unsafe(self.select(both_enabled, temp_validator_both_true[l].target, temp_validators[i / 2][l].target));
                }

                // Set temp_validators_enabled[i / 2] to false if both temp_validators_enabled[i] and temp_validators_enabled[i+1] are false.
                temp_validator_enabled[i / 2] = BoolTarget::new_unsafe(self.select(both_disabled, zero, one));

            }
            size /= 2;
        }

        return temp_validators[0];
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use plonky2::{
        iop::witness::PartialWitness,
        plonk::{
            circuit_builder::CircuitBuilder,
            circuit_data::CircuitConfig,
            config::{GenericConfig, PoseidonGoldilocksConfig},
        },
    };
    use plonky2_field::types::Field;

    use crate::{
        u32::U32Target,
        utils::{bits_to_bytes, f_bits_to_bytes},
        validator::{I64Target, TendermintMarshaller},
    };

    use super::Ed25519PubkeyTarget;

    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;
    const D: usize = 2;

    #[test]
    fn test_validator_inclusion() {
        let pw = PartialWitness::new();
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let data = builder.build::<C>();
        let proof = data.prove(pw).unwrap();
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
