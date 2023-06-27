//! The protobuf encoding of a Tendermint validator is a deterministic function of the validator's
//! public key (32 bytes) and voting power (int64). The encoding is as follows in bytes:
//
//!     10 34 10 32 <pubkey> 16 <varint>
//
//! The `pubkey` is encoded as the raw list of bytes used in the public key. The `varint` is
//! encoded using protobuf's default integer encoding, which consist of 7 bit payloads. You can
//! read more about them here: https://protobuf.dev/programming-guides/encoding/#varints.

use crate::u32::{U32Builder, U32Target};
use plonky2::iop::target::BoolTarget;
use plonky2::{hash::hash_types::RichField, plonk::circuit_builder::CircuitBuilder};
use plonky2_field::extension::Extendable;

/// The maximum length of a protobuf-encoded Tendermint validator in bytes.
const VALIDATOR_BYTES_LEN_MAX: usize = 46;

/// The maximum length of a protobuf-encoded Tendermint validator in bits.
const VALIDATOR_BITS_LEN_MAX: usize = VALIDATOR_BYTES_LEN_MAX * 8;

// The number of bytes in a Tendermint validator's public key.
const PUBKEY_BYTES_LEN: usize = 32;

// The maximum number of bytes in a Tendermint validator's voting power.
const VOTING_POWER_BYTES_LEN_MAX: usize = 9;

// The maximum number of bits in a Tendermint validator's voting power.
const VOTING_POWER_BITS_LEN_MAX: usize = VOTING_POWER_BYTES_LEN_MAX * 8;

/// The Ed25519 public key as a list of 32 byte targets.
#[derive(Debug, Clone, Copy)]
pub struct Ed25519PubkeyTarget(pub [BoolTarget; 256]);

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
        validator::{I64Target, TendermintMarshaller},
    };

    #[test]
    fn test_marshal_int64_varint() {
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        const D: usize = 2;

        // These are test cases generated from `celestia-core`.
        //
        // allZerosPubkey := make(ed25519.PubKey, ed25519.PubKeySize)
        // votingPower := int64(9999999999999)
        // validator := NewValidator(allZerosPubkey, votingPower)
        // fmt.Println(validator.Bytes()[37:])
        //
        // The tuples hold the form: (voting_power_i64, voting_power_varint_bytes).
        let test_cases = [
            (1i64, vec![1u64]),
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

            println!("Voting Power: {:?}", test_case.0);
            println!("Expected Varint Encoding (Bytes): {:?}", test_case.1);
            println!("Produced Varint Encoding (Bits): {:?}", proof.public_inputs);

            let mut base = F::ONE;
            let mut byte = F::ZERO;
            for i in 0..proof.public_inputs.len() {
                // If we've gone past the expected number of bytes, then we assert that the rest of
                // the bits are zero.
                if i / 8 >= test_case.1.len() + 1 {
                    if proof.public_inputs[i] != F::ZERO {
                        panic!("unexpected error 1")
                    }
                    continue;
                }

                // If we've reached the end of a byte, then we assert that the byte is correct. We
                // account for the edge conditions such as not wanting to check the 0'th index
                // and wanting to check the last index which may not be a multiple of 8.
                let res = test_case.1.clone();
                if i % 8 == 0 && i != 0 {
                    let expected_byte = F::from_canonical_u64(res[i / 8 - 1]);
                    println!("Byte {}: {} and {}", i / 8 - 1, expected_byte, byte);
                    if expected_byte != byte {
                        panic!("unexpected error 2")
                    }
                    byte = F::ZERO;
                    base = F::ONE;
                } else if i == proof.public_inputs.len() - 1 && i / 8 < res.len() {
                    let expected_byte = F::from_canonical_u64(res[i / 8]);
                    println!("Byte {}: {} and {}", i / 8 - 1, expected_byte, byte);
                    if expected_byte != byte {
                        panic!("unexpected error 3")
                    }
                }

                byte += base * proof.public_inputs[i];
                base *= F::TWO;
            }
        }
    }
}
