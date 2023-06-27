use crate::u32::{U32Builder, U32Target};
use crate::u8::{U8Builder, U8Target};
use plonky2::iop::target::BoolTarget;
use plonky2::{hash::hash_types::RichField, plonk::circuit_builder::CircuitBuilder};
use plonky2_field::extension::Extendable;

/// The protobuf-encoding of a Tendermint validator is a deterministic function of the validator's
/// public key (32 bytes) and voting power (int64). The encoding is as follows in bytes:
///
///     10 34 10 32 <pubkey> 16 <varint>
///
/// The `pubkey` is encoded as the raw list of bytes used in the public key. The `varint` is
/// encoded using protobuf's default integer encoding, which consist of 7 bit payloads. You can
/// read more about them here: https://protobuf.dev/programming-guides/encoding/#varints.

/// The maximum length of a protobuf-encoded Tendermint validator.
const VALIDATOR_BYTES_LEN_MAX: usize = 46;

// The number of bytes in a Tendermint validator's public key.
const PUBKEY_BYTES_LEN: usize = 32;

// The maximum number of bytes in a Tendermint validator's voting power.
const VOTING_POWER_BYTES_LEN_MAX: usize = 9;

/// The Ed25519 public key as a list of 32 byte targets.
#[derive(Debug, Clone, Copy)]
pub struct Ed25519PubkeyTarget(pub [U8Target; 32]);

/// The voting power as a list of 2 u32 targets.
#[derive(Debug, Clone, Copy)]
pub struct I64Target(pub [U32Target; 2]);

/// The bytes, public key, and voting power targets inside of a Tendermint validator.
#[derive(Debug, Clone)]
struct TendermintValidator {
    pub pubkey: Ed25519PubkeyTarget,
    pub voting_power: I64Target,
}

pub trait TendermintVerifier {
    /// Serializes the validator public key and voting power to bytes.
    fn marshal_tendermint_validator(
        &mut self,
        pubkey: Ed25519PubkeyTarget,
        voting_power: I64Target,
    ) -> [U8Target; VALIDATOR_BYTES_LEN_MAX];
}

impl<F: RichField + Extendable<D>, const D: usize> TendermintVerifier for CircuitBuilder<F, D> {
    fn marshal_tendermint_validator(
        &mut self,
        pubkey: Ed25519PubkeyTarget,
        voting_power: I64Target,
    ) -> [U8Target; VALIDATOR_BYTES_LEN_MAX] {
        let mut ptr = 0;
        let zero = self.zero();
        let one = self.one();
        let zero_u8 = self.zero_u8();
        let mut serialized_bytes = [zero_u8; VALIDATOR_BYTES_LEN_MAX];

        // The first four prefix bytes of the serialized validator are `10 34 10 32`.
        let prefix_pubkey_bytes = [10, 34, 10, 32].map(|x| self.constant(F::from_canonical_u64(x)));
        for i in 0..prefix_pubkey_bytes.len() {
            serialized_bytes[ptr] = self.new_u8(prefix_pubkey_bytes[i]);
            ptr += 1;
        }

        // The next 32 bytes of the serialized validator are the public key.
        for i in 0..PUBKEY_BYTES_LEN {
            serialized_bytes[ptr] = pubkey.0[i];
            ptr += 1;
        }

        // The next byte of the serialized validator is `16`.
        let prefix_voting_power_byte = self.constant(F::from_canonical_u64(16));
        serialized_bytes[ptr] = self.new_u8(prefix_voting_power_byte);

        // The remaining bytes of the serialized validator are the voting power as a "varint".
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
        for i in 0..VOTING_POWER_BYTES_LEN_MAX {
            // If the index is less than the last non-zero septet index, `diff` will be in
            // [0, VOTING_POWER_BYTES_LEN_MAX).
            let idx = self.constant(F::from_canonical_usize(i));
            let diff = self.sub(last_seen_non_zero_septet_idx, idx);

            // Calculates whether we've seen at least one `diff` in [0, VOTING_POWER_BYTES_LEN_MAX).
            let mut is_lt_last_non_zero_septet_idx = BoolTarget::new_unsafe(zero);
            for j in 0..VOTING_POWER_BYTES_LEN_MAX {
                let candidate_idx = self.constant(F::from_canonical_usize(j));
                let is_candidate = self.is_equal(diff, candidate_idx);
                is_lt_last_non_zero_septet_idx =
                    self.or(is_lt_last_non_zero_septet_idx, is_candidate);
            }

            // If the index is less than the last non-zero septet index, set the most significant
            // bit of the byte to 1 and copy the septet bits into the lower 7 bits. Otherwise,
            // still copy the bit but the set the most significant bit to zero.
            let base = F::TWO.exp_u64(7);
            let byte = self.mul_const_add(base, is_lt_last_non_zero_septet_idx.target, septets[i]);
            serialized_bytes[ptr] = self.new_u8(byte);
        }

        return serialized_bytes;
    }
}
