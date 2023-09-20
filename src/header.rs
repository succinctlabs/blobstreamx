use crate::utils::VARINT_BYTES_LENGTH_MAX;
use plonky2x::frontend::ecc::ed25519::curve::curve_types::Curve;
use plonky2x::frontend::ecc::ed25519::curve::ed25519::Ed25519;
use plonky2x::frontend::uint::uint64::U64Variable;
use plonky2x::prelude::Field;

use plonky2x::prelude::{
    BoolVariable, ByteVariable, CircuitBuilder, CircuitVariable, PlonkParameters, Variable,
};

pub trait TendermintHeader<L: PlonkParameters<D>, const D: usize> {
    type Curve: Curve;

    /// Serializes an int64 as a protobuf varint.
    fn marshal_int64_varint(
        &mut self,
        num: &U64Variable,
    ) -> [ByteVariable; VARINT_BYTES_LENGTH_MAX];

    /// Verifies the block height against the header.
    fn verify_block_height(
        &mut self,
        header: Bytes32Variable,
        proof: &ArrayVariable<Bytes32Variable, HEADER_PROOF_DEPTH>,
        height: &U64Variable,
        encoded_height_byte_length: U32Variable,
    );
}

impl<L: PlonkParameters<D>, const D: usize> TendermintHeader<L, D> for CircuitBuilder<L, D> {
    type Curve = Ed25519;

    fn marshal_int64_varint(
        &mut self,
        voting_power: &U64Variable,
    ) -> [ByteVariable; VARINT_BYTES_LENGTH_MAX] {
        let zero = self.zero::<Variable>();
        let one = self.one::<Variable>();

        // The remaining bytes of the serialized validator are the voting power as a "varint".
        // Note: need to be careful regarding U64 and I64 differences.
        let voting_power_bits = self.to_le_bits(*voting_power);

        // Check that the MSB of the voting power is zero.
        self.api
            .assert_zero(voting_power_bits[voting_power_bits.len() - 1].0 .0);

        // The septet (7 bit) payloads  of the "varint".
        let septets = (0..VARINT_BYTES_LENGTH_MAX)
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
        let is_zero_septets = (0..VARINT_BYTES_LENGTH_MAX)
            .map(|i| self.is_equal(septets[i], zero))
            .collect::<Vec<_>>();

        // Calculates the index of the last non-zero septet.
        let mut last_seen_non_zero_septet_idx = self.zero();
        for i in 0..VARINT_BYTES_LENGTH_MAX {
            // Ok to cast as BoolVariable since is_zero_septets[i] is 0 or 1 so result is either 0 or 1
            let is_nonzero_septet = BoolVariable(self.sub(one, is_zero_septets[i].0));
            let idx = self.constant::<Variable>(L::Field::from_canonical_usize(i));
            last_seen_non_zero_septet_idx =
                self.select(is_nonzero_septet, idx, last_seen_non_zero_septet_idx);
        }

        let mut res = [self.zero(); VARINT_BYTES_LENGTH_MAX];

        // If the index of a septet is elss than the last non-zero septet, set the most significant
        // bit of the byte to 1 and copy the septet bits into the lower 7 bits. Otherwise, still
        // copy the bit but the set the most significant bit to zero.
        for i in 0..VARINT_BYTES_LENGTH_MAX {
            // If the index is less than the last non-zero septet index, `diff` will be in
            // [0, VARINT_BYTES_LENGTH_MAX).
            let idx = self.constant(L::Field::from_canonical_usize(i + 1));
            let diff = self.sub(last_seen_non_zero_septet_idx, idx);

            // Calculates whether we've seen at least one `diff` in [0, VARINT_BYTES_LENGTH_MAX).
            let mut is_lt_last_non_zero_septet_idx = self._false();
            for j in 0..VARINT_BYTES_LENGTH_MAX {
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
}

// To run tests with logs (i.e. to see proof generation time), set the environment variable `RUST_LOG=debug` before the test command.
// Alternatively, add env::set_var("RUST_LOG", "debug") to the top of the test.
#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    use plonky2x::prelude::DefaultBuilder;

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
}
