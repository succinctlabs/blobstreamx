//! The protobuf encoding of a Tendermint validator is a deterministic function of the validator's
//! public key (32 bytes) and voting power (int64). The encoding is as follows in bytes:
//
//!     10 34 10 32 <pubkey> 16 <varint>
//
//! The `pubkey` is encoded as the raw list of bytes used in the public key. The `varint` is
//! encoded using protobuf's default integer encoding, which consist of 7 bit payloads. You can
//! read more about them here: https://protobuf.dev/programming-guides/encoding/#varints.
use plonky2x::frontend::ecc::ed25519::curve::curve_types::Curve;
use plonky2x::frontend::ecc::ed25519::curve::ed25519::Ed25519;
use plonky2x::frontend::uint::uint64::U64Variable;
use plonky2x::prelude::{BoolVariable, CircuitBuilder, PlonkParameters};
pub trait TendermintVoting {
    type Curve: Curve;
    // Gets the total voting power by summing the voting power of all validators.
    fn get_total_voting_power<const VALIDATOR_SET_SIZE_MAX: usize>(
        &mut self,
        validator_voting_power: &[U64Variable],
    ) -> U64Variable;

    // Checks if accumulated voting power * m > total voting power * n (threshold is n/m)
    fn voting_power_greater_than_threshold(
        &mut self,
        accumulated_power: &U64Variable,
        total_voting_power: &U64Variable,
        threshold_numerator: &U64Variable,
        threshold_denominator: &U64Variable,
    ) -> BoolVariable;

    /// Accumulate voting power from the enabled validators & check that the voting power is greater than 2/3 of the total voting power.
    fn check_voting_power<const VALIDATOR_SET_SIZE_MAX: usize>(
        &mut self,
        validator_voting_power: &[U64Variable],
        validator_enabled: &[BoolVariable],
        total_voting_power: &U64Variable,
        threshold_numerator: &U64Variable,
        threshold_denominator: &U64Variable,
    ) -> BoolVariable;
}

impl<L: PlonkParameters<D>, const D: usize> TendermintVoting for CircuitBuilder<L, D> {
    type Curve = Ed25519;

    fn get_total_voting_power<const VALIDATOR_SET_SIZE_MAX: usize>(
        &mut self,
        validator_voting_power: &[U64Variable],
    ) -> U64Variable {
        // Total will not overflow as MaxTotalVotingPower = int64(math.MaxInt64) / 8
        // https://github.com/celestiaorg/celestia-core/blob/37f950717381e8d8f6393437624652693e4775b8/types/validator_set.go#L25
        let mut total = self.constant::<U64Variable>(0.into());
        for i in 0..validator_voting_power.len() {
            total = self.add(total, validator_voting_power[i])
        }
        total
    }

    fn voting_power_greater_than_threshold(
        &mut self,
        accumulated_power: &U64Variable,
        total_voting_power: &U64Variable,
        threshold_numerator: &U64Variable,
        threshold_denominator: &U64Variable,
    ) -> BoolVariable {
        // Note: MaxTotalVotingPower = int64(math.MaxInt64) / 8
        // Threshold is n/m * total_voting_power
        // Multiplying by a small factor (specifically, c<16) will never overflow.

        // Compute accumulated_voting_power * m
        let scaled_accumulated = self.mul(*accumulated_power, *threshold_denominator);

        // Compute total_vp * n
        let scaled_threshold = self.mul(*total_voting_power, *threshold_numerator);

        self.le(scaled_threshold, scaled_accumulated)
    }

    fn check_voting_power<const VALIDATOR_SET_SIZE_MAX: usize>(
        &mut self,
        validator_voting_power: &[U64Variable],
        validator_enabled: &[BoolVariable],
        total_voting_power: &U64Variable,
        threshold_numerator: &U64Variable,
        threshold_denominator: &U64Variable,
    ) -> BoolVariable {
        let zero = self.constant::<U64Variable>(0.into());
        // Accumulate the voting power from the enabled validators.
        let mut accumulated_voting_power = self.constant::<U64Variable>(0.into());

        // Note: MaxTotalVotingPower = int64(math.MaxInt64) / 8
        for i in 0..VALIDATOR_SET_SIZE_MAX {
            // If the validator is enabled, add their voting power to the accumulated voting power.
            let select_voting_power =
                self.select(validator_enabled[i], validator_voting_power[i], zero);
            accumulated_voting_power = self.add(accumulated_voting_power, select_voting_power);
        }

        // Note: Because the threshold is n/m, max I64 should be range checked to be < 2^63 / m
        self.voting_power_greater_than_threshold(
            &accumulated_voting_power,
            total_voting_power,
            threshold_numerator,
            threshold_denominator,
        )
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use plonky2x::prelude::DefaultBuilder;

    use super::*;

    const VALIDATOR_SET_SIZE_MAX: usize = 4;

    #[test]
    fn test_accumulate_voting_power() {
        let test_cases = [
            // voting power, enabled, pass
            (vec![10i64, 10i64, 10i64, 10i64], [1, 1, 1, 0], true),
            (vec![10i64, 10i64, 10i64, 10i64], [1, 1, 1, 1], true),
            (
                vec![4294967296000i64, 4294967296i64, 10i64, 10i64],
                [1, 0, 0, 0],
                true,
            ),
            (
                vec![4294967296000i64, 4294967296000i64, 4294967296000i64, 0i64],
                [1, 1, 0, 0],
                true,
            ),
            (
                vec![4294967296000i64, 4294967296000i64, 4294967296000i64, 0i64],
                [0, 0, 0, 0],
                false,
            ),
        ];

        // Define the circuit
        let mut builder = DefaultBuilder::new();
        let mut validator_voting_power_vec = Vec::new();
        let mut validator_enabled_vec = Vec::new();
        for _ in 0..VALIDATOR_SET_SIZE_MAX {
            validator_voting_power_vec.push(builder.read::<U64Variable>());
            validator_enabled_vec.push(builder.read::<BoolVariable>());
        }
        let total_voting_power = builder.read::<U64Variable>();
        let threshold_numerator = builder.read::<U64Variable>();
        let threshold_denominator = builder.read::<U64Variable>();
        let result = builder.check_voting_power::<VALIDATOR_SET_SIZE_MAX>(
            &validator_voting_power_vec,
            &validator_enabled_vec,
            &total_voting_power,
            &threshold_numerator,
            &threshold_denominator,
        );
        builder.write(result);

        let circuit = builder.build();

        // These test cases should pass
        for test_case in test_cases {
            let mut input = circuit.input();

            let mut total_vp = 0;
            for i in 0..VALIDATOR_SET_SIZE_MAX {
                let voting_power = test_case.0[i];
                total_vp += voting_power;
                input.write::<U64Variable>((voting_power as u64).into());
                input.write::<BoolVariable>(test_case.1[i] == 1);
            }
            input.write::<U64Variable>((total_vp as u64).into());
            input.write::<U64Variable>(2.into());
            input.write::<U64Variable>(3.into());

            let (_, mut output) = circuit.prove(&input);
            assert_eq!(output.read::<BoolVariable>(), test_case.2);
        }
    }
}
