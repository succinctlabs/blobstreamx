//! Celestia's MaxTotalVotingPower = int64(math.MaxInt64) / 8
//! https://github.com/celestiaorg/celestia-core/blob/37f950717381e8d8f6393437624652693e4775b8/types/validator_set.go#L25
//! When summing the voting power of all validators, the total voting power will not overflow a u64.
//! When multiplying the total voting power by a small factor c < 16, the result will not overflow a u64.
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

    // Check if accumulated voting power > total voting power * (n / m).
    fn voting_power_greater_than_threshold(
        &mut self,
        accumulated_power: &U64Variable,
        total_voting_power: &U64Variable,
        threshold_numerator: &U64Variable,
        threshold_denominator: &U64Variable,
    ) -> BoolVariable;

    /// Accumulate voting power from the enabled validators & check the voting power is greater than 2/3 of the total voting power.
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
        // Compute accumulated_voting_power * m.
        let scaled_accumulated = self.mul(*accumulated_power, *threshold_denominator);

        // Compute total_vp * n.
        let scaled_threshold = self.mul(*total_voting_power, *threshold_numerator);

        // Check if accumulated_voting_power > total_vp * (n / m).
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

        for i in 0..VALIDATOR_SET_SIZE_MAX {
            // If the validator is enabled, add their voting power to the accumulated voting power.
            let select_voting_power =
                self.select(validator_enabled[i], validator_voting_power[i], zero);
            accumulated_voting_power = self.add(accumulated_voting_power, select_voting_power);
        }

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

        for test_case in test_cases {
            let mut input = circuit.input();

            let mut total_vp = 0;
            for i in 0..VALIDATOR_SET_SIZE_MAX {
                let voting_power = test_case.0[i];
                total_vp += voting_power;
                input.write::<U64Variable>((voting_power as u64).into());
                // If test_case.1[i] == 1, the test should pass.
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
