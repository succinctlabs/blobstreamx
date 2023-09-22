//! The protobuf encoding of a Tendermint validator is a deterministic function of the validator's
//! public key (32 bytes) and voting power (int64). The encoding is as follows in bytes:
//
//!     10 34 10 32 <pubkey> 16 <varint>
//
//! The `pubkey` is encoded as the raw list of bytes used in the public key. The `varint` is
//! encoded using protobuf's default integer encoding, which consist of 7 bit payloads. You can
//! read more about them here: https://protobuf.dev/programming-guides/encoding/#varints.

use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::target::BoolTarget;
use plonky2::plonk::circuit_builder::CircuitBuilder as BaseBuilder;
use plonky2x::frontend::ecc::ed25519::curve::curve_types::Curve;
use plonky2x::frontend::ecc::ed25519::curve::ed25519::Ed25519;
use plonky2x::frontend::num::u32::gadgets::arithmetic_u32::{CircuitBuilderU32, U32Target};
use plonky2x::frontend::uint::uint64::U64Variable;
use plonky2x::frontend::vars::U32Variable;
use plonky2x::prelude::{BoolVariable, CircuitBuilder, PlonkParameters, Variable};

use crate::circuits::I64Target;

// TODO: remove all of this, it's all legacy

fn u64_variable_to_i64_target_legacy(a: &U64Variable) -> I64Target {
    let lower = U32Target(a.limbs[0].0 .0);
    let upper = U32Target(a.limbs[1].0 .0);

    I64Target([lower, upper])
}

fn i64_target_to_u64_variable_legacy(a: &I64Target) -> U64Variable {
    let lower = a.0[0].0;
    let upper = a.0[1].0;

    let limbs = [U32Variable(Variable(lower)), U32Variable(Variable(upper))];

    U64Variable {
        limbs,
        _marker: std::marker::PhantomData,
    }
}

fn mul_i64_by_u32<F: RichField + Extendable<D>, const D: usize>(
    api: &mut BaseBuilder<F, D>,
    a: &I64Target,
    b: U32Target,
) -> I64Target {
    // Multiply the lower 32 bits of the accumulated voting power by b
    let (lower_product, lower_carry) = api.mul_u32(a.0[0], b);

    // Multiply the upper 32 bits of the accumulated voting power by b
    let (upper_product, upper_carry) = api.mul_u32(a.0[1], b);

    // NOTE: This will limit the maximum size of numbers to (2^64 - 1) / b
    api.assert_zero_u32(upper_carry);

    // Add the carry from the lower 32 bits of the accumulated voting power to the upper 32 bits of
    // the accumulated voting power.
    let (upper_sum, upper_carry) = api.add_u32(upper_product, lower_carry);

    // Check that we did not overflow when multiplying the upper bits
    api.assert_zero_u32(upper_carry);

    I64Target([lower_product, upper_sum])
}

// Returns a >= b
fn is_i64_gte<F: RichField + Extendable<D>, const D: usize>(
    api: &mut BaseBuilder<F, D>,
    a: &I64Target,
    b: &I64Target,
) -> BoolTarget {
    // Check that the a >= b
    // 1) a_high > b_high => TRUE
    // 2) a_high == b_high
    //  a) a_low >= b_low => TRUE
    //  b) a_low < b_low => FAIL
    // 3) a_high < b_high => FAIL

    let zero_u32 = api.constant_u32(0);

    let (result_high, underflow_high) = api.sub_u32(a.0[1], b.0[1], zero_u32);

    let no_underflow_high = api.is_equal(underflow_high.0, zero_u32.0);

    // Check if upper 32 bits are equal (a_high - b_high = 0)
    let upper_equal = api.is_equal(result_high.0, zero_u32.0);

    let upper_not_equal = api.not(upper_equal);

    // Underflows if a_low < b_low
    let (_, underflow_low) = api.sub_u32(a.0[0], b.0[0], zero_u32);

    let no_underflow_low = api.is_equal(underflow_low.0, zero_u32.0);

    // Case 1)
    // If there was no underflow & a_high - b_high is not equal (i.e. positive), accumulated voting
    //  power is greater.
    let upper_pass = api.and(upper_not_equal, no_underflow_high);

    // Case 2a)
    // If a_high = b_high & a_low >= b_low, accumulated voting power is greater.
    let lower_pass = api.and(upper_equal, no_underflow_low);

    // Note: True if accumulated voting power is >= than 2/3 of the total voting power.
    api.or(upper_pass, lower_pass)
}

pub trait TendermintVotingBuilder {
    type Curve: Curve;

    /// Gets the total voting power by summing the voting power of all validators.
    fn get_total_voting_power<const VALIDATOR_SET_SIZE_MAX: usize>(
        &mut self,
        validator_voting_power: &[U64Variable],
    ) -> U64Variable;

    /// Checks if accumulated voting power * m > total voting power * n (threshold is n/m)
    fn voting_power_greater_than_threshold(
        &mut self,
        accumulated_power: &U64Variable,
        total_voting_power: &U64Variable,
        threshold_numerator: &U32Variable,
        threshold_denominator: &U32Variable,
    ) -> BoolVariable;

    /// Accumulate voting power from the enabled validators & check that the voting power is greater
    ///  than 2/3 of the total voting power.
    fn check_voting_power<const VALIDATOR_SET_SIZE_MAX: usize>(
        &mut self,
        validator_voting_power: &[U64Variable],
        validator_enabled: &[BoolVariable],
        total_voting_power: &U64Variable,
        threshold_numerator: &U32Variable,
        threshold_denominator: &U32Variable,
    ) -> BoolVariable;
}

impl<L: PlonkParameters<D>, const D: usize> TendermintVotingBuilder for CircuitBuilder<L, D> {
    type Curve = Ed25519;

    fn get_total_voting_power<const VALIDATOR_SET_SIZE_MAX: usize>(
        &mut self,
        validator_voting_power: &[U64Variable],
    ) -> U64Variable {
        let api = &mut self.api;
        let zero = api.zero();
        // Sum up the voting power of all the validators
        let validator_voting_power = validator_voting_power
            .iter()
            .map(u64_variable_to_i64_target_legacy)
            .collect::<Vec<_>>();

        let mut voting_power_low = U32Target(zero);
        let mut voting_power_high = U32Target(zero);

        // Note: We can only put a max of 80 targets into add_many_u32 (max num_routed_wires), which is why we need to split the sum into 2 chunks.
        for i in 0..2 {
            let start = (VALIDATOR_SET_SIZE_MAX / 2) * i;
            let end = (VALIDATOR_SET_SIZE_MAX / 2) * (i + 1);
            let validator_voting_power_first = validator_voting_power[start..end]
                .iter()
                .map(|x| x.0[0])
                .collect::<Vec<_>>();

            let (sum_lower_low, sum_lower_high) = api.add_many_u32(&validator_voting_power_first);

            let validator_voting_power_second = validator_voting_power[start..end]
                .iter()
                .map(|x| x.0[1])
                .collect::<Vec<_>>();

            let (sum_upper_low, sum_upper_high) = api.add_many_u32(&validator_voting_power_second);

            api.assert_zero_u32(sum_upper_high);

            let (carry_sum_low, carry_sum_high) = api.add_u32(sum_lower_high, sum_upper_low);

            api.assert_zero_u32(carry_sum_high);

            // Sum the voting power of the second chunk of validators and add it to the first.

            let (sum_lower_low, sum_lower_high) = api.add_u32(sum_lower_low, voting_power_low);

            let (sum_upper_low, sum_upper_high) = api.add_u32(carry_sum_low, voting_power_high);

            api.assert_zero_u32(sum_upper_high);

            let (carry_sum_low, carry_sum_high) = api.add_u32(sum_lower_high, sum_upper_low);

            api.assert_zero_u32(carry_sum_high);

            voting_power_low = sum_lower_low;
            voting_power_high = carry_sum_low;
        }

        i64_target_to_u64_variable_legacy(&I64Target([voting_power_low, voting_power_high]))
    }

    fn voting_power_greater_than_threshold(
        &mut self,
        accumulated_power: &U64Variable,
        total_voting_power: &U64Variable,
        threshold_numerator: &U32Variable,
        threshold_denominator: &U32Variable,
    ) -> BoolVariable {
        let api = &mut self.api;
        let accumalated_power_convert = u64_variable_to_i64_target_legacy(accumulated_power);
        let total_voting_power_convert = u64_variable_to_i64_target_legacy(total_voting_power);
        let threshold_numerator_convert = U32Target(threshold_numerator.0 .0);
        let threshold_denominator_convert = U32Target(threshold_denominator.0 .0);

        // Threshold is numerator/denominator * total_voting_power
        // Compute accumulated_voting_power * m
        let scaled_accumulated_vp = mul_i64_by_u32(
            api,
            &accumalated_power_convert,
            threshold_denominator_convert,
        );

        // Compute total_vp * n
        let scaled_total_vp = mul_i64_by_u32(
            api,
            &total_voting_power_convert,
            threshold_numerator_convert,
        );

        let res = is_i64_gte(api, &scaled_accumulated_vp, &scaled_total_vp);
        BoolVariable(Variable(res.target))
    }

    fn check_voting_power<const VALIDATOR_SET_SIZE_MAX: usize>(
        &mut self,
        validator_voting_power: &[U64Variable],
        validator_enabled: &[BoolVariable],
        total_voting_power: &U64Variable,
        threshold_numerator: &U32Variable,
        threshold_denominator: &U32Variable,
    ) -> BoolVariable {
        let api = &mut self.api;
        // Accumulate the voting power from the enabled validators.
        let mut accumulated_voting_power =
            I64Target([U32Target(api.zero()), U32Target(api.zero())]);
        for i in 0..VALIDATOR_SET_SIZE_MAX {
            let voting_power_split = validator_voting_power[i];
            let voting_power = [
                U32Target(voting_power_split.limbs[0].0 .0),
                U32Target(voting_power_split.limbs[1].0 .0),
            ];
            let enabled = U32Target(validator_enabled[i].0 .0);

            // Note: Tendermint validators max voting power is 2^63 - 1. (Should below 2^32)
            let (sum_lower_low, sum_lower_high) =
                api.mul_add_u32(voting_power[0], enabled, accumulated_voting_power.0[0]);

            let (carry_sum_low, carry_sum_high) = api.add_u32(sum_lower_high, voting_power[1]);

            // This should not overflow from carrying voting_power[1] + accumulated_voting_power[0]
            api.assert_zero_u32(carry_sum_high);

            // This should not overflow
            let (sum_upper_low, sum_upper_high) =
                api.mul_add_u32(carry_sum_low, enabled, accumulated_voting_power.0[1]);

            // Check that the upper 32 bits of the upper sum are zero.
            api.assert_zero_u32(sum_upper_high);

            accumulated_voting_power.0[0] = sum_lower_low;
            accumulated_voting_power.0[1] = sum_upper_low;
        }

        // Note: Because the threshold is n/m, max I64 should be range checked to be < 2^63 / m
        self.voting_power_greater_than_threshold(
            &i64_target_to_u64_variable_legacy(&accumulated_voting_power),
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
        let threshold_numerator = builder.read::<U32Variable>();
        let threshold_denominator = builder.read::<U32Variable>();
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
            input.write::<U32Variable>(2u32);
            input.write::<U32Variable>(3u32);

            let (_, mut output) = circuit.prove(&input);
            assert_eq!(output.read::<BoolVariable>(), test_case.2);
        }
    }
}
