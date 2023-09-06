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
use plonky2::{hash::hash_types::RichField, plonk::circuit_builder::CircuitBuilder};
use plonky2x::frontend::ecc::ed25519::curve::curve_types::Curve;
use plonky2x::frontend::ecc::ed25519::curve::ed25519::Ed25519;
use plonky2x::frontend::num::u32::gadgets::arithmetic_u32::{CircuitBuilderU32, U32Target};

use crate::utils::I64Target;

pub trait TendermintVoting<F: RichField + Extendable<D>, const D: usize> {
    type Curve: Curve;

    fn mul_i64_by_u32(&mut self, a: &I64Target, b: U32Target) -> I64Target;

    // Returns a >= b
    fn is_i64_gte(&mut self, a: &I64Target, b: &I64Target) -> BoolTarget;

    // Gets the total voting power by summing the voting power of all validators.
    fn get_total_voting_power<const VALIDATOR_SET_SIZE_MAX: usize>(
        &mut self,
        validator_voting_power: &Vec<I64Target>,
    ) -> I64Target;

    // Checks if accumulated voting power * m > total voting power * n (threshold is n/m)
    fn voting_power_greater_than_threshold(
        &mut self,
        accumulated_power: &I64Target,
        total_voting_power: &I64Target,
        threshold_numerator: &U32Target,
        threshold_denominator: &U32Target,
    ) -> BoolTarget;

    /// Accumulate voting power from the enabled validators & check that the voting power is greater than 2/3 of the total voting power.
    fn check_voting_power<const VALIDATOR_SET_SIZE_MAX: usize>(
        &mut self,
        validator_voting_power: &Vec<I64Target>,
        validator_enabled: &Vec<U32Target>,
        total_voting_power: &I64Target,
        threshold_numerator: &U32Target,
        threshold_denominator: &U32Target,
    ) -> BoolTarget;
}

impl<F: RichField + Extendable<D>, const D: usize> TendermintVoting<F, D> for CircuitBuilder<F, D> {
    type Curve = Ed25519;

    fn mul_i64_by_u32(&mut self, a: &I64Target, b: U32Target) -> I64Target {
        // Multiply the lower 32 bits of the accumulated voting power by b
        let (lower_product, lower_carry) = self.mul_u32(a.0[0], b);

        // Multiply the upper 32 bits of the accumulated voting power by b
        let (upper_product, upper_carry) = self.mul_u32(a.0[1], b);

        // NOTE: This will limit the maximum size of numbers to (2^64 - 1) / b
        self.assert_zero_u32(upper_carry);

        // Add the carry from the lower 32 bits of the accumulated voting power to the upper 32 bits of the accumulated voting power
        let (upper_sum, upper_carry) = self.add_u32(upper_product, lower_carry);

        // Check that we did not overflow when multiplying the upper bits
        self.assert_zero_u32(upper_carry);

        I64Target([lower_product, upper_sum])
    }

    // Returns a >= b
    fn is_i64_gte(&mut self, a: &I64Target, b: &I64Target) -> BoolTarget {
        // Check that the a >= b
        // 1) a_high > b_high => TRUE
        // 2) a_high == b_high
        //  a) a_low >= b_low => TRUE
        //  b) a_low < b_low => FAIL
        // 3) a_high < b_high => FAIL

        let zero_u32 = self.constant_u32(0);

        let (result_high, underflow_high) = self.sub_u32(a.0[1], b.0[1], zero_u32);

        let no_underflow_high = self.is_equal(underflow_high.0, zero_u32.0);

        // Check if upper 32 bits are equal (a_high - b_high = 0)
        let upper_equal = self.is_equal(result_high.0, zero_u32.0);

        let upper_not_equal = self.not(upper_equal);

        // Underflows if a_low < b_low
        let (_, underflow_low) = self.sub_u32(a.0[0], b.0[0], zero_u32);

        let no_underflow_low = self.is_equal(underflow_low.0, zero_u32.0);

        // Case 1)
        // If there was no underflow & a_high - b_high is not equal (i.e. positive), accumulated voting power is greater.
        let upper_pass = self.and(upper_not_equal, no_underflow_high);

        // Case 2a)
        // If a_high = b_high & a_low >= b_low, accumulated voting power is greater.
        let lower_pass = self.and(upper_equal, no_underflow_low);

        // Note: True if accumulated voting power is >= than 2/3 of the total voting power.
        self.or(upper_pass, lower_pass)
    }

    fn get_total_voting_power<const VALIDATOR_SET_SIZE_MAX: usize>(
        &mut self,
        validator_voting_power: &Vec<I64Target>,
    ) -> I64Target {
        // Sum up the voting power of all the validators

        let mut voting_power_low = U32Target(self.zero());
        let mut voting_power_high = U32Target(self.zero());

        // Note: We can only put a max of 80 targets into add_many_u32 (max num_routed_wires), which is why we need to split the sum into 2 chunks.
        for i in 0..2 {
            let mut validator_voting_power_first = Vec::new();
            for j in (VALIDATOR_SET_SIZE_MAX / 2) * i..(VALIDATOR_SET_SIZE_MAX / 2) * (i + 1) {
                validator_voting_power_first.push(validator_voting_power[j].0[0]);
            }

            let (sum_lower_low, sum_lower_high) =
                self.add_many_u32(&mut validator_voting_power_first);

            let mut validator_voting_power_second = Vec::new();
            for j in (VALIDATOR_SET_SIZE_MAX / 2) * i..(VALIDATOR_SET_SIZE_MAX / 2) * (i + 1) {
                validator_voting_power_second.push(validator_voting_power[j].0[1]);
            }
            let (sum_upper_low, sum_upper_high) =
                self.add_many_u32(&mut validator_voting_power_second);

            self.assert_zero_u32(sum_upper_high);

            let (carry_sum_low, carry_sum_high) = self.add_u32(sum_lower_high, sum_upper_low);

            self.assert_zero_u32(carry_sum_high);

            // Sum the voting power of the second chunk of validators and add it to the first.

            let (sum_lower_low, sum_lower_high) = self.add_u32(sum_lower_low, voting_power_low);

            let (sum_upper_low, sum_upper_high) = self.add_u32(carry_sum_low, voting_power_high);

            self.assert_zero_u32(sum_upper_high);

            let (carry_sum_low, carry_sum_high) = self.add_u32(sum_lower_high, sum_upper_low);

            self.assert_zero_u32(carry_sum_high);

            voting_power_low = sum_lower_low;
            voting_power_high = carry_sum_low;
        }

        I64Target([voting_power_low, voting_power_high])
    }

    fn voting_power_greater_than_threshold(
        &mut self,
        accumulated_power: &I64Target,
        total_voting_power: &I64Target,
        threshold_numerator: &U32Target,
        threshold_denominator: &U32Target,
    ) -> BoolTarget {
        // Threshold is numerator/denominator * total_voting_power

        // Compute accumulated_voting_power * m
        let scaled_accumulated_vp = self.mul_i64_by_u32(accumulated_power, *threshold_denominator);

        // Compute total_vp * n
        let scaled_total_vp = self.mul_i64_by_u32(total_voting_power, *threshold_numerator);

        self.is_i64_gte(&scaled_accumulated_vp, &scaled_total_vp)
    }

    fn check_voting_power<const VALIDATOR_SET_SIZE_MAX: usize>(
        &mut self,
        validator_voting_power: &Vec<I64Target>,
        validator_enabled: &Vec<U32Target>,
        total_voting_power: &I64Target,
        threshold_numerator: &U32Target,
        threshold_denominator: &U32Target,
    ) -> BoolTarget {
        // Accumulate the voting power from the enabled validators.
        let mut accumulated_voting_power =
            I64Target([U32Target(self.zero()), U32Target(self.zero())]);
        for i in 0..VALIDATOR_SET_SIZE_MAX {
            let voting_power = validator_voting_power[i];
            let enabled = validator_enabled[i];

            // Note: Tendermint validators max voting power is 2^63 - 1. (Should below 2^32)
            let (sum_lower_low, sum_lower_high) =
                self.mul_add_u32(voting_power.0[0], enabled, accumulated_voting_power.0[0]);

            let (carry_sum_low, carry_sum_high) = self.add_u32(sum_lower_high, voting_power.0[1]);

            // This should not overflow from carrying voting_power[1] + accumulated_voting_power[0]
            self.assert_zero_u32(carry_sum_high);

            // This should not overflow
            let (sum_upper_low, sum_upper_high) =
                self.mul_add_u32(carry_sum_low, enabled, accumulated_voting_power.0[1]);

            // Check that the upper 32 bits of the upper sum are zero.
            self.assert_zero_u32(sum_upper_high);

            accumulated_voting_power.0[0] = sum_lower_low;
            accumulated_voting_power.0[1] = sum_upper_low;
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
    use super::*;
    use plonky2::field::types::Field;
    use plonky2::{
        iop::witness::{PartialWitness, WitnessWrite},
        plonk::{
            circuit_builder::CircuitBuilder,
            circuit_data::CircuitConfig,
            config::{GenericConfig, PoseidonGoldilocksConfig},
        },
    };

    use plonky2x::frontend::num::u32::gadgets::arithmetic_u32::U32Target;

    use crate::utils::I64Target;

    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;
    const D: usize = 2;
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
        ];

        // These test cases should pass
        for test_case in test_cases {
            let mut pw = PartialWitness::new();
            let config = CircuitConfig::standard_recursion_config();
            let mut builder = CircuitBuilder::<F, D>::new(config);

            let mut all_validators = vec![];
            let mut validators_enabled = vec![];
            let mut total_vp = 0;
            for i in 0..test_case.0.len() {
                let voting_power = test_case.0[i];
                total_vp += voting_power;
                let voting_power_lower = voting_power & ((1 << 32) - 1);
                let voting_power_upper = voting_power >> 32;

                let voting_power_lower_target = U32Target(
                    builder.constant(F::from_canonical_usize(voting_power_lower as usize)),
                );
                let voting_power_upper_target = U32Target(
                    builder.constant(F::from_canonical_usize(voting_power_upper as usize)),
                );
                let voting_power_target =
                    I64Target([voting_power_lower_target, voting_power_upper_target]);

                all_validators.push(voting_power_target);
                validators_enabled.push(builder.constant_u32(test_case.1[i]));
            }

            let total_vp_lower = total_vp & ((1 << 32) - 1);
            let total_vp_upper = total_vp >> 32;

            println!("Lower total vp: {:?}", total_vp_lower);
            println!("Upper total vp: {:?}", total_vp_upper);

            let total_vp_lower_target =
                U32Target(builder.constant(F::from_canonical_usize(total_vp_lower as usize)));
            let total_vp_upper_target =
                U32Target(builder.constant(F::from_canonical_usize(total_vp_upper as usize)));
            let total_vp_target = I64Target([total_vp_lower_target, total_vp_upper_target]);

            let two_u32 = builder.constant_u32(2);
            let three_u32 = builder.constant_u32(3);

            let result = builder.check_voting_power::<VALIDATOR_SET_SIZE_MAX>(
                &all_validators,
                &validators_enabled,
                &total_vp_target,
                &two_u32,
                &three_u32,
            );

            pw.set_bool_target(result, test_case.2);

            let data = builder.build::<C>();
            let proof = data.prove(pw).unwrap();

            println!("Created proof");

            data.verify(proof).unwrap();

            println!("Verified proof");
        }
    }
}
