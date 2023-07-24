use plonky2::{
    hash::hash_types::RichField,
    iop::target::{BoolTarget},
    plonk::circuit_builder::CircuitBuilder,
};
use plonky2::field::extension::Extendable;
use plonky2_gadgets::num::u32::gadgets::arithmetic_u32::U32Target;


pub trait U32Builder {
    fn u32_to_bits_le(&mut self, num: U32Target) -> [BoolTarget; 32];
}

impl<F: RichField + Extendable<D>, const D: usize> U32Builder for CircuitBuilder<F, D> {
    fn u32_to_bits_le(&mut self, byte: U32Target) -> [BoolTarget; 32] {
        // Note: The gate being used under the hood here is probably unoptimized for this usecase.
        // In particular, we can "batch decompose" the bits to fill the entire width of the table.
        let mut res = [self._false(); 32];
        let bits = self.split_le(byte.0, 32);
        for i in 0..32 {
            res[i] = bits[i];
        }
        return res;
    }
}
