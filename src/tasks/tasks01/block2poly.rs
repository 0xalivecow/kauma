use crate::utils::poly;
use base64::prelude::*;

fn block2poly(block: String) {
    let num_block: u128 = BASE64_STANDARD.decode(block).unwrap().into();
    let coefficients = poly::get_bit_indices_from_byte();
}