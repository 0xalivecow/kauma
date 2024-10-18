use std::str::Bytes;

use crate::utils::poly;
use base64::prelude::*;

fn block2poly(block: &str) -> Vec<u8> {
    // Convert JSON data in to a u128
    let decoded: Vec<u8> = BASE64_STANDARD.decode(block).unwrap();
    let mut bytes: [u8; 16] = [0u8; 16];
    bytes.copy_from_slice(&decoded);
    let number: u128 = <u128>::from_ne_bytes(bytes);

    let mut coefficients: Vec<u8> = vec![];

    for shift in 0..128 {
        //println!("{:?}", ((num >> shift) & 1));
        if (((number >> shift) & 1) == 1) {
            println!("Shift success");
            coefficients.push(shift);
        }
    }

    //Legacy code. 
    // TODO: Remove
    /*
    let mut counter: u8 = 0;
    let mut coefficients: Vec<u8> = vec![];
    for blk in decoded {
        let indices: Vec<u8> = poly::get_bit_indices_from_byte(blk);
        for index in indices {
            coefficients.push(counter*8+index);
        }
        counter += 1;
    }
    */
    coefficients
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    // Note this useful idiom: importing names from outer (for mod tests) scope.
    use super::*;

    #[test]
    fn block2poly_task01() {
        let block: &str = "ARIAAAAAAAAAAAAAAAAAgA==";
        let coefficients: Vec<u8> = vec![0, 9, 12, 127];
        assert_eq!(block2poly(block), coefficients);
    }
}