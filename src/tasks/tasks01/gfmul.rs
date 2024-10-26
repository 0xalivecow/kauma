use anyhow::Result;
use base64::prelude::*;
//use num_bigint::{BigUint, ToBigUint};
use serde_json::Value;

use crate::utils::{
    math::ByteArray,
    poly::{b64_2_num, coefficient_to_binary},
};

pub const RED_POLY: u128 = 0x87000000_00000000_00000000_00000000;

pub fn gfmul(args: &Value) -> Result<String> {
    eprintln!("{args}");
    // Generate reduction polynomial
    let mut red_poly_bytes: ByteArray = ByteArray(RED_POLY.to_be_bytes().to_vec());
    eprintln!("Before push  {:01X?}", red_poly_bytes);
    red_poly_bytes.0.push(0x01);
    //red_poly_bytes.0.reverse();
    eprintln!("After push  {:01X?}", red_poly_bytes);
    //let red_poly_num = ; //coefficient_to_binary(reduction_polynomial_coeffs);
    //eprintln!("{:?}", serde_json::from_value(args["a"].clone())?);

    let poly1_text: String = serde_json::from_value(args["a"].clone())?;
    let mut poly1: ByteArray = ByteArray(BASE64_STANDARD.decode(poly1_text)?);
    poly1.0.push(0x00);
    //poly1.0.reverse();

    let poly2_text: String = serde_json::from_value(args["b"].clone())?;
    let mut poly2: ByteArray = ByteArray(BASE64_STANDARD.decode(poly2_text)?);
    poly2.0.push(0x00);
    //poly2.0.reverse();

    eprintln!("poly1 is: {:01X?}", poly1);
    eprintln!("poly2 is: {:01X?}", poly2);

    /* Begin of magic algorithm
     *  poly1 = a = X = V ???
     *  poly2 = b
     *  result = Z
     */

    let mut result: ByteArray = ByteArray(vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);

    if poly2.LSB_is_one() {
        result.xor_byte_arrays(&poly1);
        poly2.right_shift();
    } else {
        poly2.right_shift();
    }

    while !poly2.is_empty() {
        if poly2.LSB_is_one() {
            poly1.left_shift();
            poly1.xor_byte_arrays(&red_poly_bytes);
            eprintln!("Poly1 after reduction: {:01X?}", poly1);
            result.xor_byte_arrays(&poly1);
            eprintln!(
                "LSB was one; \n 
                    poly1 is {:01X?}; \n
                    poly2 is {:01X?}; \n
                    result is: {:01X?}",
                poly1.0, poly2.0, result.0
            )
        } else {
            poly1.left_shift();
            poly1.xor_byte_arrays(&red_poly_bytes);
            eprintln!(
                "LSB was 0; \n
                    poly1 is {:01X?}; \n
                    poly2 is {:01X?}; \n
                    result is: {:01X?}",
                poly1.0, poly2.0, result.0
            )
        }
        poly2.right_shift();
    }
    //result.xor_byte_arrays(&red_poly_bytes);
    //result.xor_byte_arrays(&red_poly_bytes);
    eprintln!("Result after last red {:01X?}", &result.0);

    eprintln!(
        "Should be: {:01X?}",
        ByteArray(BASE64_STANDARD.decode("hSQAAAAAAAAAAAAAAAAAAA==")?)
    );
    result.0.remove(16);
    let mut bytes: [u8; 16] = [0u8; 16];
    bytes.copy_from_slice(&result.0);

    Ok(BASE64_STANDARD.encode(bytes))
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use std::str::FromStr;

    // Note this useful idiom: importing names from outer (for mod tests) scope.
    use super::*;

    #[test]
    fn gfmul_task01() -> Result<()> {
        let args: Value = json!({"a": "ARIAAAAAAAAAAAAAAAAAgA==", "b": "AgAAAAAAAAAAAAAAAAAAAA=="});
        let result = gfmul(&args)?;
        assert_eq!(
            result, "hSQAAAAAAAAAAAAAAAAAAA==",
            "Failure. Calulated result was: {}",
            result
        );
        Ok(())
    }
}
