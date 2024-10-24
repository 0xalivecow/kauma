use anyhow::Result;
use base64::prelude::*;
use serde_json::Value;

use crate::utils::poly::{b64_2_num, coefficient_to_binary};

pub fn gfmul(args: &Value) -> Result<String> {
    eprintln!("{args}");
    // Generate reduction polynomial
    let reduction_polynomial_coeffs: Vec<u8> = vec![7, 2, 1, 0];
    let red_poly_num: u128 = 340282366920938463463374607431768211591; //coefficient_to_binary(reduction_polynomial_coeffs);
                                                                      //eprintln!("{:?}", serde_json::from_value(args["a"].clone())?);

    let mut poly1: u128 = b64_2_num(&serde_json::from_value(args["a"].clone())?)?;
    let poly2: u128 = b64_2_num(&serde_json::from_value(args["b"].clone())?)?;
    eprintln!("poly1 is: {}", poly1);
    eprintln!("poly2 is: {}", poly2);

    /* Begin of magic algorithm
     *  poly1 = a = X = V ???
     *  poly2 = b
     *  result = Z
     */

    let mut result: u128 = 0;

    if ((poly2 >> 1) & 1) == 1 {
        eprintln!("ALHIGLIWhlighliwfhlihliawfhliawfhli");
        result ^= poly1;
    }

    for i in 2..128 {
        if ((poly2 >> i) & 1) == 1 {
            poly1 = (poly1 << 1) ^ red_poly_num;
            result ^= poly1;
        } else {
            poly1 = (poly1 << 1) ^ red_poly_num;
        }
    }

    poly1 = (poly1 << 1) ^ red_poly_num;
    result ^= poly1;

    Ok(BASE64_STANDARD.encode(result.to_ne_bytes()))
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
