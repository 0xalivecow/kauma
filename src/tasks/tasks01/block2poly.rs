use std::{str::Bytes, string};

use crate::utils::poly::{self, get_coefficients};
use anyhow::Result;
use base64::prelude::*;
use serde_json::Value;

pub fn block2poly(val: &Value) -> Result<Vec<u8>> {
    // Convert JSON data in to a u128
    // TODO: Transfer decoding into own function?
    eprintln!("Decoded is: {:?}", val["block"]);
    let string: String = serde_json::from_value(val["block"].clone())?;
    let decoded: Vec<u8> = BASE64_STANDARD.decode(string)?;

    let mut bytes: [u8; 16] = [0u8; 16];
    bytes.copy_from_slice(&decoded);
    let number: u128 = <u128>::from_ne_bytes(bytes);

    let coefficients: Vec<u8> = get_coefficients(number);

    Ok(coefficients)
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use std::str::FromStr;

    // Note this useful idiom: importing names from outer (for mod tests) scope.
    use super::*;

    #[test]
    fn block2poly_task01() -> Result<()> {
        let block: Value = json!({"block" : "ARIAAAAAAAAAAAAAAAAAgA=="});
        let coefficients: Vec<u8> = vec![0, 9, 12, 127];
        assert_eq!(
            block2poly(&block)?,
            coefficients,
            "Coefficients were: {:?}",
            block2poly(&block)?
        );

        Ok(())
    }
}
