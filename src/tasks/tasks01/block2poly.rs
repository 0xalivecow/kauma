use crate::utils::poly::{b64_2_num, block_2_polynomial, get_coefficients};
use anyhow::Result;
use base64::prelude::*;
use serde_json::Value;

pub fn block2poly(val: &Value) -> Result<Vec<u8>> {
    // Convert JSON data in to a u128
    // TODO: Transfer decoding into own function?
    let string: String = serde_json::from_value(val["block"].clone())?;
    let block = BASE64_STANDARD.decode(string)?;

    let semantic: String = serde_json::from_value(val["semantic"].clone())?;

    let coefficients: Vec<u8> = block_2_polynomial(block, &semantic)?; //get_coefficients(number);

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
        let block: Value = json!({"block" : "ARIAAAAAAAAAAAAAAAAAgA==", "semantic" : "xex"});
        let coefficients: Vec<u8> = vec![0, 9, 12, 127];
        assert_eq!(
            block2poly(&block)?,
            coefficients,
            "Coefficients were: {:?}",
            block2poly(&block)?
        );

        Ok(())
    }

    #[test]
    fn block2poly_task02() -> Result<()> {
        let block: Value = json!({"block" : "ARIAAAAAAAAAAAAAAAAAgA==", "semantic" : "gcm"});
        let coefficients: Vec<u8> = vec![7, 11, 14, 120];
        assert_eq!(
            block2poly(&block)?,
            coefficients,
            "Coefficients were: {:?}",
            block2poly(&block)?
        );

        Ok(())
    }

    #[test]
    fn block2poly_task03() -> Result<()> {
        let block: Value = json!({"block" : "AAAAAAAAAAAAAAAAAAAAAA==", "semantic" : "gcm"});
        let coefficients: Vec<u8> = vec![];
        assert_eq!(
            block2poly(&block)?,
            coefficients,
            "Coefficients were: {:?}",
            block2poly(&block)?
        );

        Ok(())
    }

    #[test]
    fn block2poly_task04() -> Result<()> {
        let block: Value = json!({"block" : "", "semantic" : "gcm"});
        let coefficients: Vec<u8> = vec![];
        assert_eq!(
            block2poly(&block)?,
            coefficients,
            "Coefficients were: {:?}",
            block2poly(&block)?
        );

        Ok(())
    }

    #[test]
    fn block2poly_task_empty_xex() -> Result<()> {
        let block: Value = json!({"block" : "", "semantic" : "xex"});
        let coefficients: Vec<u8> = vec![];
        assert_eq!(
            block2poly(&block)?,
            coefficients,
            "Coefficients were: {:?}",
            block2poly(&block)?
        );

        Ok(())
    }
}
