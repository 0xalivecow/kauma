use crate::utils::poly::block_2_polynomial;
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
}
