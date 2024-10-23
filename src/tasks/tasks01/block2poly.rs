
use crate::utils::poly::{b64_2_num, get_coefficients};
use anyhow::Result;
use serde_json::Value;

pub fn block2poly(val: &Value) -> Result<Vec<u8>> {
    // Convert JSON data in to a u128
    // TODO: Transfer decoding into own function?
    let string: String = serde_json::from_value(val["block"].clone())?;
    let number = b64_2_num(&string)?;

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
