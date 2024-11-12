use crate::utils::{
    field::ByteArray,
    poly::{b64_2_num, coefficient_to_binary, gfmul},
};

use anyhow::Result;
use base64::prelude::*;
use serde_json::Value;

pub fn gfmul_task(args: &Value) -> Result<Vec<u8>> {
    let poly1_text: String = serde_json::from_value(args["a"].clone())?;
    let poly_a = BASE64_STANDARD.decode(poly1_text)?;

    let poly2_text: String = serde_json::from_value(args["b"].clone())?;
    let poly_b = BASE64_STANDARD.decode(poly2_text)?;

    let semantic: String = serde_json::from_value(args["semantic"].clone())?;

    let result = gfmul(poly_a, poly_b, &semantic)?;

    Ok(result)
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

        let poly1_text: String = serde_json::from_value(args["a"].clone())?;
        let poly_a = BASE64_STANDARD.decode(poly1_text)?;

        let poly2_text: String = serde_json::from_value(args["b"].clone())?;
        let poly_b = BASE64_STANDARD.decode(poly2_text)?;

        let result = BASE64_STANDARD.encode(gfmul(poly_a, poly_b, "xex")?);

        assert_eq!(
            result, "hSQAAAAAAAAAAAAAAAAAAA==",
            "Failure. Calulated result was: {}",
            result
        );
        Ok(())
    }

    #[test]
    fn gfmul_task02() -> Result<()> {
        let args: Value = json!({"a": "AwEAAAAAAAAAAAAAAAAAgA==", "b": "gBAAAAAAAAAAAAAAAAAAAA=="});

        let poly1_text: String = serde_json::from_value(args["a"].clone())?;
        let poly_a = BASE64_STANDARD.decode(poly1_text)?;

        let poly2_text: String = serde_json::from_value(args["b"].clone())?;
        let poly_b = BASE64_STANDARD.decode(poly2_text)?;

        let result = BASE64_STANDARD.encode(gfmul(poly_a, poly_b, "xex")?);

        assert_eq!(
            result, "QKgUAAAAAAAAAAAAAAAAAA==",
            "Failure. Calulated result was: {}",
            result
        );
        Ok(())
    }

    #[test]
    fn gfmul_task03() -> Result<()> {
        let args: Value = json!({"a": "AwEAAAAAAAAAAAAAAAAAgA==", "b": "oBAAAAAAAAAAAAAAAAAAAA=="});

        let poly1_text: String = serde_json::from_value(args["a"].clone())?;
        let poly_a = BASE64_STANDARD.decode(poly1_text)?;

        let poly2_text: String = serde_json::from_value(args["b"].clone())?;
        let poly_b = BASE64_STANDARD.decode(poly2_text)?;

        let result = BASE64_STANDARD.encode(gfmul(poly_a, poly_b, "xex")?);

        assert_eq!(
            result, "UIAUAAAAAAAAAAAAAAAAAA==",
            "Failure. Calulated result was: {}",
            result
        );
        Ok(())
    }

    #[test]
    fn gfmul_task04() -> Result<()> {
        let args: Value = json!({"a": "ARIAAAAAAAAAAAAAAAAAgA==", "b": "AgAAAAAAAAAAAAAAAAAAAA=="});

        let poly1_text: String = serde_json::from_value(args["a"].clone())?;
        let poly_a = BASE64_STANDARD.decode(poly1_text)?;

        let poly2_text: String = serde_json::from_value(args["b"].clone())?;
        let poly_b = BASE64_STANDARD.decode(poly2_text)?;

        let result = BASE64_STANDARD.encode(gfmul(poly_a, poly_b, "xex")?);

        assert_eq!(
            result, "hSQAAAAAAAAAAAAAAAAAAA==",
            "Failure. Calulated result was: {}",
            result
        );
        Ok(())
    }
}
