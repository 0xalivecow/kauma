use crate::utils::poly::gfmul;

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

    use crate::utils::math::reverse_bits_in_bytevec;

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

    #[test]
    fn gfmul_task_gcm01() -> Result<()> {
        let args: Value = json!({"a": "ARIAAAAAAAAAAAAAAAAAgA==", "b": "AgAAAAAAAAAAAAAAAAAAAA=="});

        let poly1_text: String = serde_json::from_value(args["a"].clone())?;
        let poly_a = reverse_bits_in_bytevec(BASE64_STANDARD.decode(poly1_text)?);

        let poly2_text: String = serde_json::from_value(args["b"].clone())?;
        let poly_b = reverse_bits_in_bytevec(BASE64_STANDARD.decode(poly2_text)?);
        let result = BASE64_STANDARD.encode(gfmul(poly_a, poly_b, "gcm")?);

        assert_eq!(
            result,
            BASE64_STANDARD.encode(reverse_bits_in_bytevec(
                BASE64_STANDARD.decode("hSQAAAAAAAAAAAAAAAAAAA==")?
            )),
            "Failure. Calulated result was: {}",
            result
        );
        Ok(())
    }
}
