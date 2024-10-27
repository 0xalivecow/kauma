use anyhow::{anyhow, Result};
use base64::prelude::*;
use serde_json::Value;

use crate::utils::ciphers::{sea_128_decrypt, sea_128_encrypt};

pub fn sea128(args: &Value) -> Result<String> {
    let key_string: String = serde_json::from_value(args["key"].clone())?;
    //let key: &[u8] = b64_2_num(key_string)?.to_ne_bytes();
    let key = BASE64_STANDARD.decode(key_string)?;
    //eprintln!("{:?}", key);
    let input_string: String = serde_json::from_value(args["input"].clone())?;
    //let plaintexts: &[u8] = &b64_2_num(plaintexts_string)?.to_ne_bytes();
    let input = BASE64_STANDARD.decode(input_string)?;
    let xor_val: u128 = 0xc0ffeec0ffeec0ffeec0ffeec0ffee11;

    let mode: String = serde_json::from_value(args["mode"].clone())?;
    match mode.as_str() {
        "encrypt" => {
            //eprintln!("{:?}", plaintexts);

            let output = BASE64_STANDARD.encode(sea_128_encrypt(&key, &input)?);

            Ok(output)
        }
        "decrypt" => {
            let output = BASE64_STANDARD.encode(sea_128_decrypt(&key.into(), &input)?);

            Ok(output)
        }
        _ => Err(anyhow!("Failure. no valid mode detected")),
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use anyhow::Result;
    use serde_json::json;
    // Note this useful idiom: importing names from outer (for mod tests) scope.
    use super::*;

    #[test]
    fn test_sea128_encrypt() -> Result<()> {
        let args = json!({"mode" : "encrypt", "key" : "istDASeincoolerKEYrofg==", "input" : "yv66vvrO263eyviIiDNEVQ=="});

        assert_eq!(sea128(&args)?, "D5FDo3iVBoBN9gVi9/MSKQ==");

        Ok(())
    }

    #[test]
    fn test_sea128_decrypt() -> Result<()> {
        let args = json!({"mode" : "decrypt", "key" : "istDASeincoolerKEYrofg==", "input" : "D5FDo3iVBoBN9gVi9/MSKQ=="});

        assert_eq!(sea128(&args)?, "yv66vvrO263eyviIiDNEVQ==");

        Ok(())
    }
}
