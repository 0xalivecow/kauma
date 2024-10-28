use anyhow::{anyhow, Result};
use base64::prelude::*;
use serde_json::Value;

use crate::utils::ciphers::{xex_decrypt, xex_encrypt};

pub fn fde_xex(args: &Value) -> Result<Vec<u8>> {
    let key_string: String = serde_json::from_value(args["key"].clone())?;
    let key: Vec<u8> = BASE64_STANDARD.decode(key_string)?;

    let tweak_string: String = serde_json::from_value(args["tweak"].clone())?;
    let tweak: Vec<u8> = BASE64_STANDARD.decode(tweak_string)?;

    let input_string: String = serde_json::from_value(args["input"].clone())?;
    let input: Vec<u8> = BASE64_STANDARD.decode(input_string)?;

    let mode_string: String = serde_json::from_value(args["mode"].clone())?;

    match mode_string.as_str() {
        "encrypt" => Ok(xex_encrypt(key, &tweak, &input)?),
        "decrypt" => Ok(xex_decrypt(key, &tweak, &input)?),
        _ => Err(anyhow!(
            "Failure: No compatible mode found. Data was: {:?}",
            args
        )),
    }
}
