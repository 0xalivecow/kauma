use anyhow::{anyhow, Result};
use base64::prelude::*;
use serde_json::Value;

use crate::utils::ciphers::gcm_encrypt_aes;

pub fn gcm_encrypt(args: &Value) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>)> {
    let nonce_text: String = serde_json::from_value(args["nonce"].clone())?;
    let nonce = BASE64_STANDARD.decode(nonce_text)?;

    let key_text: String = serde_json::from_value(args["key"].clone())?;
    let key = BASE64_STANDARD.decode(key_text)?;

    let plaintext_text: String = serde_json::from_value(args["plaintext"].clone())?;
    let plaintext = BASE64_STANDARD.decode(plaintext_text)?;

    let ad_text: String = serde_json::from_value(args["ad"].clone())?;
    let ad = BASE64_STANDARD.decode(ad_text)?;

    let alg_text: String = serde_json::from_value(args["algorithm"].clone())?;

    match alg_text.as_str() {
        "aes128" => Ok(gcm_encrypt_aes(nonce, key, plaintext, ad)?),
        _ => Err(anyhow!("No compatible algorithm found")),
    }
}
