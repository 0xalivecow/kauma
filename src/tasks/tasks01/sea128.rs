use anyhow::Result;
use base64::prelude::*;
use openssl::symm::{Cipher, Crypter, Mode};
use serde_json::Value;

use crate::utils::poly::b64_2_num;

pub fn sea128(args: &Value) -> Result<String> {
    let key_string: String = serde_json::from_value(args["key"].clone())?;
    //let key: &[u8] = b64_2_num(key_string)?.to_ne_bytes();
    let key = BASE64_STANDARD.decode(key_string)?;
    eprintln!("{:?}", key);

    let plaintexts_string: String = serde_json::from_value(args["input"].clone())?;
    //let plaintexts: &[u8] = &b64_2_num(plaintexts_string)?.to_ne_bytes();
    let plaintexts = BASE64_STANDARD.decode(plaintexts_string)?;
    eprintln!("{:?}", plaintexts);

    let xor_val: u128 = 0xc0ffeec0ffeec0ffeec0ffeec0ffee11;

    let mut encrypter = Crypter::new(Cipher::aes_128_ecb(), Mode::Encrypt, &key, None)?;
    encrypter.pad(false);

    let mut ciphertext = [0; 32].to_vec();

    let mut count = encrypter.update(&plaintexts, &mut ciphertext)?;
    count += encrypter.finalize(&mut ciphertext)?;
    ciphertext.truncate(count);

    eprintln!("{:?}", &ciphertext[..]);

    let mut bytes: [u8; 16] = [0u8; 16];
    bytes.copy_from_slice(&ciphertext);
    let number: u128 = <u128>::from_be_bytes(bytes);

    let output = BASE64_STANDARD.encode((number ^ xor_val).to_be_bytes());

    Ok(output)
}

#[cfg(test)]
mod tests {
    use std::fs;

    use anyhow::Result;
    use serde_json::json;
    // Note this useful idiom: importing names from outer (for mod tests) scope.
    use super::*;

    #[test]
    fn test_sea128() -> Result<()> {
        let args =
            json!({"key" : "istDASeincoolerKEYrofg==", "input" : "yv66vvrO263eyviIiDNEVQ=="});

        assert_eq!(sea128(&args)?, "D5FDo3iVBoBN9gVi9/MSKQ==");

        Ok(())
    }
}
