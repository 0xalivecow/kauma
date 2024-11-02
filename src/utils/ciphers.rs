
use anyhow::Result;
use openssl::symm::{Cipher, Crypter, Mode};

use crate::utils::field::ByteArray;

use super::math::xor_bytes;

pub fn aes_128_encrypt(key: &Vec<u8>, input: &Vec<u8>) -> Result<Vec<u8>> {
    let mut encrypter = Crypter::new(Cipher::aes_128_ecb(), Mode::Encrypt, &key, None)?;
    encrypter.pad(false);

    let mut ciphertext = [0; 32].to_vec();

    let mut count = encrypter.update(input, &mut ciphertext)?;
    count += encrypter.finalize(&mut ciphertext)?;
    ciphertext.truncate(count);

    //eprintln!("{:?}", &ciphertext[..]);

    Ok(ciphertext)
}

pub fn aes_128_decrypt(key: &Vec<u8>, input: &Vec<u8>) -> Result<Vec<u8>> {
    let mut decrypter = Crypter::new(Cipher::aes_128_ecb(), Mode::Decrypt, key, None)?;
    decrypter.pad(false);

    let mut plaintext = [0; 32].to_vec();

    let mut count = decrypter.update(input, &mut plaintext)?;
    count += decrypter.finalize(&mut plaintext)?;
    plaintext.truncate(count);

    let mut bytes: [u8; 16] = [0u8; 16];
    bytes.copy_from_slice(&plaintext);
    let number: u128 = <u128>::from_be_bytes(bytes);

    Ok(plaintext)
}

pub fn sea_128_encrypt(key: &Vec<u8>, input: &Vec<u8>) -> Result<Vec<u8>> {
    let xor_val: u128 = 0xc0ffeec0ffeec0ffeec0ffeec0ffee11;
    let sea128_out = xor_bytes(
        &aes_128_encrypt(key, input)?,
        xor_val.to_be_bytes().to_vec(),
    )?;
    Ok(sea128_out)
}

pub fn sea_128_decrypt(key: &Vec<u8>, input: &Vec<u8>) -> Result<Vec<u8>> {
    let xor_val: u128 = 0xc0ffeec0ffeec0ffeec0ffeec0ffee11;

    let intermediate = xor_bytes(input, xor_val.to_be_bytes().to_vec())?;
    Ok(aes_128_decrypt(&key, &intermediate)?)
}

pub fn xex_encrypt(mut key: Vec<u8>, tweak: &Vec<u8>, input: &Vec<u8>) -> Result<Vec<u8>> {
    let key2: Vec<u8> = key.split_off(16);
    //let key1: ByteArray = ByteArray(vec![key_parts[0]]);
    //let key2: ByteArray = ByteArray(vec![key_parts[1]]);

    let input_chunks: Vec<Vec<u8>> = input.chunks(16).map(|x| x.to_vec()).collect();

    let mut output: Vec<u8> = vec![];
    //assert!(key.len() % 16 == 0, "Failure: Key len {}", key.len());
    //assert!(key2.len() % 16 == 0, "Failure: Key2 len {}", key2.len());
    let mut tweak_block: ByteArray = ByteArray(sea_128_encrypt(&key2, tweak)?);

    //dbg!("input_chunks: {:001X?}", &input_chunks);

    for chunk in input_chunks {
        let plaintext_intermediate = xor_bytes(&tweak_block.0, chunk)?;
        /*
                assert!(
                    plaintext_intermediate.len() % 16 == 0,
                    "Failure: plaintext_intermediate len was {}",
                    plaintext_intermediate.len()
                );
        */
        //assert!(key.len() % 16 == 0, "Failure: Key len {}", key.len());
        //assert!(key2.len() % 16 == 0, "Failure: Key2 len {}", key2.len());
        let cypher_block_intermediate = sea_128_encrypt(&key, &plaintext_intermediate)?;
        let mut cypher_block = xor_bytes(&tweak_block.0, cypher_block_intermediate)?;
        output.append(cypher_block.as_mut());
        tweak_block.left_shift_reduce("xex");
    }

    Ok(output)
}

pub fn xex_decrypt(mut key: Vec<u8>, tweak: &Vec<u8>, input: &Vec<u8>) -> Result<Vec<u8>> {
    let key2: Vec<u8> = key.split_off(16);
    //let key1: ByteArray = ByteArray(vec![key_parts[0]]);
    //let key2: ByteArray = ByteArray(vec![key_parts[1]]);

    let input_chunks: Vec<Vec<u8>> = input.chunks(16).map(|x| x.to_vec()).collect();

    let mut output: Vec<u8> = vec![];
    //assert!(key.len() % 16 == 0, "Failure: Key len {}", key.len());
    //assert!(key2.len() % 16 == 0, "Failure: Key2 len {}", key2.len());
    let mut tweak_block: ByteArray = ByteArray(sea_128_encrypt(&key2, tweak)?);

    for chunk in input_chunks {
        let cyphertext_intermediate = xor_bytes(&tweak_block.0, chunk)?;

        /*
        assert!(
            cyphertext_intermediate.len() % 16 == 0,
            "Failure: plaintext_intermediate len was {}",
            cyphertext_intermediate.len()
        );
        assert!(key.len() % 16 == 0, "Failure: Key len {}", key.len());
        assert!(key2.len() % 16 == 0, "Failure: Key2 len {}", key2.len());
        */
        let plaintext_block_intermediate = sea_128_decrypt(&key, &cyphertext_intermediate)?;
        let mut cypher_block = xor_bytes(&tweak_block.0, plaintext_block_intermediate)?;
        output.append(cypher_block.as_mut());
        tweak_block.left_shift_reduce("xex");
    }

    Ok(output)
}

/*
* let mut bytes: [u8; 16] = [0u8; 16];
    bytes.copy_from_slice(&ciphertext);
    let number: u128 = <u128>::from_be_bytes(bytes);

* */

#[cfg(test)]
mod tests {
    use super::*;
    use base64::prelude::*;

    #[test]
    fn test_xex_encrypt() -> Result<()> {
        let key = BASE64_STANDARD.decode("B1ygNO/CyRYIUYhTSgoUysX5Y/wWLi4UiWaVeloUWs0=")?;
        let tweak = BASE64_STANDARD.decode("6VXORr+YYHrd2nVe0OlA+Q==")?;
        let input = BASE64_STANDARD
            .decode("/aOg4jMocLkBLkDLgkHYtFKc2L9jjyd2WXSSyxXQikpMY9ZRnsJE76e9dW9olZIW")?;

        let output = BASE64_STANDARD.encode(xex_encrypt(key, &tweak, &input)?);

        assert_eq!(
            output,
            "mHAVhRCKPAPx0BcufG5BZ4+/CbneMV/gRvqK5rtLe0OJgpDU5iT7z2P0R7gEeRDO"
        );

        Ok(())
    }

    #[test]
    fn test_xex_decrypt() -> Result<()> {
        let key = BASE64_STANDARD.decode("B1ygNO/CyRYIUYhTSgoUysX5Y/wWLi4UiWaVeloUWs0=")?;
        let tweak = BASE64_STANDARD.decode("6VXORr+YYHrd2nVe0OlA+Q==")?;
        let input = BASE64_STANDARD
            .decode("lr/ItaYGFXCtHhdPndE65yg7u/GIdM9wscABiiFOUH2Sbyc2UFMlIRSMnZrYCW1a")?;

        let output = BASE64_STANDARD.encode(xex_decrypt(key, &tweak, &input)?);

        assert_eq!(
            output,
            "SGV5IHdpZSBrcmFzcyBkYXMgZnVua3Rpb25pZXJ0IGphIG9mZmVuYmFyIGVjaHQu"
        );

        Ok(())
    }

    #[test]
    fn test_xex_encrypt_empty_case() -> Result<()> {
        let key = BASE64_STANDARD.decode("B1ygNO/CyRYIUYhTSgoUysX5Y/wWLi4UiWaVeloUWs0=")?;
        let tweak = BASE64_STANDARD.decode("6VXORr+YYHrd2nVe0OlA+Q==")?;
        let input = BASE64_STANDARD.decode("")?;

        let output = BASE64_STANDARD.encode(xex_encrypt(key, &tweak, &input)?);

        assert_eq!(output, "");

        Ok(())
    }
}
