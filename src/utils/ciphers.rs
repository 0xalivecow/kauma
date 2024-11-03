use std::{io::BufRead, process::Output};

use anyhow::Result;
use openssl::symm::{Cipher, Crypter, Mode};

use crate::utils::{field::ByteArray, math::reverse_bits_in_bytevec, poly::gfmul};

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

pub fn gcm_encrypt_aes(
    mut nonce: Vec<u8>,
    key: Vec<u8>,
    plaintext: Vec<u8>,
    ad: Vec<u8>,
) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>)> {
    let mut ciphertext: Vec<u8> = vec![];

    let mut counter: u32 = 1;
    nonce.append(counter.to_be_bytes().to_vec().as_mut());
    //nonce.append(0u8.to_le_bytes().to_vec().as_mut());
    eprintln!("{:001X?}", nonce);

    let auth_tag_xor = aes_128_encrypt(&key, &nonce)?;

    let auth_key_h = aes_128_encrypt(&key, &0u128.to_be_bytes().to_vec())?;

    let plaintext_chunks: Vec<Vec<u8>> = plaintext.chunks(16).map(|x| x.to_vec()).collect();

    counter = 2;
    for chunk in plaintext_chunks {
        nonce.drain(12..);
        nonce.append(counter.to_be_bytes().to_vec().as_mut());

        eprintln!("{:001X?}", nonce);

        let inter1 = aes_128_encrypt(&key, &nonce)?;

        let mut inter2 = xor_bytes(&inter1, chunk.clone())?;

        ciphertext.append(inter2.as_mut());
        counter += 1;
    }

    let mut l_field: Vec<u8> = ((ad.len() * 8) as u64).to_be_bytes().to_vec();
    let mut c_len: Vec<u8> = ((ciphertext.len() * 8) as u64).to_be_bytes().to_vec();
    l_field.append(c_len.as_mut());

    let auth_tag = xor_bytes(
        &ghash(auth_key_h.clone(), ad, ciphertext.clone(), l_field.clone())?,
        auth_tag_xor,
    )?;

    Ok((ciphertext, auth_tag, l_field, auth_key_h))
}

pub fn ghash(
    auth_key_h: Vec<u8>,
    mut ad: Vec<u8>,
    mut ciphertext: Vec<u8>,
    l_field: Vec<u8>,
) -> Result<Vec<u8>> {
    let output: Vec<u8> = vec![0; 16];

    eprintln!("{:?}", (ad.len() % 16) as u8);
    eprintln!("{:001X?}", ad);

    if ad.len() % 16 != 0 {
        ad.append(vec![0u8; ad.len() % 16].as_mut());
    }

    if ciphertext.len() % 16 != 0 {
        ciphertext.append(vec![0u8; ciphertext.len() % 16].as_mut());
    }

    eprintln!("{:001X?}", ad);
    eprintln!("{:001X?}", ciphertext);

    let inter1 = xor_bytes(&output, ad)?;
    let mut inter_loop = gfmul(inter1, auth_key_h.clone(), "gcm")?;

    inter_loop = inter_loop;

    let cipher_chunks = ciphertext.chunks(16);

    for chunk in cipher_chunks {
        let inter3 = xor_bytes(&inter_loop, chunk.to_vec())?;
        inter_loop = gfmul(inter3, auth_key_h.clone(), "gcm")?;
    }

    let inter4 = xor_bytes(&inter_loop, l_field)?;
    inter_loop = gfmul(inter4, auth_key_h.clone(), "gcm")?;

    Ok(inter_loop)
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

    #[test]
    fn test_gcm_encrypt_aes() -> Result<()> {
        let nonce = BASE64_STANDARD.decode("4gF+BtR3ku/PUQci")?;
        let key = BASE64_STANDARD.decode("Xjq/GkpTSWoe3ZH0F+tjrQ==")?;
        let plaintext = BASE64_STANDARD.decode("RGFzIGlzdCBlaW4gVGVzdA==")?;
        let ad = BASE64_STANDARD.decode("QUQtRGF0ZW4=")?;

        let (ciphertext, auth_tag, l_field, auth_key_h) =
            gcm_encrypt_aes(nonce, key, plaintext, ad)?;

        eprintln!(
            "Cipher: {:001X?} \n Tag: {:001X?} \n L_Field: {:001X?} \n H: {:001X?}",
            BASE64_STANDARD.encode(&ciphertext),
            BASE64_STANDARD.encode(&auth_tag),
            BASE64_STANDARD.encode(&l_field),
            BASE64_STANDARD.encode(&auth_key_h)
        );

        assert_eq!(
            BASE64_STANDARD.encode(ciphertext),
            "ET3RmvH/Hbuxba63EuPRrw=="
        );
        assert_eq!(BASE64_STANDARD.encode(auth_tag), "Mp0APJb/ZIURRwQlMgNN/w==");
        assert_eq!(BASE64_STANDARD.encode(l_field), "AAAAAAAAAEAAAAAAAAAAgA==");
        assert_eq!(
            BASE64_STANDARD.encode(auth_key_h),
            "Bu6ywbsUKlpmZXMQyuGAng=="
        );

        Ok(())
    }
}
