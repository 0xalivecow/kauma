use anyhow::Result;
use openssl::symm::{Cipher, Crypter, Mode};

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

/*
* let mut bytes: [u8; 16] = [0u8; 16];
    bytes.copy_from_slice(&ciphertext);
    let number: u128 = <u128>::from_be_bytes(bytes);

* */
