use crate::utils::{field::ByteArray, poly::gfmul};
use anyhow::Result;
use base64::prelude::*;
use openssl::symm::{Cipher, Crypter, Mode};

use super::math::xor_bytes;

/// AES ENCRYPT
/// Function to perform encryption with AES ECB mode
/// Function does not use padding for blocks
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

/// AES DECRPYT
/// Function to perform decryption with AES ECB mode
/// Function does not use padding for blocks    
pub fn aes_128_decrypt(key: &Vec<u8>, input: &Vec<u8>) -> Result<Vec<u8>> {
    let mut decrypter = Crypter::new(Cipher::aes_128_ecb(), Mode::Decrypt, key, None)?;
    decrypter.pad(false);

    let mut plaintext = [0; 32].to_vec();

    let mut count = decrypter.update(input, &mut plaintext)?;
    count += decrypter.finalize(&mut plaintext)?;
    plaintext.truncate(count);

    let mut bytes: [u8; 16] = [0u8; 16];
    bytes.copy_from_slice(&plaintext);

    Ok(plaintext)
}

/// SEA ENCRYPT
/// Function to perform sea encrption.
/// At its core, the function ses the AES ENCRYPT, but then xors with a constant value of:
/// 0xc0ffeec0ffeec0ffeec0ffeec0ffee11
pub fn sea_128_encrypt(key: &Vec<u8>, input: &Vec<u8>) -> Result<Vec<u8>> {
    // Constant value used for XOR
    let xor_val: u128 = 0xc0ffeec0ffeec0ffeec0ffeec0ffee11;

    let sea128_out = xor_bytes(
        &aes_128_encrypt(key, input)?,
        xor_val.to_be_bytes().to_vec(),
    )?;
    Ok(sea128_out)
}

/// SEA DECRYPT
/// Function to perform sea decryption.
/// At its core, the function ses the AES DECRYPT, but then xors with a constant value of:
/// 0xc0ffeec0ffeec0ffeec0ffeec0ffee11
pub fn sea_128_decrypt(key: &Vec<u8>, input: &Vec<u8>) -> Result<Vec<u8>> {
    // Constant value used for XOR
    let xor_val: u128 = 0xc0ffeec0ffeec0ffeec0ffeec0ffee11;

    let intermediate = xor_bytes(input, xor_val.to_be_bytes().to_vec())?;
    Ok(aes_128_decrypt(&key, &intermediate)?)
}

/// Function to perform xex encryption.
/// The function performs the encryption for XEX on the basis of the SEA ENCRYPT.
pub fn xex_encrypt(mut key: Vec<u8>, tweak: &Vec<u8>, input: &Vec<u8>) -> Result<Vec<u8>> {
    let key2: Vec<u8> = key.split_off(16);

    let input_chunks: Vec<Vec<u8>> = input.chunks(16).map(|x| x.to_vec()).collect();

    let mut output: Vec<u8> = vec![];
    let mut tweak_block: ByteArray = ByteArray(sea_128_encrypt(&key2, tweak)?);

    for chunk in input_chunks {
        let plaintext_intermediate = xor_bytes(&tweak_block.0, chunk)?;
        let cypher_block_intermediate = sea_128_encrypt(&key, &plaintext_intermediate)?;
        let mut cypher_block = xor_bytes(&tweak_block.0, cypher_block_intermediate)?;
        output.append(cypher_block.as_mut());
        tweak_block.left_shift_reduce("xex");
    }

    Ok(output)
}

pub fn xex_decrypt(mut key: Vec<u8>, tweak: &Vec<u8>, input: &Vec<u8>) -> Result<Vec<u8>> {
    let key2: Vec<u8> = key.split_off(16);
    let input_chunks: Vec<Vec<u8>> = input.chunks(16).map(|x| x.to_vec()).collect();

    let mut output: Vec<u8> = vec![];
    let mut tweak_block: ByteArray = ByteArray(sea_128_encrypt(&key2, tweak)?);

    for chunk in input_chunks {
        let cyphertext_intermediate = xor_bytes(&tweak_block.0, chunk)?;
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

    let auth_tag_xor = aes_128_encrypt(&key, &nonce)?;

    let auth_key_h = aes_128_encrypt(&key, &0u128.to_be_bytes().to_vec())?;

    let plaintext_chunks: Vec<Vec<u8>> = plaintext.chunks(16).map(|x| x.to_vec()).collect();

    counter = 2;
    for chunk in plaintext_chunks {
        nonce.drain(12..);
        nonce.append(counter.to_be_bytes().to_vec().as_mut());

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

pub fn gcm_decrypt_aes(
    mut nonce: Vec<u8>,
    key: Vec<u8>,
    ciphertext: Vec<u8>,
    ad: Vec<u8>,
    tag: Vec<u8>,
) -> Result<(Vec<u8>, bool)> {
    let mut plaintext: Vec<u8> = vec![];

    let mut counter: u32 = 1;
    nonce.append(counter.to_be_bytes().to_vec().as_mut());
    //nonce.append(0u8.to_le_bytes().to_vec().as_mut());

    let auth_tag_xor = aes_128_encrypt(&key, &nonce)?;

    let auth_key_h = aes_128_encrypt(&key, &0u128.to_be_bytes().to_vec())?;

    let ciphertext_chunks: Vec<Vec<u8>> = ciphertext.chunks(16).map(|x| x.to_vec()).collect();

    counter = 2;
    for chunk in ciphertext_chunks {
        nonce.drain(12..);
        nonce.append(counter.to_be_bytes().to_vec().as_mut());

        let inter1 = aes_128_encrypt(&key, &nonce)?;

        let mut inter2 = xor_bytes(&inter1, chunk.clone())?;

        plaintext.append(inter2.as_mut());
        counter += 1;
    }

    let mut l_field: Vec<u8> = ((ad.len() * 8) as u64).to_be_bytes().to_vec();
    let mut c_len: Vec<u8> = ((ciphertext.len() * 8) as u64).to_be_bytes().to_vec();
    l_field.append(c_len.as_mut());

    let auth_tag = xor_bytes(
        &ghash(auth_key_h.clone(), ad, ciphertext.clone(), l_field.clone())?,
        auth_tag_xor,
    )?;

    let valid = auth_tag == tag;

    Ok((plaintext, valid))
}

pub fn gcm_encrypt_sea(
    mut nonce: Vec<u8>,
    key: Vec<u8>,
    plaintext: Vec<u8>,
    ad: Vec<u8>,
) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>)> {
    let mut ciphertext: Vec<u8> = vec![];

    let mut counter: u32 = 1;
    nonce.append(counter.to_be_bytes().to_vec().as_mut());
    //nonce.append(0u8.to_le_bytes().to_vec().as_mut());

    let auth_tag_xor = sea_128_encrypt(&key, &nonce)?;

    let auth_key_h = sea_128_encrypt(&key, &0u128.to_be_bytes().to_vec())?;

    let plaintext_chunks: Vec<Vec<u8>> = plaintext.chunks(16).map(|x| x.to_vec()).collect();

    counter = 2;
    for chunk in plaintext_chunks {
        nonce.drain(12..);
        nonce.append(counter.to_be_bytes().to_vec().as_mut());

        let inter1 = sea_128_encrypt(&key, &nonce)?;

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

pub fn gcm_decrypt_sea(
    mut nonce: Vec<u8>,
    key: Vec<u8>,
    ciphertext: Vec<u8>,
    ad: Vec<u8>,
    tag: Vec<u8>,
) -> Result<(Vec<u8>, bool)> {
    let mut plaintext: Vec<u8> = vec![];

    let mut counter: u32 = 1;
    nonce.append(counter.to_be_bytes().to_vec().as_mut());
    //nonce.append(0u8.to_le_bytes().to_vec().as_mut());

    let auth_tag_xor = sea_128_encrypt(&key, &nonce)?;

    let auth_key_h = sea_128_encrypt(&key, &0u128.to_be_bytes().to_vec())?;

    let plaintext_chunks: Vec<Vec<u8>> = ciphertext.chunks(16).map(|x| x.to_vec()).collect();

    counter = 2;
    for chunk in plaintext_chunks {
        nonce.drain(12..);
        nonce.append(counter.to_be_bytes().to_vec().as_mut());

        let inter1 = sea_128_encrypt(&key, &nonce)?;

        let mut inter2 = xor_bytes(&inter1, chunk.clone())?;

        plaintext.append(inter2.as_mut());
        counter += 1;
    }

    let mut l_field: Vec<u8> = ((ad.len() * 8) as u64).to_be_bytes().to_vec();
    let mut c_len: Vec<u8> = ((plaintext.len() * 8) as u64).to_be_bytes().to_vec();
    l_field.append(c_len.as_mut());

    let auth_tag = xor_bytes(
        &ghash(auth_key_h.clone(), ad, ciphertext.clone(), l_field.clone())?,
        auth_tag_xor,
    )?;

    let valid = auth_tag == tag;

    Ok((plaintext, valid))
}

pub fn ghash(
    auth_key_h: Vec<u8>,
    mut ad: Vec<u8>,
    mut ciphertext: Vec<u8>,
    l_field: Vec<u8>,
) -> Result<Vec<u8>> {
    let output: Vec<u8> = vec![0; 16];

    if ad.len() % 16 != 0 || ad.is_empty() {
        ad.append(vec![0u8; 16 - (ad.len() % 16)].as_mut());
    }

    if ciphertext.len() % 16 != 0 {
        ciphertext.append(vec![0u8; 16 - (ciphertext.len() % 16)].as_mut());
    }

    let mut ad_chunks = ad.chunks(16);

    let inter1 = xor_bytes(&output, ad_chunks.next().unwrap().to_vec())?;
    let mut inter_loop = gfmul(&inter1, &auth_key_h, "gcm")?;

    for chunk in ad_chunks {
        let inter2 = xor_bytes(&inter_loop, chunk.to_vec())?;
        inter_loop = gfmul(&inter2, &auth_key_h, "gcm")?;
    }

    let cipher_chunks = ciphertext.chunks(16);

    for chunk in cipher_chunks {
        let inter3 = xor_bytes(&inter_loop, chunk.to_vec())?;
        inter_loop = gfmul(&inter3, &auth_key_h, "gcm")?;
    }

    let inter4 = xor_bytes(&inter_loop, l_field)?;
    inter_loop = gfmul(&inter4, &auth_key_h, "gcm")?;

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

    #[test]
    fn test_gcm_encrypt_aes_long_ad() -> Result<()> {
        let nonce = BASE64_STANDARD.decode("yv66vvrO263eyviI")?;
        let key = BASE64_STANDARD.decode("/v/pkoZlcxxtao+UZzCDCA==")?;
        let plaintext = BASE64_STANDARD.decode(
            "2TEyJfiEBuWlWQnFr/UmmoanqVMVNPfaLkwwPYoxinIcPAyVlWgJUy/PDiRJprUlsWrt9aoN5le6Y3s5",
        )?;
        let ad = BASE64_STANDARD.decode("/u36zt6tvu/+7frO3q2+76ut2tI=")?;

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
            "QoMewiF3dCRLciG3hNDUnOOqIS8sAqTgNcF+IymsoS4h1RSyVGaTHH2PalqshKoFG6MLOWoKrJc9WOCR"
        );
        assert_eq!(BASE64_STANDARD.encode(auth_tag), "W8lPvDIhpduU+ula5xIaRw==");
        assert_eq!(BASE64_STANDARD.encode(l_field), "AAAAAAAAAKAAAAAAAAAB4A==");
        assert_eq!(
            BASE64_STANDARD.encode(auth_key_h),
            "uDtTNwi/U10KpuUpgNU7eA=="
        );

        Ok(())
    }
    /*
        * TODO:Not sure if this case can really happen in our data

        #[test]
        fn test_gcm_encrypt_aes_long_0000() -> Result<()> {
            let nonce = BASE64_STANDARD.decode(
                "kxMiXfiEBuVVkJxa/1Jpqmp6lThTT32h5MMD0qMYpyjDwMlRVoCVOfzw4kKaa1JUFq7b9aDealemN7Ob",
            )?;
            let key = BASE64_STANDARD.decode("/v/pkoZlcxxtao+UZzCDCP7/6ZKGZXMcbWqPlGcwgwg=")?;
            let plaintext = BASE64_STANDARD.decode(
                "2TEyJfiEBuWlWQnFr/UmmoanqVMVNPfaLkwwPYoxinIcPAyVlWgJUy/PDiRJprUlsWrt9aoN5le6Y3s5",
            )?;
            let ad = BASE64_STANDARD.decode("/u36zt6tvu/+7frO3q2+76ut2tI=")?;

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
                "Wo3vLwyeU/H3XXhTZZ4qIO6ysiqv3mQZoFirT290a/QPwMO3gPJERS2j6/HF2CzeokGJlyAO+C5Ern4/"
            );
            assert_eq!(BASE64_STANDARD.encode(auth_tag), "pEqCZu4cjrDItdTPWunxmg==");
            assert_eq!(BASE64_STANDARD.encode(l_field), "AAAAAAAAAKAAAAAAAAAB4A==");
            assert_eq!(
                BASE64_STANDARD.encode(auth_key_h),
                "rL7yBXm0uOvOiJushzLa1w=="
            );

            Ok(())
        }
    */
    #[test]
    fn test_gcm_encrypt_sea() -> Result<()> {
        let nonce = BASE64_STANDARD.decode("4gF+BtR3ku/PUQci")?;
        let key = BASE64_STANDARD.decode("Xjq/GkpTSWoe3ZH0F+tjrQ==")?;
        let plaintext = BASE64_STANDARD.decode("RGFzIGlzdCBlaW4gVGVzdA==")?;
        let ad = BASE64_STANDARD.decode("QUQtRGF0ZW4=")?;

        let (ciphertext, auth_tag, l_field, auth_key_h) =
            gcm_encrypt_sea(nonce, key, plaintext, ad)?;

        eprintln!(
            "Cipher: {:001X?} \n Tag: {:001X?} \n L_Field: {:001X?} \n H: {:001X?}",
            BASE64_STANDARD.encode(&ciphertext),
            BASE64_STANDARD.encode(&auth_tag),
            BASE64_STANDARD.encode(&l_field),
            BASE64_STANDARD.encode(&auth_key_h)
        );

        assert_eq!(
            BASE64_STANDARD.encode(ciphertext),
            "0cI/Wg4R3URfrVFZ0hw/vg=="
        );
        assert_eq!(BASE64_STANDARD.encode(auth_tag), "ysDdzOSnqLH0MQ+Mkb23gw==");
        assert_eq!(BASE64_STANDARD.encode(l_field), "AAAAAAAAAEAAAAAAAAAAgA==");
        assert_eq!(
            BASE64_STANDARD.encode(auth_key_h),
            "xhFcAUT66qWIpYz+Ch5ujw=="
        );

        Ok(())
    }

    #[test]
    fn test_gcm_decrypt_aes() -> Result<()> {
        let nonce = BASE64_STANDARD.decode("4gF+BtR3ku/PUQci")?;
        let key = BASE64_STANDARD.decode("Xjq/GkpTSWoe3ZH0F+tjrQ==")?;
        let ciphertext = BASE64_STANDARD.decode("ET3RmvH/Hbuxba63EuPRrw==")?;
        let ad = BASE64_STANDARD.decode("QUQtRGF0ZW4=")?;
        let tag = BASE64_STANDARD.decode("Mp0APJb/ZIURRwQlMgNN/w==")?;

        let (plaintext, valid) = gcm_decrypt_aes(nonce, key, ciphertext, ad, tag)?;

        eprintln!(
            "Cipher: {:001X?} \n Valids: {:001X?}",
            BASE64_STANDARD.encode(&plaintext),
            &valid,
        );

        assert_eq!(
            BASE64_STANDARD.encode(plaintext),
            "RGFzIGlzdCBlaW4gVGVzdA=="
        );
        assert_eq!(valid, true);

        Ok(())
    }

    #[test]
    fn test_gcm_decrypt_sea() -> Result<()> {
        let nonce = BASE64_STANDARD.decode("4gF+BtR3ku/PUQci")?;
        let key = BASE64_STANDARD.decode("Xjq/GkpTSWoe3ZH0F+tjrQ==")?;
        let ciphertext = BASE64_STANDARD.decode("0cI/Wg4R3URfrVFZ0hw/vg==")?;
        let ad = BASE64_STANDARD.decode("QUQtRGF0ZW4=")?;
        let tag = BASE64_STANDARD.decode("ysDdzOSnqLH0MQ+Mkb23gw==")?;

        let (plaintext, valid) = gcm_decrypt_sea(nonce, key, ciphertext, ad, tag)?;

        eprintln!(
            "Plaintext: {:001X?} \n Valid: {:001X?}",
            BASE64_STANDARD.encode(&plaintext),
            &valid,
        );

        assert_eq!(
            BASE64_STANDARD.encode(plaintext),
            "RGFzIGlzdCBlaW4gVGVzdA=="
        );
        assert_eq!(valid, true);

        Ok(())
    }
}
