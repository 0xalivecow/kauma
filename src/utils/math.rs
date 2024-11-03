use anyhow::{anyhow, Ok, Result};
use base64::Engine;

use super::poly::gfmul;

pub fn xor_bytes(vec1: &Vec<u8>, mut vec2: Vec<u8>) -> Result<Vec<u8>> {
    for (byte1, byte2) in vec1.iter().zip(vec2.iter_mut()) {
        *byte2 ^= byte1;
    }

    Ok(vec2)
}

pub fn reverse_bits_in_bytevec(mut vec: Vec<u8>) -> Vec<u8> {
    vec = vec.iter_mut().map(|byte| byte.reverse_bits()).collect();

    vec
}
