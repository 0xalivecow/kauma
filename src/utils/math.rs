use anyhow::{Ok, Result};


pub fn xor_bytes(vec1: &Vec<u8>, mut vec2: Vec<u8>) -> Result<Vec<u8>> {
    for (byte1, byte2) in vec1.iter().zip(vec2.iter_mut()) {
        *byte2 ^= byte1;
    }

    Ok(vec2)
}
