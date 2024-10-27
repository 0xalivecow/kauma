use anyhow::{Ok, Result};

pub fn xor_bytes(vec1: &Vec<u8>, mut vec2: Vec<u8>) -> Result<Vec<u8>> {
    for (byte1, byte2) in vec1.iter().zip(vec2.iter_mut()) {
        *byte2 ^= byte1;
    }

    Ok(vec2)
}

#[derive(Debug)]
pub struct ByteArray(pub Vec<u8>);

impl ByteArray {
    pub fn left_shift(&mut self) -> u8 {
        let mut carry = 0u8;
        for byte in self.0.iter_mut() {
            let new_carry = *byte >> 7;
            *byte = (*byte << 1) | carry;
            carry = new_carry;
        }
        carry
    }

    pub fn right_shift(&mut self) -> u8 {
        let mut carry = 0u8;
        for byte in self.0.iter_mut().rev() {
            let new_carry = *byte & 1;
            *byte = (*byte >> 1) | (carry << 7);
            carry = new_carry;
        }
        carry
    }

    pub fn xor_byte_arrays(&mut self, vec2: &ByteArray) {
        self.0
            .iter_mut()
            .zip(vec2.0.iter())
            .for_each(|(x1, x2)| *x1 ^= *x2);
    }

    pub fn LSB_is_one(&self) -> bool {
        (self.0.first().unwrap() & 1) == 1
    }

    pub fn is_empty(&self) -> bool {
        for i in self.0.iter() {
            if *i != 0 {
                return false;
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_byte_array_shift1() {
        let mut byte_array: ByteArray = ByteArray(vec![0x00, 0x01]);
        let shifted_array: ByteArray = ByteArray(vec![0x00, 0x02]);
        byte_array.left_shift();

        assert_eq!(byte_array.0, shifted_array.0);
    }

    #[test]
    fn test_byte_array_shift2() {
        let mut byte_array: ByteArray = ByteArray(vec![0xFF, 0x00]);
        let shifted_array: ByteArray = ByteArray(vec![0xFE, 0x01]);
        byte_array.left_shift();

        assert_eq!(
            byte_array.0, shifted_array.0,
            "Failure: Shifted array was: {:?}",
            byte_array.0
        );
    }

    #[test]
    fn test_byte_array_shift_right() {
        let mut byte_array: ByteArray = ByteArray(vec![0x02]);
        let shifted_array: ByteArray = ByteArray(vec![0x01]);
        byte_array.right_shift();

        assert_eq!(
            byte_array.0, shifted_array.0,
            "Failure: Shifted array was: {:?}",
            byte_array.0
        );
    }

    #[test]
    fn test_lsb_one() {
        let mut byte_array: ByteArray = ByteArray(vec![0x00, 0xFF]);
        assert!(!byte_array.LSB_is_one());

        let mut byte_array2: ByteArray = ByteArray(vec![0x02, 0xFF]);
        assert!(!byte_array2.LSB_is_one());

        let mut byte_array3: ByteArray = ByteArray(vec![0xFF, 0x00]);
        assert!(byte_array3.LSB_is_one());
    }

    #[test]
    fn test_byte_xor() {
        let mut byte_array: ByteArray = ByteArray(vec![0x25, 0x25]);
        let byte_array2: ByteArray = ByteArray(vec![0x55, 0x55]);

        byte_array.xor_byte_arrays(&byte_array2);

        assert_eq!(byte_array.0, vec![0x70, 0x70]);
    }

    #[test]
    fn test_byte_xor2() {
        let mut byte_array: ByteArray = ByteArray(vec![0x00, 0x00]);
        let byte_array2: ByteArray = ByteArray(vec![0x55, 0x55]);

        byte_array.xor_byte_arrays(&byte_array2);

        assert_eq!(byte_array.0, vec![0x55, 0x55]);
    }
}
