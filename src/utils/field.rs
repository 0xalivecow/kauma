use anyhow::{anyhow, Ok, Result};
use base64::Engine;

use super::poly::gfmul;

#[derive(Debug)]
pub struct ByteArray {
    pub vector: Vec<u8>,
}

impl ByteArray {
    pub fn left_shift(&mut self, semantic: &str) -> Result<u8> {
        match semantic {
            "xex" => {
                let mut carry = 0u8;
                for byte in self.vector.iter_mut() {
                    let new_carry = *byte >> 7;
                    *byte = (*byte << 1) | carry;
                    carry = new_carry;
                }
                Ok(carry)
            }
            "gcm" => {
                let mut carry = 0u8;
                for byte in self.vector.iter_mut() {
                    let new_carry = *byte & 1;
                    *byte = (*byte >> 1) | (carry << 7);
                    carry = new_carry;
                }
                Ok(carry)
            }
            _ => Err(anyhow!("Failure in lsh. No compatible action found")),
        }
    }

    pub fn left_shift_reduce(&mut self, semantic: &str) {
        match semantic {
            "xex" => {
                let alpha_poly: Vec<u8> = base64::prelude::BASE64_STANDARD
                    .decode("AgAAAAAAAAAAAAAAAAAAAA==")
                    .expect("Decode failed");
                self.vector = gfmul(self.vector.clone(), alpha_poly, "xex").unwrap();
            }
            "gcm" => {
                let alpha_poly: Vec<u8> = base64::prelude::BASE64_STANDARD
                    .decode("AgAAAAAAAAAAAAAAAAAAAA==")
                    .expect("Decode failed");
                self.vector = gfmul(self.vector.clone(), alpha_poly, "gcm").unwrap();
            }
            _ => {}
        }
    }

    pub fn right_shift(&mut self, semantic: &str) -> Result<u8> {
        match semantic {
            "xex" => {
                let mut carry = 0u8;
                for byte in self.vector.iter_mut().rev() {
                    let new_carry = *byte & 1;
                    *byte = (*byte >> 1) | (carry << 7);
                    carry = new_carry;
                }
                Ok(carry)
            }
            "gcm" => {
                let mut carry = 0u8;
                for byte in self.vector.iter_mut().rev() {
                    let new_carry = *byte & 1;
                    *byte = (*byte << 1) | carry;
                    carry = new_carry;
                }
                Ok(carry)
            }
            _ => Err(anyhow!("Failure in rsh. No valid semantic found")),
        }
    }

    pub fn xor_byte_arrays(&mut self, vec2: &ByteArray) {
        self.vector
            .iter_mut()
            .zip(vec2.vector.iter())
            .for_each(|(x1, x2)| *x1 ^= *x2);
    }

    pub fn LSB_is_one(&self) -> bool {
        (self.vector.first().unwrap() & 1) == 1
    }

    pub fn msb_is_one(&self) -> bool {
        (self.vector.last().unwrap() & 1) == 1
    }

    pub fn is_empty(&self) -> bool {
        for i in self.vector.iter() {
            if *i != 0 {
                return false;
            }
        }
        true
    }

    pub fn append_vec(&mut self, mut other: Vec<u8>) {
        self.vector.append(other.as_mut());
    }
}

impl From<Vec<u8>> for ByteArray {
    fn from(item: Vec<u8>) -> Self {
        ByteArray { vector: item }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_byte_array_shift1() {
        let mut byte_array: ByteArray = ByteArray::from(vec![0x00, 0x01]);
        let shifted_array: ByteArray = ByteArray::from(vec![0x00, 0x02]);
        byte_array.left_shift("xex");

        assert_eq!(byte_array.vector, shifted_array.vector);
    }

    #[test]
    fn test_byte_array_shift2() {
        let mut byte_array: ByteArray = ByteArray::from(vec![0xFF, 0x00]);
        let shifted_array: ByteArray = ByteArray::from(vec![0xFE, 0x01]);
        byte_array.left_shift("xex");

        assert_eq!(
            byte_array.vector, shifted_array.vector,
            "Failure: Shifted array was: {:?}",
            byte_array.vector
        );
    }

    #[test]
    fn test_byte_array_shift1_gcm() {
        let mut byte_array: ByteArray = ByteArray::from(vec![0xFF, 0x00]);
        let shifted_array: ByteArray = ByteArray::from(vec![0x7F, 0x80]);
        byte_array.left_shift("gcm");

        assert_eq!(
            byte_array.vector, shifted_array.vector,
            "Failure: Shifted array was: {:02X?}",
            byte_array.vector
        );
    }

    #[test]
    fn test_byte_array_shift1_right_gcm() {
        let mut byte_array: ByteArray = ByteArray::from(vec![0xFF, 0x00]);
        let shifted_array: ByteArray = ByteArray::from(vec![0xFE, 0x00]);
        byte_array.right_shift("gcm");

        assert_eq!(
            byte_array.vector, shifted_array.vector,
            "Failure: Shifted array was: {:02X?}",
            byte_array.vector
        );
    }

    #[test]
    fn test_byte_array_shift_right() {
        let mut byte_array: ByteArray = ByteArray::from(vec![0x02]);
        let shifted_array: ByteArray = ByteArray::from(vec![0x01]);
        byte_array.right_shift("xex");

        assert_eq!(
            byte_array.vector, shifted_array.vector,
            "Failure: Shifted array was: {:?}",
            byte_array.vector
        );
    }

    #[test]
    fn test_lsb_one() {
        let byte_array: ByteArray = ByteArray::from(vec![0x00, 0xFF]);
        assert!(!byte_array.LSB_is_one());

        let byte_array2: ByteArray = ByteArray::from(vec![0x02, 0xFF]);
        assert!(!byte_array2.LSB_is_one());

        let byte_array3: ByteArray = ByteArray::from(vec![0xFF, 0x00]);
        assert!(byte_array3.LSB_is_one());
    }

    #[test]
    fn test_byte_xor() {
        let mut byte_array: ByteArray = ByteArray::from(vec![0x25, 0x25]);
        let byte_array2: ByteArray = ByteArray::from(vec![0x55, 0x55]);

        byte_array.xor_byte_arrays(&byte_array2);

        assert_eq!(byte_array.vector, vec![0x70, 0x70]);
    }

    #[test]
    fn test_byte_xor2() {
        let mut byte_array: ByteArray = ByteArray::from(vec![0x00, 0x00]);
        let byte_array2: ByteArray = ByteArray::from(vec![0x55, 0x55]);

        byte_array.xor_byte_arrays(&byte_array2);

        assert_eq!(byte_array.vector, vec![0x55, 0x55]);
    }
}
