use base64::prelude::*;
use std::{u128, u8, usize};

use std::{
    cmp::Ordering,
    ops::{Add, BitXor, Div, Mul},
};

use anyhow::{anyhow, Ok, Result};

use crate::utils::poly::bgfmul;

use super::poly::polynomial_2_block;
use super::{
    math::{reverse_bits_in_bytevec, xor_bytes},
    poly::gfmul,
};

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct FieldElement {
    field_element: Vec<u8>,
}

impl FieldElement {
    pub const IRREDUCIBLE_POLYNOMIAL: [u8; 17] = [
        0x87, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 0x01,
    ];

    pub fn rand() -> Self {
        let rand_field: [u8; 16] = rand::random();
        FieldElement::new_no_convert(rand_field.to_vec())
    }

    pub fn zero() -> Self {
        FieldElement::new_no_convert(vec![0; 16])
    }

    pub fn one() -> Self {
        FieldElement::new_no_convert(vec![0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
    }

    pub fn new(field_element: Vec<u8>) -> Self {
        Self {
            field_element: reverse_bits_in_bytevec(field_element),
        }
    }

    pub fn new_no_convert(field_element: Vec<u8>) -> Self {
        Self { field_element }
    }

    pub fn mul(&self, poly_a: Vec<u8>, poly_b: Vec<u8>) -> Result<Vec<u8>> {
        gfmul(&poly_a, &poly_b, "gcm")
    }

    pub fn to_b64(&self) -> String {
        BASE64_STANDARD.encode(reverse_bits_in_bytevec(self.field_element.to_owned()))
    }

    pub fn pow(mut self, mut exponent: u128) -> FieldElement {
        let mut result: FieldElement = FieldElement::one();

        if exponent == 1 {
            return self;
        }

        if exponent == 0 {
            let result = FieldElement::one();

            return result;
        }

        //eprintln!("Initial result: {:?}", result);
        while exponent > 0 {
            //eprintln!("Current exponent: {:02X}", exponent);
            if exponent & 1 == 1 {
                let temp = &self * &result;
                //eprintln!("Mult");
                //eprintln!("After mod: {:?}", temp);

                result = temp
            }
            let temp_square = &self * &self;
            // eprintln!("Square");

            // eprintln!("After squaring: {:?}", temp_square);
            self = temp_square;
            //eprintln!("After mod: {:?}", self);
            exponent >>= 1;
        }

        // eprintln!("result in powmod before reduction: {:02X?}", result);

        // eprintln!("result in powmod after reduction: {:02X?}", result);

        result
    }

    pub fn inv(mut self) -> Self {
        const INVERSER_START: u128 = 0xfffffffffffffffffffffffffffffffe;

        let mut inverser = INVERSER_START;
        let mut inverse: Vec<u8> = vec![0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        //eprintln!("Inverse start {:02X?}", inverse);

        while inverser > 0 {
            //eprintln!("{:02X}", inverser);
            if inverser & 1 == 1 {
                inverse = gfmul(&self.field_element, &inverse, "xex").unwrap();
            }
            inverser >>= 1;
            self.field_element = gfmul(&self.field_element, &self.field_element, "xex")
                .expect("Error in sqrmul sqr");
        }
        //eprintln!("Inverse rhs {:?}", inverse);
        FieldElement::new_no_convert(inverse)
    }

    pub fn is_zero(&self) -> bool {
        self.field_element.iter().all(|&x| x == 0x00)
    }

    pub fn reverse_bits(&self) -> Self {
        FieldElement::new_no_convert(reverse_bits_in_bytevec(self.field_element.clone()))
    }
}

impl Mul for FieldElement {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        FieldElement::new_no_convert(
            gfmul(&self.field_element, &rhs.field_element, "xex")
                .expect("Error during multiplication"),
        )
    }
}

impl Mul for &FieldElement {
    type Output = FieldElement;

    fn mul(self, rhs: &FieldElement) -> FieldElement {
        FieldElement::new_no_convert(
            gfmul(&self.field_element, &rhs.field_element, "xex")
                .expect("Error during multiplication"),
        )
    }
}

impl Add for FieldElement {
    type Output = Self;
    fn add(self, rhs: Self) -> Self::Output {
        FieldElement::new_no_convert(
            xor_bytes(&self.field_element, rhs.field_element).expect("Error in poly add"),
        )
    }
}

impl Add for &FieldElement {
    type Output = FieldElement;
    fn add(self, rhs: Self) -> Self::Output {
        FieldElement::new_no_convert(
            xor_bytes(&self.field_element, rhs.field_element.clone()).expect("Error in poly add"),
        )
    }
}

impl AsRef<[u8]> for FieldElement {
    fn as_ref(&self) -> &[u8] {
        &self.field_element.as_ref()
    }
}

impl Clone for FieldElement {
    fn clone(&self) -> Self {
        FieldElement {
            field_element: self.field_element.clone(),
        }
    }
}

impl BitXor for FieldElement {
    type Output = Self;
    fn bitxor(self, rhs: Self) -> Self::Output {
        let result: Vec<u8> = self
            .field_element
            .iter()
            .zip(rhs.field_element.iter())
            .map(|(&x1, &x2)| x1 ^ x2)
            .collect();
        FieldElement::new_no_convert(result)
    }
}

impl Div for FieldElement {
    type Output = Self;
    fn div(self, rhs: Self) -> Self::Output {
        let inverse = rhs.inv();
        self * inverse
    }
}

impl Div for &FieldElement {
    type Output = FieldElement;

    fn div(self, rhs: Self) -> Self::Output {
        self.clone() * rhs.clone().inv()
    }
}

impl PartialOrd for FieldElement {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        for (byte_a, byte_b) in self.as_ref().iter().rev().zip(other.as_ref().iter().rev()) {
            if byte_a > byte_b {
                return Some(Ordering::Greater);
            } else if byte_a < byte_b {
                return Some(Ordering::Less);
            } else {
                continue;
            }
        }
        Some(Ordering::Equal)
    }
}

impl PartialEq for FieldElement {
    fn eq(&self, other: &Self) -> bool {
        self.field_element == other.field_element
    }
}

impl Eq for FieldElement {
    // add code here
}

impl Ord for FieldElement {
    fn cmp(&self, other: &Self) -> Ordering {
        for (byte_a, byte_b) in self.as_ref().iter().rev().zip(other.as_ref().iter().rev()) {
            if byte_a > byte_b {
                return Ordering::Greater;
            } else if byte_a < byte_b {
                return Ordering::Less;
            } else {
                continue;
            }
        }
        Ordering::Equal
    }
}

#[derive(Debug)]
pub struct ByteArray(pub Vec<u8>);

impl ByteArray {
    pub fn left_shift(&mut self, semantic: &str) -> Result<u8> {
        match semantic {
            "xex" => {
                let mut carry = 0u8;
                for byte in self.0.iter_mut() {
                    let new_carry = *byte >> 7;
                    *byte = (*byte << 1) | carry;
                    carry = new_carry;
                }
                Ok(carry)
            }
            "gcm" => {
                let mut carry = 0u8;
                for byte in self.0.iter_mut() {
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
                self.0 = gfmul(&self.0, &alpha_poly, "xex").unwrap();
            }
            "gcm" => {
                let alpha_poly: Vec<u8> = base64::prelude::BASE64_STANDARD
                    .decode("AgAAAAAAAAAAAAAAAAAAAA==")
                    .expect("Decode failed");
                self.0 = gfmul(&self.0, &alpha_poly, "gcm").unwrap();
            }
            _ => {}
        }
    }

    pub fn right_shift(&mut self, semantic: &str) -> Result<u8> {
        match semantic {
            "xex" => {
                let mut carry = 0u8;
                for byte in self.0.iter_mut().rev() {
                    let new_carry = *byte & 1;
                    *byte = (*byte >> 1) | (carry << 7);
                    carry = new_carry;
                }
                Ok(carry)
            }
            "gcm" => {
                let mut carry = 0u8;
                for byte in self.0.iter_mut().rev() {
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
        self.0
            .iter_mut()
            .zip(vec2.0.iter())
            .for_each(|(x1, x2)| *x1 ^= *x2);
    }

    pub fn LSB_is_one(&self) -> bool {
        (self.0.first().unwrap() & 1) == 1
    }

    pub fn msb_is_one(&self) -> bool {
        (self.0.last().unwrap() & 1) == 1
    }

    pub fn is_empty(&self) -> bool {
        for i in self.0.iter() {
            if *i != 0 {
                return false;
            }
        }
        true
    }

    pub fn reverse_bits_in_bytevec(&mut self) {
        self.0 = self.0.iter_mut().map(|byte| byte.reverse_bits()).collect();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_byte_array_shift1() {
        let mut byte_array: ByteArray = ByteArray(vec![0x00, 0x01]);
        let shifted_array: ByteArray = ByteArray(vec![0x00, 0x02]);
        byte_array.left_shift("xex").unwrap();

        assert_eq!(byte_array.0, shifted_array.0);
    }

    #[test]
    fn test_byte_array_shift2() {
        let mut byte_array: ByteArray = ByteArray(vec![0xFF, 0x00]);
        let shifted_array: ByteArray = ByteArray(vec![0xFE, 0x01]);
        byte_array.left_shift("xex").unwrap();

        assert_eq!(
            byte_array.0, shifted_array.0,
            "Failure: Shifted array was: {:?}",
            byte_array.0
        );
    }

    #[test]
    fn test_byte_array_shift1_gcm() {
        let mut byte_array: ByteArray = ByteArray(vec![0xFF, 0x00]);
        let shifted_array: ByteArray = ByteArray(vec![0x7F, 0x80]);
        byte_array.left_shift("gcm").unwrap();

        assert_eq!(
            byte_array.0, shifted_array.0,
            "Failure: Shifted array was: {:02X?}",
            byte_array.0
        );
    }

    #[test]
    fn test_byte_array_shift1_right_gcm() {
        let mut byte_array: ByteArray = ByteArray(vec![0xFF, 0x00]);
        let shifted_array: ByteArray = ByteArray(vec![0xFE, 0x00]);
        byte_array.right_shift("gcm").unwrap();

        assert_eq!(
            byte_array.0, shifted_array.0,
            "Failure: Shifted array was: {:02X?}",
            byte_array.0
        );
    }

    #[test]
    fn test_byte_array_shift_right() {
        let mut byte_array: ByteArray = ByteArray(vec![0x02]);
        let shifted_array: ByteArray = ByteArray(vec![0x01]);
        byte_array.right_shift("xex").unwrap();

        assert_eq!(
            byte_array.0, shifted_array.0,
            "Failure: Shifted array was: {:?}",
            byte_array.0
        );
    }

    #[test]
    fn test_lsb_one() {
        let byte_array: ByteArray = ByteArray(vec![0x00, 0xFF]);
        assert!(!byte_array.LSB_is_one());

        let byte_array2: ByteArray = ByteArray(vec![0x02, 0xFF]);
        assert!(!byte_array2.LSB_is_one());

        let byte_array3: ByteArray = ByteArray(vec![0xFF, 0x00]);
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

    #[test]
    fn test_field_add_01() {
        let element1: FieldElement =
            FieldElement::new(BASE64_STANDARD.decode("NeverGonnaGiveYouUpAAA==").unwrap());
        let element2: FieldElement =
            FieldElement::new(BASE64_STANDARD.decode("KryptoanalyseAAAAAAAAA==").unwrap());
        let sum = element2 + element1;

        assert_eq!(sum.to_b64(), "H1d3GuyA9/0OxeYouUpAAA==");
    }

    #[test]
    fn test_field_add_02() {
        let element1: FieldElement =
            FieldElement::new(BASE64_STANDARD.decode("NeverGonnaLetYouDownAA==").unwrap());
        let element2: FieldElement =
            FieldElement::new(BASE64_STANDARD.decode("DHBWMannheimAAAAAAAAAA==").unwrap());
        let sum = element2 + element1;

        assert_eq!(sum.to_b64(), "OZuIncPAGEp4tYouDownAA==");
    }

    #[test]
    fn test_field_div_01() {
        let element1 =
            FieldElement::new(BASE64_STANDARD.decode("JAAAAAAAAAAAAAAAAAAAAA==").unwrap());

        let element2 =
            FieldElement::new(BASE64_STANDARD.decode("wAAAAAAAAAAAAAAAAAAAAA==").unwrap());

        let result = element1 / element2;

        assert_eq!(result.to_b64(), "OAAAAAAAAAAAAAAAAAAAAA==");
    }
}
