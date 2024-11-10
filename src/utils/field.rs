use std::{
    env::args,
    ops::{Add, Mul},
};

use anyhow::{anyhow, Ok, Result};
use base64::prelude::*;
use serde_json::Value;

use super::{math::xor_bytes, poly::gfmul};

#[derive(Debug)]
pub struct Polynomial {
    polynomial: Vec<FieldElement>,
}

impl Polynomial {
    pub const fn new(polynomial: Vec<FieldElement>) -> Self {
        Self { polynomial }
    }

    pub fn from_c_array(array: &Value) -> Self {
        let mut polynomial: Vec<FieldElement> = vec![];
        let c_array: Vec<String> = array
            .as_array()
            .expect("Input is not an array")
            .iter()
            .map(|x| {
                x.as_str()
                    .expect("Array element is not a string")
                    .to_string()
            })
            .collect();

        eprintln!("{:?}", c_array);

        for coefficient in c_array {
            polynomial.push(FieldElement::new(
                BASE64_STANDARD
                    .decode(coefficient)
                    .expect("Error on poly decode:"),
            ));
        }
        Self { polynomial }
    }

    pub fn to_c_array(self) -> Vec<String> {
        let mut output: Vec<String> = vec![];
        for coeff in self.polynomial {
            output.push(BASE64_STANDARD.encode(coeff));
        }

        output
    }
}

impl Mul for Polynomial {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        let mut polynomial: Vec<FieldElement> =
            vec![FieldElement::new(vec![0; 16]); self.polynomial.len() + rhs.polynomial.len() - 1];
        for i in 0..self.polynomial.len() {
            for j in 0..rhs.polynomial.len() {
                polynomial[i + j] = &polynomial[i + j]
                    + &(self.polynomial.get(i).unwrap() * rhs.polynomial.get(j).unwrap());
            }
        }
        Polynomial::new(polynomial)
    }
}

impl Add for Polynomial {
    type Output = Self;
    fn add(self, rhs: Self) -> Self::Output {
        FieldElement::new(
            xor_bytes(&self.field_element, rhs.field_element).expect("Error in poly add"),
        )
    }
}

/*
impl Add for Polynomial {
    type Output = Self;
    fn add(self, rhs: Self) -> Self::Output {
        FieldElement::new(
            xor_bytes(&self.field_element, rhs.field_element).expect("Error in poly add"),
        )
    }
}

impl AsRef<[u8]> for Polynomial {
    fn as_ref(&self) -> &[u8] {
        &self.field_element.as_ref()
    }
}
*/

#[derive(Debug)]
pub struct FieldElement {
    field_element: Vec<u8>,
}

impl FieldElement {
    pub const IRREDUCIBLE_POLYNOMIAL: [u8; 17] = [
        87, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 01,
    ];

    pub const fn new(field_element: Vec<u8>) -> Self {
        Self { field_element }
    }

    pub fn mul(&self, poly_a: Vec<u8>, poly_b: Vec<u8>) -> Result<Vec<u8>> {
        gfmul(poly_a, poly_b, "gcm")
    }
}

impl Mul for FieldElement {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        FieldElement::new(
            gfmul(self.field_element, rhs.field_element, "gcm")
                .expect("Error during multiplication"),
        )
    }
}

impl Mul for &FieldElement {
    type Output = FieldElement;

    fn mul(self, rhs: &FieldElement) -> FieldElement {
        FieldElement::new(
            gfmul(self.field_element.clone(), rhs.field_element.clone(), "gcm")
                .expect("Error during multiplication"),
        )
    }
}

impl Add for FieldElement {
    type Output = Self;
    fn add(self, rhs: Self) -> Self::Output {
        FieldElement::new(
            xor_bytes(&self.field_element, rhs.field_element).expect("Error in poly add"),
        )
    }
}

impl Add for &FieldElement {
    type Output = FieldElement;
    fn add(self, rhs: Self) -> Self::Output {
        FieldElement::new(
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

/*
impl From<Vec<u8>> for FieldElement {
    fn from(item: Vec<u8>) -> Self {
        FieldElement { bytes: item }
    }
}
*/

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
                self.0 = gfmul(self.0.clone(), alpha_poly, "xex").unwrap();
            }
            "gcm" => {
                let alpha_poly: Vec<u8> = base64::prelude::BASE64_STANDARD
                    .decode("AgAAAAAAAAAAAAAAAAAAAA==")
                    .expect("Decode failed");
                self.0 = gfmul(self.0.clone(), alpha_poly, "gcm").unwrap();
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
    use base64::prelude::*;
    use serde_json::json;
    use std::fs;

    #[test]
    fn test_byte_array_shift1() {
        let mut byte_array: ByteArray = ByteArray(vec![0x00, 0x01]);
        let shifted_array: ByteArray = ByteArray(vec![0x00, 0x02]);
        byte_array.left_shift("xex");

        assert_eq!(byte_array.0, shifted_array.0);
    }

    #[test]
    fn test_byte_array_shift2() {
        let mut byte_array: ByteArray = ByteArray(vec![0xFF, 0x00]);
        let shifted_array: ByteArray = ByteArray(vec![0xFE, 0x01]);
        byte_array.left_shift("xex");

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
        byte_array.left_shift("gcm");

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
        byte_array.right_shift("gcm");

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
        byte_array.right_shift("xex");

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

        assert_eq!(BASE64_STANDARD.encode(sum), "H1d3GuyA9/0OxeYouUpAAA==");
    }

    #[test]
    fn test_field_add_02() {
        let element1: FieldElement =
            FieldElement::new(BASE64_STANDARD.decode("NeverGonnaLetYouDownAA==").unwrap());
        let element2: FieldElement =
            FieldElement::new(BASE64_STANDARD.decode("DHBWMannheimAAAAAAAAAA==").unwrap());
        let sum = element2 + element1;

        assert_eq!(BASE64_STANDARD.encode(sum), "OZuIncPAGEp4tYouDownAA==");
    }

    #[test]
    fn test_field_add_03() {
        let json1 = json!([
            "NeverGonnaGiveYouUpAAA==",
            "NeverGonnaLetYouDownAA==",
            "NeverGonnaRunAroundAAA==",
            "AndDesertYouAAAAAAAAAA=="
        ]);
        let json2 = json!(["KryptoanalyseAAAAAAAAA==", "DHBWMannheimAAAAAAAAAA=="]);
        let element1: Polynomial = Polynomial::from_c_array(&json1);
        let element2: Polynomial = Polynomial::from_c_array(&json2);

        let sum = element2 + element1;

        assert_eq!(BASE64_STANDARD.encode(sum), "OZuIncPAGEp4tYouDownAA==");
    }

    #[test]
    fn test_field_mul_01() {
        let json1 = json!([
            "JAAAAAAAAAAAAAAAAAAAAA==",
            "wAAAAAAAAAAAAAAAAAAAAA==",
            "ACAAAAAAAAAAAAAAAAAAAA=="
        ]);
        let json2 = json!(["0AAAAAAAAAAAAAAAAAAAAA==", "IQAAAAAAAAAAAAAAAAAAAA=="]);
        let element1: Polynomial = Polynomial::from_c_array(&json1);
        let element2: Polynomial = Polynomial::from_c_array(&json2);

        //eprintln!("{:?}", element1);

        let result = element1 * element2;

        eprintln!("Result = {:?}", result.to_c_array());

        assert!(false);
        //assert_eq!(BASE64_STANDARD.encode(product), "MoAAAAAAAAAAAAAAAAAAAA==");
    }
}
