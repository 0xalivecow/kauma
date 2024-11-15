use std::ops::{Add, BitXor, Div, Mul, Sub};

use anyhow::{anyhow, Ok, Result};
use base64::prelude::*;
use serde_json::Value;

use crate::utils::poly::polynomial_2_block;

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

    pub fn pow(&self, mut exponent: u128) -> Polynomial {
        if exponent == 0 {
            return Polynomial::new(vec![FieldElement::new(
                polynomial_2_block(vec![0], "gcm").unwrap(),
            )]);
        }

        let base = self.clone();
        let mut result = base.clone();
        exponent -= 1;
        while exponent > 0 {
            result = result * base.clone();
            exponent -= 1;
        }

        result
    }

    pub fn pow_mod(mut self, mut exponent: u128, modulus: Polynomial) -> Polynomial {
        let mut result: Polynomial = Polynomial::new(vec![FieldElement::new(
            polynomial_2_block(vec![0], "gcm").unwrap(),
        )]);

        if exponent == 1 {
            return self;
        }

        if exponent == 0 {
            Polynomial::new(vec![FieldElement::new(
                polynomial_2_block(vec![1], "gcm").unwrap(),
            )])
            .div(&modulus)
            .1;
        }

        //eprintln!("Initial result: {:?}", result);
        while exponent > 0 {
            //eprintln!("Current exponent: {:02X}", exponent);
            if exponent & 1 == 1 {
                let temp = &self * &result;
                //eprintln!("After multiplication: {:?}", temp);
                result = temp.div(&modulus).1;
                //eprintln!("After mod: {:?}", result);
            }
            let temp_square = &self * &self;
            //eprintln!("After squaring: {:?}", temp_square);
            self = temp_square.div(&modulus).1;
            //eprintln!("After mod: {:?}", self);
            exponent >>= 1;
        }
        result
    }

    // Returns (quotient, remainder)
    pub fn div(self, rhs: &Self) -> (Self, Self) {
        // Div by zero check ommitted since data is guaranteed to be non 0

        eprintln!("{:?}, {:?}", self.polynomial.len(), rhs.polynomial.len());

        if self.polynomial.len() < rhs.polynomial.len() {
            return (Polynomial::new(vec![FieldElement::new(vec![0; 16])]), self);
        }

        let mut remainder = self.clone();
        let divisor = rhs;
        let dividend_deg = remainder.polynomial.len() - 1;
        let divisor_deg = divisor.polynomial.len() - 1;

        if dividend_deg < divisor_deg {
            return (
                Polynomial::new(vec![FieldElement::new(
                    polynomial_2_block(vec![0; 16], "gcm").unwrap(),
                )]),
                remainder,
            );
        }

        let mut quotient_coeffs =
            vec![
                FieldElement::new(polynomial_2_block(vec![0; 16], "gcm").unwrap());
                dividend_deg - divisor_deg + 1
            ];

        while remainder.polynomial.len() >= divisor.polynomial.len() {
            let deg_diff = remainder.polynomial.len() - divisor.polynomial.len();

            let leading_dividend = remainder.polynomial.last().unwrap();
            let leading_divisor = divisor.polynomial.last().unwrap();
            let quot_coeff = leading_dividend / leading_divisor;

            quotient_coeffs[deg_diff] = quot_coeff.clone();

            let mut subtrahend =
                vec![FieldElement::new(polynomial_2_block(vec![0; 16], "gcm").unwrap()); deg_diff];
            subtrahend.extend(
                divisor
                    .polynomial
                    .iter()
                    .map(|x| x.clone() * quot_coeff.clone()),
            );
            let subtrahend_poly = Polynomial::new(subtrahend);

            remainder = remainder + subtrahend_poly;

            while !remainder.polynomial.is_empty()
                && remainder
                    .polynomial
                    .last()
                    .unwrap()
                    .as_ref()
                    .iter()
                    .all(|&x| x == 0)
            {
                remainder.polynomial.pop();
            }
        }

        if remainder.is_empty() {
            remainder = Polynomial::new(vec![FieldElement::new(vec![0; 16])]);
        }
        (Polynomial::new(quotient_coeffs), remainder)
    }

    fn is_zero(&self) -> bool {
        for field_element in &self.polynomial {
            if !field_element.is_zero() {
                return false;
            }
        }
        true
    }
}

impl Clone for Polynomial {
    fn clone(&self) -> Self {
        Polynomial {
            polynomial: self.polynomial.clone(),
        }
    }
}

impl Mul for Polynomial {
    type Output = Self;
    fn mul(self, rhs: Self) -> Self::Output {
        if self.is_zero() || rhs.is_zero() {
            return Polynomial::new(vec![FieldElement::new(vec![0; 16])]);
        }
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

impl Mul for &Polynomial {
    type Output = Polynomial;
    fn mul(self, rhs: Self) -> Self::Output {
        if self.is_zero() || rhs.is_zero() {
            return Polynomial::new(vec![FieldElement::new(vec![0])]);
        }
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
        let mut polynomial: Vec<FieldElement>;

        if self.polynomial.len() > rhs.polynomial.len() {
            polynomial = self.polynomial.clone();
            for i in 0..rhs.polynomial.len() {
                polynomial[i] = polynomial[i].clone() + rhs.polynomial[i].clone();
            }
        } else {
            polynomial = rhs.polynomial.clone();
            for i in 0..self.polynomial.len() {
                polynomial[i] = polynomial[i].clone() + self.polynomial[i].clone();
            }
        }

        for i in (0..polynomial.len() - 1).rev() {
            if polynomial[i].is_zero() {
                polynomial.pop();
            }
        }

        Polynomial::new(polynomial)
    }
}

// Helper implementation for subtraction
impl Sub for &FieldElement {
    type Output = FieldElement;

    fn sub(self, rhs: Self) -> FieldElement {
        // In a field of characteristic 2, addition and subtraction are the same operation (XOR)
        self + rhs
    }
}

// Helper trait for checking emptiness
trait IsEmpty {
    fn is_empty(&self) -> bool;
}

impl IsEmpty for Polynomial {
    fn is_empty(&self) -> bool {
        self.polynomial.is_empty()
    }
}
impl AsRef<[FieldElement]> for Polynomial {
    fn as_ref(&self) -> &[FieldElement] {
        &self.polynomial
    }
}

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
        gfmul(&poly_a, &poly_b, "gcm")
    }

    pub fn to_b64(&self) -> String {
        BASE64_STANDARD.encode(&self.field_element)
    }

    pub fn pow(&self, mut exponent: u128) -> FieldElement {
        if exponent == 0 {
            // Return polynomial with coefficient 1
            return FieldElement::new(vec![1]);
        }

        let base = self.clone();
        let mut result = base.clone();
        exponent -= 1; // Subtract 1 because we already set result to base

        while exponent > 0 {
            result = result * base.clone();
            exponent -= 1;
        }

        result
    }

    pub fn inv(mut self) -> Self {
        let mut inverser: u128 = 0xfffffffffffffffffffffffffffffffe;
        let mut inverse: Vec<u8> = polynomial_2_block(vec![0], "gcm").unwrap();
        //eprintln!("Inverse start {:02X?}", inverse);

        while inverser > 0 {
            //eprintln!("{:02X}", inverser);
            if inverser & 1 == 1 {
                inverse = gfmul(&self.field_element, &inverse, "gcm").unwrap();
            }
            inverser >>= 1;
            self.field_element = gfmul(&self.field_element, &self.field_element, "gcm")
                .expect("Error in sqrmul sqr");
        }
        //eprintln!("Inverse rhs {:?}", inverse);
        FieldElement::new(inverse)
    }

    fn is_zero(&self) -> bool {
        self.field_element.iter().all(|&x| x == 0x00)
    }
}

impl Mul for FieldElement {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        FieldElement::new(
            gfmul(&self.field_element, &rhs.field_element, "gcm")
                .expect("Error during multiplication"),
        )
    }
}

impl Mul for &FieldElement {
    type Output = FieldElement;

    fn mul(self, rhs: &FieldElement) -> FieldElement {
        FieldElement::new(
            gfmul(&self.field_element, &rhs.field_element, "gcm")
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

impl BitXor for FieldElement {
    type Output = Self;
    fn bitxor(self, rhs: Self) -> Self::Output {
        let result: Vec<u8> = self
            .field_element
            .iter()
            .zip(rhs.field_element.iter())
            .map(|(&x1, &x2)| x1 ^ x2)
            .collect();
        FieldElement::new(result)
    }
}

impl Div for FieldElement {
    type Output = Self;
    fn div(self, rhs: Self) -> Self::Output {
        eprintln!("RHS in div{:02X?}", &rhs);

        let inverse = rhs.inv();
        eprintln!("Inverse in div{:02X?}", inverse);
        self.clone() * inverse
    }
}

impl Div for &FieldElement {
    type Output = FieldElement;

    fn div(self, rhs: Self) -> Self::Output {
        // First clone and invert the divisor (rhs)
        let rhs_inv = rhs.clone().inv();
        // Multiply original number by the inverse
        self.clone() * rhs_inv
    }
}

/*
impl Rem for FieldElement {
    type Output = Self;
    fn rem(self, rhs: Self) -> Self::Output {
        let result: FieldElement = self.field_element;

        while self.field_element[15] != 0x00 {
            self.field_element
        }
        todo!();
    }
}
*/
/*
impl BitXor for FieldElement {
    fn bitxor(self, rhs: Self) -> Self::Output {
        FieldElement
    }
}
*/

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

        assert_eq!(
            sum.to_c_array(),
            vec![
                "H1d3GuyA9/0OxeYouUpAAA==",
                "OZuIncPAGEp4tYouDownAA==",
                "NeverGonnaRunAroundAAA==",
                "AndDesertYouAAAAAAAAAA=="
            ]
        );
    }

    #[test]
    fn test_field_add_multiple_zeros() {
        let json1 = json!([
            "AAAAAAAAAAAAAAAAAAAAAA==",
            "AAAAAAAAAAAAAAAAAAAAAA==",
            "AAAAAAAAAAAAAAAAAAAAAA==",
            "AAAAAAAAAAAAAAAAAAAAAA=="
        ]);
        let json2 = json!(["AAAAAAAAAAAAAAAAAAAAAA==", "AAAAAAAAAAAAAAAAAAAAAA=="]);
        let element1: Polynomial = Polynomial::from_c_array(&json1);
        let element2: Polynomial = Polynomial::from_c_array(&json2);

        let sum = element2 + element1;

        assert_eq!(sum.to_c_array(), vec!["AAAAAAAAAAAAAAAAAAAAAA==",]);
    }

    #[test]
    fn test_field_add_same_element() {
        let json1 = json!(["NeverGonnaGiveYouUpAAA=="]);
        let json2 = json!(["NeverGonnaGiveYouUpAAA=="]);
        let element1: Polynomial = Polynomial::from_c_array(&json1);
        let element2: Polynomial = Polynomial::from_c_array(&json2);

        let sum = element2 + element1;

        assert_eq!(sum.to_c_array(), vec!["AAAAAAAAAAAAAAAAAAAAAA==",]);
    }

    #[test]
    fn test_field_add_zero() {
        let json1 = json!([
            "NeverGonnaGiveYouUpAAA==",
            "NeverGonnaLetYouDownAA==",
            "NeverGonnaRunAroundAAA==",
            "AndDesertYouAAAAAAAAAA=="
        ]);
        let json2 = json!(["AAAAAAAAAAAAAAAAAAAAAA=="]);
        let element1: Polynomial = Polynomial::from_c_array(&json1);
        let element2: Polynomial = Polynomial::from_c_array(&json2);

        let sum = element2 + element1;

        assert_eq!(
            sum.to_c_array(),
            vec![
                "NeverGonnaGiveYouUpAAA==",
                "NeverGonnaLetYouDownAA==",
                "NeverGonnaRunAroundAAA==",
                "AndDesertYouAAAAAAAAAA=="
            ]
        );
    }

    #[test]
    fn test_field_add_zero_to_zero() {
        let json1 = json!(["AAAAAAAAAAAAAAAAAAAAAA=="]);
        let json2 = json!(["AAAAAAAAAAAAAAAAAAAAAA=="]);
        let element1: Polynomial = Polynomial::from_c_array(&json1);
        let element2: Polynomial = Polynomial::from_c_array(&json2);

        let sum = element2 + element1;

        assert_eq!(sum.to_c_array(), vec!["AAAAAAAAAAAAAAAAAAAAAA=="]);
    }

    #[test]
    fn test_field_add_short_to_long() {
        let json1 = json!(["AAAAAAAAAAAAAAAAAAAAAA=="]);
        let json2 = json!([
            "NeverGonnaGiveYouUpAAA==",
            "NeverGonnaLetYouDownAA==",
            "NeverGonnaRunAroundAAA==",
            "AndDesertYouAAAAAAAAAA=="
        ]);
        let element1: Polynomial = Polynomial::from_c_array(&json1);
        let element2: Polynomial = Polynomial::from_c_array(&json2);

        let sum = element2 + element1;

        assert_eq!(
            sum.to_c_array(),
            vec![
                "NeverGonnaGiveYouUpAAA==",
                "NeverGonnaLetYouDownAA==",
                "NeverGonnaRunAroundAAA==",
                "AndDesertYouAAAAAAAAAA=="
            ]
        );
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

        assert_eq!(
            result.to_c_array(),
            vec![
                "MoAAAAAAAAAAAAAAAAAAAA==",
                "sUgAAAAAAAAAAAAAAAAAAA==",
                "MbQAAAAAAAAAAAAAAAAAAA==",
                "AAhAAAAAAAAAAAAAAAAAAA=="
            ]
        );
        //assert_eq!(BASE64_STANDARD.encode(product), "MoAAAAAAAAAAAAAAAAAAAA==");
    }

    #[test]
    fn test_poly_mul_with_zero() {
        let json1 = json!([
            "JAAAAAAAAAAAAAAAAAAAAA==",
            "wAAAAAAAAAAAAAAAAAAAAA==",
            "ACAAAAAAAAAAAAAAAAAAAA=="
        ]);
        let json2 = json!(["AAAAAAAAAAAAAAAAAAAAAA=="]);
        let element1: Polynomial = Polynomial::from_c_array(&json1);
        let element2: Polynomial = Polynomial::from_c_array(&json2);

        //eprintln!("{:?}", element1);

        let result = element1 * element2;

        assert_eq!(result.to_c_array(), vec!["AAAAAAAAAAAAAAAAAAAAAA=="]);
        //assert_eq!(BASE64_STANDARD.encode(product), "MoAAAAAAAAAAAAAAAAAAAA==");
    }

    #[test]
    fn test_poly_pow_01() {
        let json1 = json!([
            "JAAAAAAAAAAAAAAAAAAAAA==",
            "wAAAAAAAAAAAAAAAAAAAAA==",
            "ACAAAAAAAAAAAAAAAAAAAA=="
        ]);
        let element1: Polynomial = Polynomial::from_c_array(&json1);

        let result = element1.pow(3);

        assert_eq!(
            result.to_c_array(),
            vec![
                "AkkAAAAAAAAAAAAAAAAAAA==",
                "DDAAAAAAAAAAAAAAAAAAAA==",
                "LQIIAAAAAAAAAAAAAAAAAA==",
                "8AAAAAAAAAAAAAAAAAAAAA==",
                "ACgCQAAAAAAAAAAAAAAAAA==",
                "AAAMAAAAAAAAAAAAAAAAAA==",
                "AAAAAgAAAAAAAAAAAAAAAA=="
            ]
        );
        //assert_eq!(BASE64_STANDARD.encode(product), "MoAAAAAAAAAAAAAAAAAAAA==");
    }

    #[test]
    fn test_poly_pow_with_zero() {
        let json1 = json!([
            "JAAAAAAAAAAAAAAAAAAAAA==",
            "wAAAAAAAAAAAAAAAAAAAAA==",
            "ACAAAAAAAAAAAAAAAAAAAA=="
        ]);
        let element1: Polynomial = Polynomial::from_c_array(&json1);

        let result = element1.pow(0);

        assert_eq!(result.to_c_array(), vec!["gAAAAAAAAAAAAAAAAAAAAA=="]);
        //assert_eq!(BASE64_STANDARD.encode(product), "MoAAAAAAAAAAAAAAAAAAAA==");
    }

    #[test]
    fn test_field_pow_mod_01() {
        let json1 = json!([
            "JAAAAAAAAAAAAAAAAAAAAA==",
            "wAAAAAAAAAAAAAAAAAAAAA==",
            "ACAAAAAAAAAAAAAAAAAAAA=="
        ]);
        let element1: Polynomial = Polynomial::from_c_array(&json1);

        let result = element1.pow(3);

        assert_eq!(
            result.to_c_array(),
            vec![
                "AkkAAAAAAAAAAAAAAAAAAA==",
                "DDAAAAAAAAAAAAAAAAAAAA==",
                "LQIIAAAAAAAAAAAAAAAAAA==",
                "8AAAAAAAAAAAAAAAAAAAAA==",
                "ACgCQAAAAAAAAAAAAAAAAA==",
                "AAAMAAAAAAAAAAAAAAAAAA==",
                "AAAAAgAAAAAAAAAAAAAAAA=="
            ]
        );
        //assert_eq!(BASE64_STANDARD.encode(product), "MoAAAAAAAAAAAAAAAAAAAA==");
    }

    #[test]
    fn test_field_pow_mod_with_zero() {
        let json1 = json!([
            "JAAAAAAAAAAAAAAAAAAAAA==",
            "wAAAAAAAAAAAAAAAAAAAAA==",
            "ACAAAAAAAAAAAAAAAAAAAA=="
        ]);
        let element1: Polynomial = Polynomial::from_c_array(&json1);

        let result = element1.pow(0);

        assert_eq!(result.to_c_array(), vec!["gAAAAAAAAAAAAAAAAAAAAA=="]);
        //assert_eq!(BASE64_STANDARD.encode(product), "MoAAAAAAAAAAAAAAAAAAAA==");
    }

    #[test]
    fn test_field_pow_mod_10mill() {
        let json1 = json!([
            "JAAAAAAAAAAAAAAAAAAAAA==",
            "wAAAAAAAAAAAAAAAAAAAAA==",
            "ACAAAAAAAAAAAAAAAAAAAA=="
        ]);
        let json2 = json!(["KryptoanalyseAAAAAAAAA==", "DHBWMannheimAAAAAAAAAA=="]);
        let element1: Polynomial = Polynomial::from_c_array(&json1);
        let modulus: Polynomial = Polynomial::from_c_array(&json2);

        let result = element1.pow_mod(10000000, modulus);

        assert!(!result.is_zero())
        //assert_eq!(BASE64_STANDARD.encode(product), "MoAAAAAAAAAAAAAAAAAAAA==");
    }

    #[test]
    fn test_poly_div_01() {
        let element1 =
            FieldElement::new(BASE64_STANDARD.decode("JAAAAAAAAAAAAAAAAAAAAA==").unwrap());

        let element2 =
            FieldElement::new(BASE64_STANDARD.decode("wAAAAAAAAAAAAAAAAAAAAA==").unwrap());

        let result = element1 / element2;

        assert_eq!(BASE64_STANDARD.encode(result), "OAAAAAAAAAAAAAAAAAAAAA==");
    }

    #[test]
    fn test_field_poly_div_01() {
        let json1 = json!([
            "JAAAAAAAAAAAAAAAAAAAAA==",
            "wAAAAAAAAAAAAAAAAAAAAA==",
            "ACAAAAAAAAAAAAAAAAAAAA=="
        ]);
        let json2 = json!(["0AAAAAAAAAAAAAAAAAAAAA==", "IQAAAAAAAAAAAAAAAAAAAA=="]);
        let element1: Polynomial = Polynomial::from_c_array(&json1);
        let element2: Polynomial = Polynomial::from_c_array(&json2);

        //eprintln!("{:?}", element1);

        println!("Beginning the new division");
        let (result, remainder) = element1.div(&element2);

        assert_eq!(
            result.to_c_array(),
            vec!["nAIAgCAIAgCAIAgCAIAgCg==", "m85znOc5znOc5znOc5znOQ=="]
        );
        assert_eq!(remainder.to_c_array(), vec!["lQNA0DQNA0DQNA0DQNA0Dg=="]);
        //assert_eq!(BASE64_STANDARD.encode(product), "MoAAAAAAAAAAAAAAAAAAAA==");
    }

    #[test]
    fn test_field_poly_div_larger_div() {
        let json1 = json!([
            "JAAAAAAAAAAAAAAAAAAAAA==",
            "wAAAAAAAAAAAAAAAAAAAAA==",
            "ACAAAAAAAAAAAAAAAAAAAA=="
        ]);
        let json2 = json!(["0AAAAAAAAAAAAAAAAAAAAA==", "IQAAAAAAAAAAAAAAAAAAAA=="]);
        let element1: Polynomial = Polynomial::from_c_array(&json1);
        let element2: Polynomial = Polynomial::from_c_array(&json2);

        //eprintln!("{:?}", element1);

        println!("Beginning the new division");
        let (result, remainder) = element2.div(&element1);

        assert_eq!(result.to_c_array(), vec!["AAAAAAAAAAAAAAAAAAAAAA=="]);
        assert_eq!(
            remainder.to_c_array(),
            vec!["0AAAAAAAAAAAAAAAAAAAAA==", "IQAAAAAAAAAAAAAAAAAAAA=="]
        );
        //assert_eq!(BASE64_STANDARD.encode(product), "MoAAAAAAAAAAAAAAAAAAAA==");
    }

    #[test]
    fn test_field_poly_powmod_01() {
        let json1 = json!([
            "JAAAAAAAAAAAAAAAAAAAAA==",
            "wAAAAAAAAAAAAAAAAAAAAA==",
            "ACAAAAAAAAAAAAAAAAAAAA=="
        ]);
        let json2 = json!(["KryptoanalyseAAAAAAAAA==", "DHBWMannheimAAAAAAAAAA=="]);
        let element1: Polynomial = Polynomial::from_c_array(&json1);
        let modulus: Polynomial = Polynomial::from_c_array(&json2);

        let result = element1.pow_mod(1000, modulus);

        eprintln!("Result is: {:02X?}", result);
        assert_eq!(result.to_c_array(), vec!["oNXl5P8xq2WpUTP92u25zg=="]);
    }

    #[test]
    fn test_field_poly_powmod_k1() {
        let json1 = json!(["JAAAAAAAAAAAAAAAAAAAAA==",]);
        let json2 = json!(["KryptoanalyseAAAAAAAAA=="]);
        let element1: Polynomial = Polynomial::from_c_array(&json1);
        let modulus: Polynomial = Polynomial::from_c_array(&json2);

        let result = element1.pow_mod(1, modulus);

        eprintln!("Result is: {:02X?}", result);
        assert_eq!(result.to_c_array(), vec!["JAAAAAAAAAAAAAAAAAAAAA=="]);
    }

    #[test]
    fn test_field_poly_powmod_k0() {
        let json1 = json!(["JAAAAAAAAAAAAAAAAAAAAA==",]);
        let json2 = json!(["KryptoanalyseAAAAAAAAA=="]);
        let element1: Polynomial = Polynomial::from_c_array(&json1);
        let modulus: Polynomial = Polynomial::from_c_array(&json2);

        let result = element1.pow_mod(0, modulus);

        eprintln!("Result is: {:02X?}", result);
        assert_eq!(result.to_c_array(), vec!["gAAAAAAAAAAAAAAAAAAAAA=="]);
    }
}
