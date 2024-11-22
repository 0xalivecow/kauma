use crate::utils::field::ByteArray;
use base64::prelude::*;
use std::{str::FromStr, u128, u8, usize};

use std::{
    cmp::Ordering,
    mem::discriminant,
    ops::{Add, BitXor, Div, Mul, Sub},
};

use anyhow::{anyhow, Ok, Result};
use serde_json::Value;

use super::field::FieldElement;
use super::math::{reverse_bits_in_bytevec, xor_bytes};

#[derive(Debug, serde::Serialize)]
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
            eprintln!("special case 1: {:02X?}", self.clone().div(&modulus).1);

            return self.div(&modulus).1;
        }

        if exponent == 0 {
            let result = Polynomial::new(vec![FieldElement::new(
                polynomial_2_block(vec![0], "gcm").unwrap(),
            )]);

            eprintln!("Returned value is: {:02X?}", result);
            return result;
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

        eprintln!("result in powmod before reduction: {:02X?}", result);

        while !result.polynomial.is_empty()
            && result
                .polynomial
                .last()
                .unwrap()
                .as_ref()
                .iter()
                .all(|&x| x == 0)
        {
            result.polynomial.pop();
        }

        eprintln!("result in powmod after reduction: {:02X?}", result);

        if result.is_empty() {
            result = Polynomial::new(vec![FieldElement::new(vec![0; 16])]);
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

    fn monic(mut self) -> Self {
        let divident = self.polynomial.last().unwrap().clone();

        for fieldelement in &mut self.polynomial.iter_mut() {
            *fieldelement = fieldelement.clone() / divident.clone();
        }

        self
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

        while !polynomial.is_empty() && polynomial.last().unwrap().as_ref().iter().all(|&x| x == 0)
        {
            polynomial.pop();
        }

        if polynomial.is_empty() {
            return Polynomial::new(vec![FieldElement::new(vec![0; 16])]);
        }

        Polynomial::new(polynomial)
    }
}

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

impl PartialEq for Polynomial {
    fn eq(&self, other: &Self) -> bool {
        if self.polynomial.len() != other.polynomial.len() {
            return false;
        }
        // Compare each coefficient
        self.polynomial
            .iter()
            .zip(other.polynomial.iter())
            .all(|(a, b)| a == b)
    }
}

impl PartialOrd for Polynomial {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        match other.polynomial.len().cmp(&self.polynomial.len()) {
            Ordering::Equal => {
                for (field_a, field_b) in
                    self.as_ref().iter().rev().zip(other.as_ref().iter().rev())
                {
                    eprintln!(
                        "Poly partord: {:02X?} {:02X?} ",
                        self.clone().to_c_array(),
                        other.clone().to_c_array()
                    );

                    match field_a
                        .reverse_bits()
                        .partial_cmp(&field_b.reverse_bits())
                        .unwrap()
                    {
                        Ordering::Equal => continue,
                        other => return Some(other),
                    }
                }
                Some(Ordering::Equal)
            }
            other => Some(other.reverse()),
        }
    }
}

impl Eq for Polynomial {}

impl Ord for Polynomial {
    fn cmp(&self, other: &Self) -> Ordering {
        match other.polynomial.len().cmp(&self.polynomial.len()) {
            Ordering::Equal => {
                for (field_a, field_b) in
                    self.as_ref().iter().rev().zip(other.as_ref().iter().rev())
                {
                    match field_a.reverse_bits().cmp(&field_b.reverse_bits()) {
                        Ordering::Equal => continue,
                        other => return other,
                    }
                }
                Ordering::Equal
            }
            other => other.reverse(),
        }
    }
}

pub fn sort_polynomial_array(mut polys: Vec<Polynomial>) -> Result<Vec<Polynomial>> {
    // Algorithm to sort polynomials
    // First sorting round
    // Sorting by degree of polynomial
    polys.sort();

    Ok(polys)
}

pub const RED_POLY: u128 = 0x87000000_00000000_00000000_00000000;

pub fn gfmul(poly_a: &Vec<u8>, poly_b: &Vec<u8>, semantic: &str) -> Result<Vec<u8>> {
    let mut red_poly_bytes: ByteArray = ByteArray(RED_POLY.to_be_bytes().to_vec());
    red_poly_bytes.0.push(0x01);

    let mut poly1: ByteArray = ByteArray(poly_a.to_owned());
    poly1.0.push(0x00);

    let mut poly2: ByteArray = ByteArray(poly_b.to_owned());
    poly2.0.push(0x00);

    if semantic == "gcm" {
        poly1.reverse_bits_in_bytevec();
        poly2.reverse_bits_in_bytevec();
    }

    let mut result: ByteArray = ByteArray(vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);

    if poly2.LSB_is_one() {
        result.xor_byte_arrays(&poly1);
    }
    poly2.right_shift("xex")?;

    while !poly2.is_empty() {
        poly1.left_shift("xex")?;

        if poly1.msb_is_one() {
            poly1.xor_byte_arrays(&red_poly_bytes);
        }

        if poly2.LSB_is_one() {
            result.xor_byte_arrays(&poly1);
        }

        poly2.right_shift("xex")?;
    }

    result.0.remove(16);

    if semantic == "gcm" {
        result.reverse_bits_in_bytevec();
    }

    Ok(result.0)
}

pub fn convert_gcm_to_xex(gcm_poly: Vec<u8>) -> Result<Vec<u8>> {
    let xex_poly = gcm_poly
        .into_iter()
        .map(|block| block.reverse_bits())
        .collect();

    Ok(xex_poly)
}

pub fn get_alpha_rep(num: u128) -> String {
    let powers: Vec<u8> = get_coefficients(num);

    //println!("{:?}", powers);

    let mut alpha_rep = String::new();

    if powers.len() == 1 {
        return String::from_str("1").unwrap();
    }

    for power in powers {
        alpha_rep.push_str(&format!("a^{power}"));
    }

    alpha_rep
}

pub fn b64_2_num(string: &String) -> Result<u128> {
    let decoded: Vec<u8> = BASE64_STANDARD.decode(string)?;

    let mut bytes: [u8; 16] = [0u8; 16];
    bytes.copy_from_slice(&decoded);
    let number: u128 = <u128>::from_ne_bytes(bytes);

    Ok(number)
}

pub fn get_coefficients(num: u128) -> Vec<u8> {
    let mut powers: Vec<u8> = vec![];
    for shift in 0..128 {
        //println!("{:?}", ((num >> shift) & 1));
        if ((num >> shift) & 1) == 1 {
            powers.push(shift);
        }
    }
    powers
}

pub fn get_bit_indices_from_byte(byte: u8) -> Vec<u8> {
    let mut coefficients: Vec<u8> = vec![];

    for shift in 0..8 {
        if ((byte >> shift) & 1) == 1 {
            coefficients.push(shift);
        }
    }

    coefficients
}

pub fn block_2_polynomial(block: Vec<u8>, semantic: &str) -> Result<Vec<u8>> {
    let mut output: Vec<u8> = vec![];
    match semantic {
        "xex" => {
            for i in 0u8..=15 {
                for j in 0u8..=7 {
                    if (block[i as usize] >> j) & 1 == 1 {
                        output.push(8 * i + j);
                    }
                }
            }
            output.sort();
            Ok(output)
        }
        "gcm" => {
            for i in 0u8..=15 {
                for j in 0u8..=7 {
                    if (block[i as usize] >> j) & 1 == 1 {
                        output.push(8 * i + 7 - j);
                    }
                }
            }
            output.sort();
            Ok(output)
        }
        _ => Err(anyhow!("Error in b2p")),
    }
}

pub fn polynomial_2_block(coefficients: Vec<u8>, semantic: &str) -> Result<Vec<u8>> {
    let mut output: Vec<u8> = Vec::with_capacity(16);
    output.resize(16, 0);

    match semantic {
        "xex" => {
            for coefficient in coefficients {
                let byte_position = coefficient / 8;
                let bit_position = coefficient % 8;

                output[byte_position as usize] ^= 1 << bit_position;
            }
            Ok(output)
        }
        "gcm" => {
            for coefficient in coefficients {
                let byte_position = coefficient / 8;
                let bit_position = coefficient % 8;

                output[byte_position as usize] ^= 1 << 7 - bit_position;
            }
            Ok(output)
        }
        _ => Err(anyhow!("Error in b2p")),
    }
}

pub fn coefficients_to_byte_arr_xex(coeffs: Vec<u8>) -> Vec<u8> {
    let mut byte_array: Vec<u8> = vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    for coeff in coeffs {
        let block_num = coeff / 8;
        byte_array[usize::from(block_num)] |= 1 << (coeff % 7);
    }

    byte_array
}

pub fn coefficient_to_binary(coefficients: Vec<u8>) -> u128 {
    let mut binary_number: u128 = 0;
    for coeff in coefficients {
        binary_number = binary_number | (1 << coeff);
    }

    binary_number
}

#[cfg(test)]
mod tests {
    use crate::utils::poly::b64_2_num;
    use anyhow::Result;
    use serde_json::json;
    // Note this useful idiom: importing names from outer (for mod tests) scope.
    use super::*;

    /*
    * TODO: Consider removing
    #[test]
    fn coefficients_to_byte_arr_xex_test1() {
        let coefficients: Vec<u8> = vec![0];
        let byte_array = vec![
            01, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00,
        ];
        assert_eq!(coefficients_to_byte_arr_xex(coefficients), byte_array)
    }

    #[test]
    fn coefficients_to_byte_arr_xex_test2() {
        let coefficients: Vec<u8> = vec![127, 12, 9, 0];
        let byte_array = vec![
            01, 12, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 80,
        ];
        assert_eq!(coefficients_to_byte_arr_xex(coefficients), byte_array)
    }
    */
    #[test]
    fn byte_indices_0x01() {
        let byte: u8 = 0x01;
        let bit_indices: Vec<u8> = vec![0];
        assert_eq!(get_bit_indices_from_byte(byte), bit_indices)
    }

    #[test]
    fn byte_indices_0x23() {
        let byte: u8 = 0x23;
        let bit_indices: Vec<u8> = vec![0, 1, 5];
        assert_eq!(get_bit_indices_from_byte(byte), bit_indices)
    }

    #[test]
    fn byte_indices_0x56() {
        let byte: u8 = 0x56;
        let bit_indices: Vec<u8> = vec![1, 2, 4, 6];
        assert_eq!(get_bit_indices_from_byte(byte), bit_indices)
    }

    #[test]
    fn coeff_to_binary() {
        let coefficients: Vec<u8> = vec![12, 127, 9, 0];
        let b64: &str = "ARIAAAAAAAAAAAAAAAAAgA==";
        let calculated_num: u128 = coefficient_to_binary(coefficients);
        assert_eq!(
            BASE64_STANDARD.encode(calculated_num.to_ne_bytes()),
            "ARIAAAAAAAAAAAAAAAAAgA=="
        );
    }

    #[test]
    fn test_b64_2_num() -> Result<()> {
        let b64_payload: String = String::from_str("juMqbhnlBwAAAAAAAAAAAA==")?;
        assert_eq!(
            b64_2_num(&b64_payload)?,
            2222222222222222,
            "Error: Value was: {}",
            b64_2_num(&b64_payload)?
        );

        Ok(())
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
    fn test_field_poly_div_eqdeg() {
        let json1 = json!(["JAAAAAAAAAAAAAAAAAAAAA==", "wAAAAAAAAAAAAAAAAAAAAA==",]);
        let json2 = json!(["0AAAAAAAAAAAAAAAAAAAAA==", "IQAAAAAAAAAAAAAAAAAAAA=="]);
        let element1: Polynomial = Polynomial::from_c_array(&json1);
        let element2: Polynomial = Polynomial::from_c_array(&json2);

        let (result, remainder) = element2.div(&element1);

        eprintln!("{:02X?}", (&result, &remainder));

        assert!(!result.is_zero());
        assert!(!remainder.is_zero());
        //assert_eq!(BASE64_STANDARD.encode(product), "MoAAAAAAAAAAAAAAAAAAAA==");
    }

    #[test]
    fn test_field_poly_div_eqdeg_02() {
        let json1 = json!(["JAAAAAAAAAAAAAAAAAAAAA==", "wAAAAAAAAAAAAAAAAAAAAA==",]);
        let json2 = json!(["KryptoanalyseAAAAAAAAA==", "DHBWMannheimAAAAAAAAAA=="]);
        let element1: Polynomial = Polynomial::from_c_array(&json1);
        let element2: Polynomial = Polynomial::from_c_array(&json2);

        let (result, remainder) = element2.div(&element1);

        eprintln!("{:02X?}", (&result, &remainder));

        assert!(!result.is_zero());
        assert!(!remainder.is_zero());
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
        let json2 = json!(["KryptoanalyseAAAAAAAAA==", "DHBWMannheimAAAAAAAAAA=="]);
        let element1: Polynomial = Polynomial::from_c_array(&json1);
        let modulus: Polynomial = Polynomial::from_c_array(&json2);

        let result = element1.pow_mod(1, modulus);

        eprintln!("Result is: {:02X?}", result);
        assert_eq!(result.to_c_array(), vec!["JAAAAAAAAAAAAAAAAAAAAA=="]);
    }

    #[test]
    fn test_field_poly_powmod_k0_special() {
        let json1 = json!(["NeverGonnaGiveYouUpAAA=="]);
        let json2 = json!(["NeverGonnaGiveYouUpAAA=="]);
        let element1: Polynomial = Polynomial::from_c_array(&json1);
        let modulus: Polynomial = Polynomial::from_c_array(&json2);

        let result = element1.pow_mod(0, modulus);

        eprintln!("Result is: {:02X?}", result);

        assert_eq!(result.to_c_array(), vec!["gAAAAAAAAAAAAAAAAAAAAA=="]);
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
    fn test_poly_monic() {
        let json1 = json!([
            "NeverGonnaGiveYouUpAAA==",
            "NeverGonnaLetYouDownAA==",
            "NeverGonnaRunAroundAAA==",
            "AndDesertYouAAAAAAAAAA=="
        ]);
        let expected = json!([
            "edY47onJ4MtCENDTHG/sZw==",
            "oaXjCKnceBIxSavZ9eFT8w==",
            "1Ial5rAJGOucIdUe3zh5bw==",
            "gAAAAAAAAAAAAAAAAAAAAA=="
        ]);
        let element1: Polynomial = Polynomial::from_c_array(&json1);

        let result = element1.monic();

        assert_eq!(json!(result.to_c_array()), expected);
        //assert_eq!(BASE64_STANDARD.encode(product), "MoAAAAAAAAAAAAAAAAAAAA==");
    }
}
