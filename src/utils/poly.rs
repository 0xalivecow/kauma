use crate::utils::math::ByteArray;
use anyhow::Result;
use base64::prelude::*;
use serde_json::Value;
use std::{str::FromStr, u128, u8, usize};
pub const RED_POLY: u128 = 0x87000000_00000000_00000000_00000000;

pub fn gfmul(poly_a: Vec<u8>, poly_b: Vec<u8>, semantic: &str) -> Result<Vec<u8>> {
    let mut red_poly_bytes: ByteArray = ByteArray(RED_POLY.to_be_bytes().to_vec());
    red_poly_bytes.0.push(0x01);

    let mut poly1: ByteArray = ByteArray(poly_a);
    poly1.0.push(0x00);

    let mut poly2: ByteArray = ByteArray(poly_b);
    poly2.0.push(0x00);

    let mut result: ByteArray = ByteArray(vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);

    if poly2.LSB_is_one() {
        result.xor_byte_arrays(&poly1);
    }
    poly2.right_shift(semantic)?;

    while !poly2.is_empty() {
        poly1.left_shift(semantic)?;

        if poly1.msb_is_one() {
            poly1.xor_byte_arrays(&red_poly_bytes);
        }

        if poly2.LSB_is_one() {
            result.xor_byte_arrays(&poly1);
        }

        poly2.right_shift(semantic)?;
    }

    result.0.remove(16);

    Ok(result.0)
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

pub fn coefficients_to_byte_arr_xex(coeffs: Vec<u8>) -> Vec<u8> {
    let mut byte_array: Vec<u8> = vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    for coeff in coeffs {
        let block_num = coeff / 8;
        byte_array[usize::from(block_num)] |= (1 << (coeff % 7));
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
}
