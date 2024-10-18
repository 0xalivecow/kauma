use std::{fmt::format, str::FromStr, u128, u8};
use base64::prelude::*;

pub fn get_alpha_rep(num: u128) -> String {
    let mut powers: Vec<u32> = vec![];

    for shift in 0..127 {
        //println!("{:?}", ((num >> shift) & 1));
        if (((num >> shift) & 1) == 1) {
            println!("Shift success");
            powers.push(shift);
        }
    }
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

pub fn get_bit_indices_from_byte(byte: u8) -> Vec<u8> {
    let mut coefficients: Vec<u8> = vec![];
    
    for shift in 0..7 {
        if ((byte >> shift) & 1) == 1 {
            coefficients.push(shift);
        }
    }

    coefficients
}

pub fn coefficient_to_binary(coefficients: Vec<u8>) -> u128{
    let mut binary_number: u128 = 0;
    for coeff in coefficients {
        binary_number = binary_number | (1<<coeff);
    }

    binary_number
}


#[cfg(test)]
mod tests {
    // Note this useful idiom: importing names from outer (for mod tests) scope.
    use super::*;

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
        assert_eq!(BASE64_STANDARD.encode(calculated_num.to_ne_bytes()), "ARIAAAAAAAAAAAAAAAAAgA==");
    }
}
