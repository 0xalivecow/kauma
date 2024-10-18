use std::{fmt::format, str::FromStr, u128, u8};

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

#[cfg(test)]
mod tests {
    // Note this useful idiom: importing names from outer (for mod tests) scope.
    use super::*;

    #[test]
    fn test_num_to_alpha_rep_1() {
        let number: u128 = 0x010000000000000000000000000000000;
        let polynomial: &str = "1";
        assert_eq!(get_alpha_rep(number.reverse_bits()), polynomial);
    }

    #[test]
    fn test_num_to_alpha_rep_a4a2a() {
        let number: u128 = 0x16000000000000000000000000000000;
        let polynomial: &str = "a^4a^2a";
        assert_eq!(get_alpha_rep(number.reverse_bits()), polynomial);
    }
}
