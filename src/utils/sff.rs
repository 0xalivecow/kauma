use serde::{Deserialize, Serialize};

use crate::utils::{
    field::FieldElement,
    poly::{gcd, polynomial_2_block},
};

use super::poly::Polynomial;

#[derive(Debug, Serialize, Deserialize)]
struct Factors {
    factor: Vec<String>,
    exponent: u32,
}

pub fn sff(mut f: Polynomial) -> Vec<(Polynomial, u32)> {
    let mut c = gcd(&f, &f.clone().diff());
    f = f.div(&c).0;
    let mut z: Vec<(Polynomial, u32)> = vec![];
    let mut e: u32 = 1;

    let one_element = Polynomial::new(vec![FieldElement::new(
        polynomial_2_block(vec![0], "gcm").unwrap(),
    )]);

    while f != one_element {
        let y = gcd(&f, &c);
        if f != y {
            z.push(((f.div(&y).0), e));
        }

        f = y.clone();
        c = c.div(&y).0;
        e += 1;
    }

    if c != one_element {
        let r = sff(c.sqrt());
        for (f_star, e_star) in r {
            z.push((f_star, 2 * e_star));
        }
    }

    z
}

#[cfg(test)]
mod tests {

    use serde_json::json;
    // Note this useful idiom: importing names from outer (for mod tests) scope.
    use super::*;

    #[test]
    fn byte_indices_0x01() {
        let json_f = json!([
            "vL77UwAAAAAAAAAAAAAAAA==",
            "mEHchYAAAAAAAAAAAAAAAA==",
            "9WJa0MAAAAAAAAAAAAAAAA==",
            "akHfwWAAAAAAAAAAAAAAAA==",
            "E12o/QAAAAAAAAAAAAAAAA==",
            "vKJ/FgAAAAAAAAAAAAAAAA==",
            "yctWwAAAAAAAAAAAAAAAAA==",
            "c1BXYAAAAAAAAAAAAAAAAA==",
            "o0AtAAAAAAAAAAAAAAAAAA==",
            "AbP2AAAAAAAAAAAAAAAAAA==",
            "k2YAAAAAAAAAAAAAAAAAAA==",
            "vBYAAAAAAAAAAAAAAAAAAA==",
            "dSAAAAAAAAAAAAAAAAAAAA==",
            "69gAAAAAAAAAAAAAAAAAAA==",
            "VkAAAAAAAAAAAAAAAAAAAA==",
            "a4AAAAAAAAAAAAAAAAAAAA==",
            "gAAAAAAAAAAAAAAAAAAAAA=="
        ]);
        let poly_f = Polynomial::from_c_array(&json_f);

        let mut factors = sff(poly_f);
        factors.sort();
        let mut result: Vec<Factors> = vec![];

        for (factor, exponent) in factors {
            result.push(Factors {
                factor: factor.to_c_array(),
                exponent,
            });
        }

        println!("{:?}", result);
        let bit_indices: Vec<u8> = vec![0];
        assert!(false)
    }
}
