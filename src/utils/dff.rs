use std::usize;

use num::{pow::Pow, BigUint, FromPrimitive};
use serde::{Deserialize, Serialize};

use super::poly::{gcd, Polynomial};

#[derive(Debug, Serialize, Deserialize)]
pub struct Factors {
    pub factor: Vec<String>,
    pub degree: u32,
}

pub fn ddf(f: Polynomial) -> Vec<(Polynomial, u128)> {
    let q = BigUint::pow(&BigUint::from_u8(2).unwrap(), 128);

    let mut z: Vec<(Polynomial, u128)> = vec![];
    let mut d: u128 = 1;
    let mut f_star = f.clone();

    let one_cmp = Polynomial::one();

    while f_star.degree() as u128 >= (2 * d) {
        let h = Polynomial::x().bpow_mod(q.clone().pow(d), &f_star.clone()) + Polynomial::x();

        let g = gcd(&h, &f_star);
        if g != one_cmp {
            z.push((g.clone(), d));
            f_star = f_star.div(&g).0;
        }

        d += 1;
    }

    if f_star != one_cmp {
        z.push((f_star.clone(), f_star.degree() as u128));
    } else if z.len() == 0 {
        z.push((f.clone(), 1));
    }

    z
}

#[cfg(test)]
mod tests {

    use serde_json::json;

    // Note this useful idiom: importing names from outer (for mod tests) scope.
    use super::*;

    #[test]
    fn test_dff_sheet() {
        let json_f = json!([
            "tpkgAAAAAAAAAAAAAAAAAA==",
            "m6MQAAAAAAAAAAAAAAAAAA==",
            "8roAAAAAAAAAAAAAAAAAAA==",
            "3dUAAAAAAAAAAAAAAAAAAA==",
            "FwAAAAAAAAAAAAAAAAAAAA==",
            "/kAAAAAAAAAAAAAAAAAAAA==",
            "a4AAAAAAAAAAAAAAAAAAAA==",
            "gAAAAAAAAAAAAAAAAAAAAA=="
        ]);
        let poly_f = Polynomial::from_c_array(&json_f);

        let mut factors = ddf(poly_f);
        factors.sort();
        let mut result: Vec<Factors> = vec![];

        for (factor, degree) in factors {
            result.push(Factors {
                factor: factor.to_c_array(),
                degree: degree as u32,
            });
        }

        println!("Result: {:?}", result);
        let _bit_indices: Vec<u8> = vec![0];
        assert!(false)
    }
}
