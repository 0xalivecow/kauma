use num::{BigUint, FromPrimitive, One};
use rand::Rng;

use super::poly::{gcd, Polynomial};

pub fn edf(f: Polynomial, d: u32) -> Vec<Polynomial> {
    eprintln!("edf started: {:?}", f.clone().to_c_array());
    let q = BigUint::pow(&BigUint::from_u8(2).unwrap(), 128);
    let n: u32 = (f.degree() as u32) / (d);
    let mut z: Vec<Polynomial> = vec![f.clone()];
    let one_cmp = Polynomial::one();

    while (z.len() as u32) < n {
        eprintln!("z len {}", z.len());
        eprintln!("n len {}", n);

        let h = Polynomial::rand(&rand::thread_rng().gen_range(1..=f.degree()));
        eprintln!("h: {:02X?}", h);

        let exponent = (q.pow(d) - BigUint::one()) / BigUint::from_u8(3).unwrap();

        let g = h.bpow_mod(exponent, &f) + Polynomial::one();
        eprintln!("g before for {:0X?}", g);

        eprintln!("z before for {:0X?}", z);

        for i in (0..z.len()).rev() {
            if z[i].degree() as u32 > d {
                eprintln!("Inside if");
                let j = gcd(&z[i], &g);
                eprintln!("j != one_cmp {:?}", j != one_cmp);
                eprintln!("j != z[i] {:?}", j != z[i]);

                eprintln!("Inside if");
                if j != one_cmp && j != z[i] {
                    let intemediate = z[i].div(&j).0;
                    z.remove(i);
                    z.push(j.clone());
                    z.push(intemediate);
                }
            }
        }

        eprintln!("z after for {:0X?}", z);
    }

    eprintln!("edf finished");
    z
}

#[cfg(test)]
mod tests {

    use serde_json::json;

    // Note this useful idiom: importing names from outer (for mod tests) scope.
    use super::*;

    #[test]
    fn test_edf_sheet() {
        let json_f = json!([
            "mmAAAAAAAAAAAAAAAAAAAA==",
            "AbAAAAAAAAAAAAAAAAAAAA==",
            "zgAAAAAAAAAAAAAAAAAAAA==",
            "FwAAAAAAAAAAAAAAAAAAAA==",
            "AAAAAAAAAAAAAAAAAAAAAA==",
            "wAAAAAAAAAAAAAAAAAAAAA==",
            "gAAAAAAAAAAAAAAAAAAAAA=="
        ]);
        let d = 3;
        let poly_f = Polynomial::from_c_array(&json_f);

        let mut factors = edf(poly_f, d);
        factors.sort();

        let mut result: Vec<Vec<String>> = vec![];

        for factor in factors {
            result.push(factor.to_c_array())
        }

        println!("Result: {:?}", result);

        assert_eq!(
            result,
            vec![
                [
                    "iwAAAAAAAAAAAAAAAAAAAA==",
                    "CAAAAAAAAAAAAAAAAAAAAA==",
                    "AAAAAAAAAAAAAAAAAAAAAA==",
                    "gAAAAAAAAAAAAAAAAAAAAA=="
                ],
                [
                    "kAAAAAAAAAAAAAAAAAAAAA==",
                    "CAAAAAAAAAAAAAAAAAAAAA==",
                    "wAAAAAAAAAAAAAAAAAAAAA==",
                    "gAAAAAAAAAAAAAAAAAAAAA=="
                ]
            ]
        )
    }
}
