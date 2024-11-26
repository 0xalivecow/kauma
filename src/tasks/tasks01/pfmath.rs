use std::usize;

use anyhow::Result;
use base64::{prelude::BASE64_STANDARD, Engine};
use serde_json::Value;

use crate::{
    tasks,
    utils::{
        self,
        dff::ddf,
        field::FieldElement,
        poly::{gcd, Polynomial},
        sff::{sff, Factors},
    },
};

pub fn gfpoly_add(args: &Value) -> Result<Polynomial> {
    let poly_a = Polynomial::from_c_array(&args["A"].clone());

    let poly_b = Polynomial::from_c_array(&args["B"].clone());

    let result = poly_a + poly_b;

    Ok(result)
}

pub fn gfpoly_mul(args: &Value) -> Result<Polynomial> {
    let poly_a = Polynomial::from_c_array(&args["A"].clone());

    let poly_b = Polynomial::from_c_array(&args["B"].clone());

    let result = poly_a * poly_b;

    Ok(result)
}

pub fn gfpoly_pow(args: &Value) -> Result<Polynomial> {
    let poly_a = Polynomial::from_c_array(&args["A"].clone());

    let k: u128 = serde_json::from_value(args["k"].clone())?;

    let result = poly_a.pow(k);

    Ok(result)
}

pub fn gfdiv(args: &Value) -> Result<FieldElement> {
    let f1_text: String = serde_json::from_value(args["a"].clone())?;
    let f_a = FieldElement::new(BASE64_STANDARD.decode(f1_text)?);

    let f2_text: String = serde_json::from_value(args["b"].clone())?;
    let f_b = FieldElement::new(BASE64_STANDARD.decode(f2_text)?);

    let result = f_a / f_b;

    Ok(result)
}

pub fn gfpoly_divmod(args: &Value) -> Result<(Polynomial, Polynomial)> {
    let poly_a = Polynomial::from_c_array(&args["A"].clone());

    let poly_b = Polynomial::from_c_array(&args["B"].clone());

    let result = poly_a.div(&poly_b);

    Ok(result)
}

pub fn gfpoly_powmod(args: &Value) -> Result<Polynomial> {
    let poly_a = Polynomial::from_c_array(&args["A"].clone());

    let poly_m = Polynomial::from_c_array(&args["M"].clone());

    let k: u128 = serde_json::from_value(args["k"].clone())?;

    let result = poly_a.pow_mod(k, poly_m);

    Ok(result)
}

pub fn gfpoly_sort(args: &Value) -> Result<Vec<Polynomial>> {
    let poly_arrays: Vec<Value> = serde_json::from_value(args["polys"].clone())?;
    let mut polys: Vec<Polynomial> = vec![];

    for array in poly_arrays {
        polys.push(Polynomial::from_c_array(&array));
    }

    polys.sort();
    //polys.sort();
    Ok(polys)
}

pub fn gfpoly_make_monic(args: &Value) -> Result<Polynomial> {
    let poly_a = Polynomial::from_c_array(&args["A"].clone());

    let result = poly_a.monic();

    Ok(result)
}

pub fn gfpoly_sqrt(args: &Value) -> Result<Polynomial> {
    let poly_a = Polynomial::from_c_array(&args["Q"].clone());

    let result = poly_a.sqrt();

    Ok(result)
}

pub fn gfpoly_diff(args: &Value) -> Result<Polynomial> {
    let poly_f = Polynomial::from_c_array(&args["F"].clone());

    let result = poly_f.diff();

    Ok(result)
}

pub fn gfpoly_gcd(args: &Value) -> Result<Polynomial> {
    let poly_a = Polynomial::from_c_array(&args["A"].clone());
    let poly_b = Polynomial::from_c_array(&args["B"].clone());

    let result = gcd(&poly_a.monic(), &poly_b.monic());

    Ok(result)
}

pub fn gfpoly_factor_sff(arsg: &Value) -> Result<Vec<(Factors)>> {
    let poly_f = Polynomial::from_c_array(&arsg["F"].clone());

    let mut factors = sff(poly_f);
    factors.sort();
    let mut result: Vec<Factors> = vec![];

    for (factor, exponent) in factors {
        result.push(Factors {
            factor: factor.to_c_array(),
            exponent,
        });
    }

    Ok(result)
}

pub fn gfpoly_factor_ddf(arsg: &Value) -> Result<Vec<(utils::dff::Factors)>> {
    let poly_f = Polynomial::from_c_array(&arsg["F"].clone());

    let mut factors = ddf(poly_f);
    factors.sort();
    let mut result: Vec<utils::dff::Factors> = vec![];

    for (factor, degree) in factors {
        result.push(utils::dff::Factors {
            factor: factor.to_c_array(),
            degree: degree as u32,
        });
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_poly_sorting() {
        let json1 = json!(
            {"polys": [
            [
                "NeverGonnaGiveYouUpAAA==",
                "NeverGonnaLetYouDownAA==",
                "NeverGonnaRunAroundAAA==",
                "AndDesertYouAAAAAAAAAA=="
            ],
            [
                "WereNoStrangersToLoveA==",
                "YouKnowTheRulesAAAAAAA==",
                "AndSoDoIAAAAAAAAAAAAAA=="
            ],
            [
                "NeverGonnaMakeYouCryAA==",
                "NeverGonnaSayGoodbyeAA==",
                "NeverGonnaTellALieAAAA==",
                "AndHurtYouAAAAAAAAAAAA=="
            ]
        ]});

        let expected = json!([
            [
                "WereNoStrangersToLoveA==",
                "YouKnowTheRulesAAAAAAA==",
                "AndSoDoIAAAAAAAAAAAAAA=="
            ],
            [
                "NeverGonnaMakeYouCryAA==",
                "NeverGonnaSayGoodbyeAA==",
                "NeverGonnaTellALieAAAA==",
                "AndHurtYouAAAAAAAAAAAA=="
            ],
            [
                "NeverGonnaGiveYouUpAAA==",
                "NeverGonnaLetYouDownAA==",
                "NeverGonnaRunAroundAAA==",
                "AndDesertYouAAAAAAAAAA=="
            ]
        ]);

        let sorted_array = gfpoly_sort(&json1).unwrap();
        let mut result: Vec<Vec<String>> = vec![];
        for poly in sorted_array {
            result.push(poly.to_c_array());
        }

        assert_eq!(json!(result), expected);
        //assert_eq!(BASE64_STANDARD.encode(product), "MoAAAAAAAAAAAAAAAAAAAA==");
    }

    #[test]
    fn test_poly_sorting_02() {
        let json1 = json!(
            {"polys": [
            [
            "AQAAAAAAAAAAAAAAAAAAAA==",  // 0x01
            "AgAAAAAAAAAAAAAAAAAAAA==",  // 0x02 
            "AwAAAAAAAAAAAAAAAAAAAA=="   // 0x03
            ],
            [
            "AQAAAAAAAAAAAAAAAAAAAA==",  // 0x01
            "AgAAAAAAAAAAAAAAAAAAAA==",  // 0x02
            "BAAAAAAAAAAAAAAAAAAAAA=="   // 0x04
            ],
            [
            "AQAAAAAAAAAAAAAAAAAAAA==",  // 0x01
            "AgAAAAAAAAAAAAAAAAAAAA=="   // 0x02
            ],
            [
            "AQAAAAAAAAAAAAAAAAAAAA==",  // 0x01
            "AwAAAAAAAAAAAAAAAAAAAA=="   // 0x03
            ]
        ],});

        let expected = json!([
            ["AQAAAAAAAAAAAAAAAAAAAA==", "AgAAAAAAAAAAAAAAAAAAAA=="],
            ["AQAAAAAAAAAAAAAAAAAAAA==", "AwAAAAAAAAAAAAAAAAAAAA=="],
            [
                "AQAAAAAAAAAAAAAAAAAAAA==",
                "AgAAAAAAAAAAAAAAAAAAAA==",
                "BAAAAAAAAAAAAAAAAAAAAA=="
            ],
            [
                "AQAAAAAAAAAAAAAAAAAAAA==",
                "AgAAAAAAAAAAAAAAAAAAAA==",
                "AwAAAAAAAAAAAAAAAAAAAA=="
            ]
        ]);

        let sorted_array = gfpoly_sort(&json1).unwrap();
        let mut result: Vec<Vec<String>> = vec![];
        for poly in sorted_array {
            result.push(poly.to_c_array());
        }

        assert_eq!(json!(result), expected);
        //assert_eq!(BASE64_STANDARD.encode(product), "MoAAAAAAAAAAAAAAAAAAAA==");
    }
}
