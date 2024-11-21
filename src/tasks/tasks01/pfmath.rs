use anyhow::Result;
use base64::{prelude::BASE64_STANDARD, Engine};
use serde_json::Value;

use crate::utils::field::{sort_polynomial_array, FieldElement, Polynomial};

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
}
