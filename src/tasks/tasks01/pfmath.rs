use anyhow::Result;
use base64::{prelude::BASE64_STANDARD, Engine};
use serde_json::Value;

use crate::utils::field::{FieldElement, Polynomial};

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
