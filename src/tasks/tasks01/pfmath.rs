use anyhow::Result;
use base64::{prelude::BASE64_STANDARD, Engine};
use serde_json::Value;

use crate::utils::field::Polynomial;

pub fn gfpoly_add(args: &Value) -> Result<Polynomial> {
    let poly_a = Polynomial::from_c_array(&args["A"].clone());

    let poly_b = Polynomial::from_c_array(&args["B"].clone());

    let result = poly_a + poly_b;

    Ok(result)
}
