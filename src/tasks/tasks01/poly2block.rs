use crate::utils::poly::{self, coefficient_to_binary};
use base64::prelude::*;
use serde_json::Value;

pub fn poly2block(args: &Value) -> String {
    let coefficients: Vec<u8> = args["coefficients"]
        .as_array()
        .unwrap()
        .into_iter()
        .map(|x| x.as_u64().unwrap() as u8)
        .collect();
    BASE64_STANDARD.encode(poly::coefficient_to_binary(coefficients).to_ne_bytes())
}
