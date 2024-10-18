use crate::utils::poly::{self, coefficient_to_binary};
use base64::prelude::*;
use serde_json::Value;

pub fn poly2block(coefficients: Vec<u8>) -> String {
    BASE64_STANDARD.encode(poly::coefficient_to_binary(coefficients).to_ne_bytes())
}