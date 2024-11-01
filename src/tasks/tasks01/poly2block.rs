use crate::utils::poly::{self, polynomial_2_block};
use anyhow::{Ok, Result};
use base64::prelude::*;
use serde_json::Value;

pub fn poly2block(args: &Value) -> Result<Vec<u8>> {
    let coefficients: Vec<u8> = args["coefficients"]
        .as_array()
        .unwrap()
        .into_iter()
        .map(|x| x.as_u64().unwrap() as u8)
        .collect();

    let semantic: String = serde_json::from_value(args["semantic"].clone())?;

    let result = polynomial_2_block(coefficients, &semantic).unwrap();

    Ok(result)
}
