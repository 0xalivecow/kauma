use std::{
    collections::HashMap,
    fmt::format,
    io::{self, Error, ErrorKind},
};

use crate::utils::parse::{Responses, Testcase, Testcases};
use tasks01::{
    block2poly::block2poly,
    poly2block::{self, poly2block},
};

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

mod tasks01;

pub fn task_deploy(testcase: &Testcase) -> Result<Value> {
    /*
     * Function to automatially distribute task workloads
     * TODO: Add functionality to also pass semantics
     *
     * */

    let args = &testcase.arguments;

    match testcase.action.as_str() {
        "poly2block" => {
            let result = poly2block(args);
            let json = json!({"block" : result});
            Ok(json)
        }
        "block2poly" => {
            let result: Vec<u8> = block2poly(args)?;
            //TODO: Sort Coefficients
            let json = json!({"coefficients" : result});
            Ok(json)
        }
        _ => Err(anyhow!("Fatal. No compatible action found")),
    }
}

pub fn task_distrubute(testcases: &Testcases) -> Responses {
    let mut responses: HashMap<String, Value> = HashMap::new();

    for (id, testcase) in &testcases.testcases {
        responses.insert(id.to_owned(), task_deploy(testcase).unwrap());
    }

    Responses {
        responses: responses,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::parse::parse_json;
    use std::fs;

    #[test]
    fn test_task_deploy() {
        let json = fs::read_to_string("src/test_json/poly2block_example.json").unwrap();
        let parsed = parse_json(json).unwrap();
        let testcase = parsed
            .testcases
            .get("b856d760-023d-4b00-bad2-15d2b6da22fe")
            .unwrap();

        assert!(
            task_deploy(&testcase).is_ok(),
            "Error: Function result was: {:?}",
            task_deploy(&testcase)
        );
    }

    #[test]
    fn test_task_distribution() {
        let json = fs::read_to_string("src/test_json/poly2block_example.json").unwrap();
        let parsed = parse_json(json).unwrap();

        let expected = json!({ "responses": { "b856d760-023d-4b00-bad2-15d2b6da22fe": {"block": "ARIAAAAAAAAAAAAAAAAAgA=="}}});

        assert_eq!(
            serde_json::to_value(task_distrubute(&parsed)).unwrap(),
            serde_json::to_value(expected).unwrap()
        );
    }
}
