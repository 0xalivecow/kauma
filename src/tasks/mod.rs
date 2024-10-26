use std::collections::HashMap;

use crate::utils::parse::{Responses, Testcase, Testcases};
use tasks01::{block2poly::block2poly, gfmul::gfmul, poly2block::poly2block, sea128::sea128};

use anyhow::{anyhow, Result};
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
        "sea128" => {
            let result = sea128(args)?;
            let json = json!({"output" : result});
            Ok(json)
        }
        "gfmul" => {
            let result = gfmul(args)?;
            let json = json!({"product" : result});
            Ok(json)
        }
        _ => Err(anyhow!(
            "Fatal. No compatible action found. Json data was {:?}. Arguments were; {:?}",
            testcase,
            args
        )),
    }
}

pub fn task_distrubute(testcases: &Testcases) -> Result<Responses> {
    let mut responses: HashMap<String, Value> = HashMap::new();

    for (id, testcase) in &testcases.testcases {
        responses.insert(id.to_owned(), task_deploy(testcase).unwrap());
    }

    Ok(Responses {
        responses: responses,
    })
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
    fn test_task_distribution() -> Result<()> {
        let json = fs::read_to_string("src/test_json/poly2block_example.json").unwrap();
        let parsed = parse_json(json).unwrap();

        let expected = json!({ "responses": { "b856d760-023d-4b00-bad2-15d2b6da22fe": {"block": "ARIAAAAAAAAAAAAAAAAAgA=="}}});

        assert_eq!(
            serde_json::to_value(task_distrubute(&parsed)?).unwrap(),
            serde_json::to_value(expected).unwrap()
        );

        Ok(())
    }

    #[test]
    fn test_task_sea128_task_full() -> Result<()> {
        let json = fs::read_to_string("src/test_json/sea128.json").unwrap();
        let parsed = parse_json(json).unwrap();

        let expected = json!({
            "responses": {
                "b856d760-023d-4b00-bad2-15d2b6da22fe": {
                "output": "D5FDo3iVBoBN9gVi9/MSKQ=="
            },
            "254eaee7-05fd-4e0d-8292-9b658a852245": {
            "output": "yv66vvrO263eyviIiDNEVQ=="
            }
            }
        });

        assert_eq!(
            serde_json::to_value(task_distrubute(&parsed)?).unwrap(),
            serde_json::to_value(expected).unwrap()
        );

        Ok(())
    }
}
