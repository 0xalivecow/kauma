use std::{
    collections::HashMap,
    fmt::format,
    io::{self, Error, ErrorKind},
};

use crate::utils::parse::{Responses, Testcase, Testcases};
use tasks01::poly2block::{self, poly2block};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

mod tasks01;

pub fn task_deploy(testcase: &Testcase) -> Result<Value, String> {
    /*
     * Function to automatially distribute task workloads
     * TODO: Add functionality to also pass semantics
     *
     * */

    let args = &testcase.arguments;

    match testcase.action.as_str() {
        "poly2block" => {
            let coefficients: Vec<u8> = args["coefficients"]
                .as_array()
                .unwrap()
                .into_iter()
                .map(|x| x.as_u64().unwrap() as u8)
                .collect();
            //eprintln!("{:?}", &args["coefficients"]);
            //eprintln!("{:?}", testcase);
            //eprintln!("{:?}", coefficients);
            let result = poly2block(coefficients);
            let json = json!({"block" : result});
            Ok(json)
        }
        _ => Err(format!(
            "Fatal error in task distribution. Data was: {:?}",
            args
        )),
    }
}

// TODO: Is this obsolete? Might delete later.
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
