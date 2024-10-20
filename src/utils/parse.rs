use std::{collections::HashMap, io::Result};

use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Serialize, Deserialize)]
pub struct Testcases {
    pub testcases: HashMap<String, Testcase>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Testcase {
    pub action: String,
    pub arguments: Value,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Responses {
    pub responses: HashMap<String, Value>,
}

pub fn parse_json(json: String) -> Result<Testcases> {
    let deserialised: Testcases = serde_json::from_str(&json)?;
    Ok(deserialised)
}

/*
pub fn generate_response_payload(
    testcase_id: String,
    payload: Value,
) -> Result<HashMap<String, Value>> {
    let mut hashmap = HashMap::new();
    hashmap.insert(testcase_id, payload);
    Ok(hashmap)
}

pub fn generate_response(payloads: HashMap<String, Value>) -> Result<Value> {
    let response: Responses = Responses {
        responses: payloads,
    };

    Ok(serde_json::to_value(response).unwrap())
}
*/

#[cfg(test)]
mod tests {
    use std::fs;

    use serde_json::json;

    // Note this useful idiom: importing names from outer (for mod tests) scope.
    use super::*;

    #[test]
    fn test_json_parsing() {
        let json = fs::read_to_string("src/test_json/parse_example.json").unwrap();
        let parsed = parse_json(json).unwrap();

        /*
         * Test if struct is deserialised at all
         * */
        assert!(
            !parsed.testcases.is_empty(),
            "Testcases struct was: {:?}",
            parsed.testcases
        );

        /*
         * Test id the keys are set correctly in the hashmap
         * */
        assert!(
            !parsed
                .testcases
                .contains_key("\"b856d760-023d-4b00-bad2-15d2b6da22fe\""),
            "Testcases first elemient was: {:?}",
            parsed.testcases
        );
        assert!(
            !parsed
                .testcases
                .contains_key("\"254eaee7-05fd-4e0d-8292-9b658a852245\""),
            "Testcases first element was: {:?}",
            parsed.testcases
        );
        assert!(
            !parsed
                .testcases
                .contains_key("\"affbf4fc-4d2a-41e3-afe0-a79e1d174781\""),
            "Testcases first element was: {:?}",
            parsed.testcases
        );

        /*
         * Test if the actions are parsed correctly
         * */
        let testcase_1 = &parsed
            .testcases
            .get("b856d760-023d-4b00-bad2-15d2b6da22fe")
            .unwrap();
        assert_eq!(
            testcase_1.action, "add_numbers",
            "Test case was: {:?}",
            testcase_1.action
        );
    }
    /*
    #[test]
    fn test_response_payload_generation() {
        let testcase_id = "b856d760-023d-4b00-bad2-15d2b6da22fe";
        let value: Value = json!({"sum" : serde_json::Number::from(666)});
        let payload = serde_json::to_string(
            &generate_response_payload(testcase_id.to_owned(), value).unwrap(),
        )
        .unwrap();

        let expected = r#"{"b856d760-023d-4b00-bad2-15d2b6da22fe":{"sum":666}}"#;

        assert_eq!(payload, expected);
    }

    #[test]
    fn test_response_generation() {
        let testcase1_id = "b856d760-023d-4b00-bad2-15d2b6da22fe";
        let value1: Value = json!({"sum" : serde_json::Number::from(666)});
        let payload1 = generate_response_payload(testcase1_id.to_owned(), value1).unwrap();
        let testcase2_id = "b856d760-023d-4b00-bad2-15d2b6da22fe";
        let value2: Value = json!({"sum" : serde_json::Number::from(666)});
        let payload2 = generate_response_payload(testcase2_id.to_owned(), value2).unwrap();
        let testcase3_id = "b856d760-023d-4b00-bad2-15d2b6da22fe";
        let value3: Value = json!({"sum" : serde_json::Number::from(666)});
        let payload3 = generate_response_payload(testcase3_id.to_owned(), value3).unwrap();

        let mut responses_vec: HashMap<String, Value> = vec![];

        responses_vec.insert(payload1);
        responses_vec.push(payload2);
        responses_vec.push(payload3);
        let response = generate_response(responses_vec).unwrap();

        let expected = json!(
        {
        "responses": {
        "b856d760-023d-4b00-bad2-15d2b6da22fe": {
        "sum": 357
        },
        "254eaee7-05fd-4e0d-8292-9b658a852245": {
        "sum": 777
        },
        "affbf4fc-4d2a-41e3-afe0-a79e1d174781": {
        "difference": -120213
        }
        }
        });

        eprintln!("{}", serde_json::to_string(&response).unwrap());
        eprintln!("{}", serde_json::to_string(&expected).unwrap());
        assert_eq!(response, expected);
    }*/
}
