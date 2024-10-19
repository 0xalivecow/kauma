use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_json::{Result, Value};

#[derive(Debug, Serialize, Deserialize)]
pub struct Testcases {
    pub testcases: HashMap<String, Testcase>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Testcase {
    pub action: String,
    pub arguments: Value,
}

pub fn parse_json(json: String) -> Result<Testcases> {
    let deserialised: Testcases = serde_json::from_str(&json)?;
    Ok(deserialised)
}

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
        assert!(
            !parsed.testcases.is_empty(),
            "Testcases struct was: {:?}",
            parsed.testcases
        );
        assert!(
            !parsed
                .testcases
                .contains_key("\"b856d760-023d-4b00-bad2-15d2b6da22fe\""),
            "Testcases first element was: {:?}",
            parsed.testcases
        );
    }
}
