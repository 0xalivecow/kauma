use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Serialize, Deserialize)]
pub struct Testcases {
    testcase: Vec<Testcase>,
}

#[derive(Serialize, Deserialize)]
pub struct Testcase {
    uuid: String,
    action: String,
    arguments: Value,
}