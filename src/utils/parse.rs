use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct Testcases {
    testcase: Vec<Testcase>,
}

#[derive(Serialize, Deserialize)]
pub struct Testcase {
    uuid: String,
    action: String,
    arguments: Vec<Argument>,
}

#[derive(Serialize, Deserialize)]
pub struct Argument {
    uuid: String,
    action: String,
    arguments: Vec<Argument>,
}
