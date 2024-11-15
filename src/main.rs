use std::{
    env::{self},
    fs,
};

// TESTING

use anyhow::Result;

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    let path_to_workload = &args[1];

    let json = fs::read_to_string(path_to_workload).unwrap();
    let workload = kauma::utils::parse::parse_json(json)?;

    let response = kauma::tasks::task_distrubute(&workload)?;
    println!("{}", serde_json::to_string(&response)?);

    Ok(())
}
