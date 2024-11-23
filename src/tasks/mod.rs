use base64::prelude::*;

use std::collections::HashMap;

use crate::utils::parse::{Responses, Testcase, Testcases};
use tasks01::{
    block2poly::block2poly,
    gcm::{gcm_decrypt, gcm_encrypt},
    gfmul::gfmul_task,
    pad_oracle::padding_oracle,
    pfmath::{
        gfdiv, gfpoly_add, gfpoly_diff, gfpoly_divmod, gfpoly_make_monic, gfpoly_mul, gfpoly_pow,
        gfpoly_powmod, gfpoly_sort, gfpoly_sqrt,
    },
    poly2block::poly2block,
    sea128::sea128,
    xex::fde_xex,
};

use anyhow::{anyhow, Result};
use serde_json::{json, Value};

pub mod tasks01;

pub fn task_deploy(testcase: &Testcase) -> Result<Value> {
    /*
     * Function to automatially distribute task workloads
     * TODO: Add functionality to also pass semantics
     *
     * */

    let args = &testcase.arguments;

    match testcase.action.as_str() {
        "poly2block" => {
            let result = BASE64_STANDARD.encode(poly2block(args)?);
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
            let result = BASE64_STANDARD.encode(gfmul_task(args)?);
            let json = json!({"product" : result});
            Ok(json)
        }
        "xex" => {
            let result = BASE64_STANDARD.encode(fde_xex(args)?);
            let json = json!({"output" : result});

            Ok(json)
        }
        "gcm_encrypt" => {
            let (ciphertext, auth_tag, l_field, auth_key_h) = gcm_encrypt(args)?;
            let out_ciph = BASE64_STANDARD.encode(&ciphertext);
            let out_tag = BASE64_STANDARD.encode(&auth_tag);
            let out_l = BASE64_STANDARD.encode(&l_field);
            let out_h = BASE64_STANDARD.encode(&auth_key_h);

            let json = json!({"ciphertext" : out_ciph, "tag" : out_tag, "L" : out_l, "H" : out_h});

            Ok(json)
        }
        "gcm_decrypt" => {
            let (plaintext, valid) = gcm_decrypt(args)?;
            let out_plain = BASE64_STANDARD.encode(&plaintext);
            let json = json!({ "authentic" : valid, "plaintext" : out_plain});

            Ok(json)
        }
        "padding_oracle" => {
            let plaintext = padding_oracle(args)?;
            let out_plain = BASE64_STANDARD.encode(&plaintext);
            let json = json!({"plaintext" : out_plain});

            Ok(json)
        }
        "gfpoly_add" => {
            let result = gfpoly_add(args)?;
            let json = json!({"S" : result.to_c_array()});

            Ok(json)
        }
        "gfpoly_mul" => {
            let result = gfpoly_mul(args)?;
            let json = json!({"P" : result.to_c_array()});

            Ok(json)
        }
        "gfpoly_pow" => {
            let result = gfpoly_pow(args)?;
            let json = json!({"Z" : result.to_c_array()});

            Ok(json)
        }
        "gfdiv" => {
            let result = gfdiv(args)?;
            let out = BASE64_STANDARD.encode(result);
            let json = json!({"q" : out});

            Ok(json)
        }
        "gfpoly_divmod" => {
            let result = gfpoly_divmod(args)?;
            let json = json!({"Q" : result.0.to_c_array(), "R" : result.1.to_c_array()});

            Ok(json)
        }
        "gfpoly_powmod" => {
            let result = gfpoly_powmod(args)?;
            let json = json!({"Z" : result.to_c_array()});

            Ok(json)
        }
        "gfpoly_sort" => {
            let sorted_array = gfpoly_sort(args)?;
            let mut result: Vec<Vec<String>> = vec![];

            for poly in sorted_array {
                result.push(poly.to_c_array());
            }

            let json = json!({"sorted_polys" : json!(result)});

            Ok(json)
        }
        "gfpoly_make_monic" => {
            let result = gfpoly_make_monic(args)?;
            let json = json!({"A*" : result.to_c_array()});

            Ok(json)
        }
        "gfpoly_sqrt" => {
            let result = gfpoly_sqrt(args)?;
            let json = json!({"S" : result.to_c_array()});

            Ok(json)
        }
        "gfpoly_diff" => {
            let result = gfpoly_diff(args)?;
            let json = json!({"F'" : result.to_c_array()});

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
        let json = fs::read_to_string("test_json/poly2block_example.json").unwrap();
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
        let json = fs::read_to_string("test_json/poly2block_example.json").unwrap();
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
        let json = fs::read_to_string("test_json/sea128.json").unwrap();
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

    #[test]
    fn test_task_gfmul_full() -> Result<()> {
        let json = fs::read_to_string("test_json/gfmul_test.json").unwrap();
        let parsed = parse_json(json).unwrap();

        let expected = json!({ "responses": { "b856d760-023d-4b00-bad2-15d2b6da22fe": {"product": "hSQAAAAAAAAAAAAAAAAAAA=="}}});

        assert_eq!(
            serde_json::to_value(task_distrubute(&parsed)?).unwrap(),
            serde_json::to_value(expected).unwrap()
        );

        Ok(())
    }

    #[test]
    fn test_task_xex_full() -> Result<()> {
        let json = fs::read_to_string("test_json/xex_tests.json").unwrap();
        let parsed = parse_json(json).unwrap();

        let expected = json!({ "responses": {
        "0192d428-3913-762b-a702-d14828eae1f8": {"output": "mHAVhRCKPAPx0BcufG5BZ4+/CbneMV/gRvqK5rtLe0OJgpDU5iT7z2P0R7gEeRDO"},
        "0192d428-3913-7168-a3bb-69c258c74dc1": {"output": "SGV5IHdpZSBrcmFzcyBkYXMgZnVua3Rpb25pZXJ0IGphIG9mZmVuYmFyIGVjaHQu"}
        }});

        assert_eq!(
            serde_json::to_value(task_distrubute(&parsed)?).unwrap(),
            serde_json::to_value(expected).unwrap()
        );

        Ok(())
    }

    #[test]
    fn test_task_gcm_encrypt_aes_case() -> Result<()> {
        let json = fs::read_to_string("test_json/gcm_encrypt.json").unwrap();
        let parsed = parse_json(json).unwrap();

        let expected = json!({ "responses" : { "b856d760-023d-4b00-bad2-15d2b6da22fe" : {
        "ciphertext": "ET3RmvH/Hbuxba63EuPRrw==",
        "tag": "Mp0APJb/ZIURRwQlMgNN/w==",
        "L": "AAAAAAAAAEAAAAAAAAAAgA==",
        "H": "Bu6ywbsUKlpmZXMQyuGAng=="
        }}});

        assert_eq!(
            serde_json::to_value(task_distrubute(&parsed)?).unwrap(),
            serde_json::to_value(expected).unwrap()
        );

        Ok(())
    }

    #[test]
    fn test_task_gcm_encrypt_sea_case() -> Result<()> {
        let json = fs::read_to_string("test_json/gcm_encrypt_sea.json").unwrap();
        let parsed = parse_json(json).unwrap();

        let expected = json!({ "responses" : { "b856d760-023d-4b00-bad2-15d2b6da22fe" : {
        "ciphertext": "0cI/Wg4R3URfrVFZ0hw/vg==",
        "tag": "ysDdzOSnqLH0MQ+Mkb23gw==",
        "L": "AAAAAAAAAEAAAAAAAAAAgA==",
        "H": "xhFcAUT66qWIpYz+Ch5ujw=="
        }}});

        assert_eq!(
            serde_json::to_value(task_distrubute(&parsed)?).unwrap(),
            serde_json::to_value(expected).unwrap()
        );

        Ok(())
    }

    #[test]
    fn test_task_gcm_decrypt_aes_case() -> Result<()> {
        let json = fs::read_to_string("test_json/gcm_decrypt_aes.json").unwrap();
        let parsed = parse_json(json).unwrap();

        let expected = json!({ "responses" : { "b856d760-023d-4b00-bad2-15d2b6da22fe" : {
        "plaintext": "RGFzIGlzdCBlaW4gVGVzdA==",
        "authentic": true,
        }}});

        assert_eq!(
            serde_json::to_value(task_distrubute(&parsed)?).unwrap(),
            serde_json::to_value(expected).unwrap()
        );

        Ok(())
    }

    #[test]
    fn test_task_gcm_decrypt_sea_case() -> Result<()> {
        let json = fs::read_to_string("test_json/gcm_decrypt_sea.json").unwrap();
        let parsed = parse_json(json).unwrap();

        let expected = json!({ "responses" : { "b856d760-023d-4b00-bad2-15d2b6da22fe" : {
        "plaintext": "RGFzIGlzdCBlaW4gVGVzdA==",
        "authentic": true,
        }}});

        assert_eq!(
            serde_json::to_value(task_distrubute(&parsed)?).unwrap(),
            serde_json::to_value(expected).unwrap()
        );

        Ok(())
    }

    #[test]
    fn test_task_gcm_gfpoly_add() -> Result<()> {
        let json = fs::read_to_string("test_json/gcm_decrypt_sea.json").unwrap();
        let parsed = parse_json(json).unwrap();

        let expected = json!({ "responses" : { "b856d760-023d-4b00-bad2-15d2b6da22fe" : {
        "plaintext": "RGFzIGlzdCBlaW4gVGVzdA==",
        "authentic": true,
        }}});

        assert_eq!(
            serde_json::to_value(task_distrubute(&parsed)?).unwrap(),
            serde_json::to_value(expected).unwrap()
        );

        Ok(())
    }
}
