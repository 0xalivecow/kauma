use std::{env::args, fs::canonicalize, slice::Chunks};

use anyhow::{Ok, Result};
use base64::{prelude::BASE64_STANDARD, Engine};
use openssl::derive;
use serde::{Deserialize, Serialize};
use serde_json::{map, Value};

use crate::utils::{
    self,
    ciphers::ghash,
    dff::ddf,
    edf::edf,
    field::FieldElement,
    math::{reverse_bits_in_bytevec, xor_bytes},
    poly::Polynomial,
    sff::sff,
};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CrackAnswer {
    tag: String,
    H: String,
    mask: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct Message {
    ciphertext: Vec<u8>,
    ad: Vec<u8>,
    tag: Vec<u8>,
    l_field: Vec<u8>,
}

fn parse_message(val: &Value) -> Result<(Message, Polynomial)> {
    let ciphertext_text: String = serde_json::from_value(val["ciphertext"].clone())?;
    let mut ciphertext_bytes: Vec<u8> = BASE64_STANDARD.decode(ciphertext_text)?;
    let mut c_len: Vec<u8> = ((ciphertext_bytes.len() * 8) as u64).to_be_bytes().to_vec();

    if ciphertext_bytes.len() % 16 != 0 {
        ciphertext_bytes.append(vec![0u8; 16 - (ciphertext_bytes.len() % 16)].as_mut());
    }

    let ciphertext_chunks: Vec<FieldElement> = ciphertext_bytes
        .chunks(16)
        .into_iter()
        .map(|chunk| FieldElement::new(chunk.to_vec()))
        .collect();

    let ad_text: String = serde_json::from_value(val["associated_data"].clone())?;
    let mut ad_bytes: Vec<u8> = BASE64_STANDARD.decode(ad_text)?;
    let mut l_field: Vec<u8> = ((ad_bytes.len() * 8) as u64).to_be_bytes().to_vec();

    if ad_bytes.len() % 16 != 0 || ad_bytes.is_empty() {
        ad_bytes.append(vec![0u8; 16 - (ad_bytes.len() % 16)].as_mut());
    }

    let ad_chunks: Vec<FieldElement> = ad_bytes
        .chunks(16)
        .into_iter()
        .map(|chunk| FieldElement::new(chunk.to_vec()))
        .collect();

    let tag_text: String = serde_json::from_value(val["tag"].clone()).unwrap_or("".to_string());
    let tag_bytes: Vec<u8> = BASE64_STANDARD.decode(tag_text)?;
    let tag_field: FieldElement = FieldElement::new(tag_bytes.clone());

    l_field.append(c_len.as_mut());

    // Combine all data
    let mut combined: Vec<FieldElement> =
        Vec::with_capacity(ad_chunks.len() + ciphertext_chunks.len() + 1);
    combined.extend(ad_chunks);
    combined.extend(ciphertext_chunks.clone());
    combined.push(FieldElement::new(l_field.clone()));
    combined.push(tag_field);

    combined.reverse();

    let h_poly: Polynomial = Polynomial::new(combined);

    Ok((
        Message {
            ciphertext: ciphertext_bytes,
            ad: ad_bytes,
            tag: tag_bytes,
            l_field,
        },
        h_poly,
    ))
}

pub fn gcm_crack(args: &Value) -> Result<CrackAnswer> {
    // Prepare first equation
    let (m1_data, m1_h_poly) = parse_message(&args["m1"])?;

    let (_, m2_h_poly) = parse_message(&args["m2"])?;

    let (m3_data, _) = parse_message(&args["m3"])?;

    let combine_poly = m1_h_poly + m2_h_poly;

    let combine_sff = sff(combine_poly.monic());

    let mut combine_ddf: Vec<(Polynomial, u128)> = vec![];
    for (factor, _) in combine_sff {
        combine_ddf.extend(ddf(factor));
    }

    let mut combine_edf: Vec<Polynomial> = vec![];
    for (factor, degree) in combine_ddf {
        if degree == 1 {
            combine_edf.extend(edf(factor, degree as u32));
        }
    }

    let mut m3_auth_tag: Vec<u8> = vec![];
    let mut h_candidate: FieldElement = FieldElement::zero();
    let mut eky0: Vec<u8> = vec![];
    for candidate in combine_edf {
        if candidate.degree() == 1 {
            h_candidate = candidate.extract_component(0);
            let m1_ghash = ghash(
                reverse_bits_in_bytevec(h_candidate.to_vec()),
                m1_data.ad.clone(),
                m1_data.ciphertext.clone(),
                m1_data.l_field.clone(),
            )
            .unwrap();

            eky0 = xor_bytes(&m1_data.tag, m1_ghash).unwrap();
            eprintln!("eky0: {:?}", BASE64_STANDARD.encode(eky0.clone()));

            let m3_ghash = ghash(
                reverse_bits_in_bytevec(h_candidate.to_vec()),
                m3_data.ad.clone(),
                m3_data.ciphertext.clone(),
                m3_data.l_field.clone(),
            )
            .unwrap();

            m3_auth_tag = xor_bytes(&eky0, m3_ghash).unwrap();
            eprintln!(
                "M3 auth tag: {:02X?}",
                BASE64_STANDARD.encode(m3_auth_tag.clone())
            );

            if m3_auth_tag == m3_data.tag {
                break;
            } else {
                eprintln!("H candidate not valid");
            }
        }
    }

    let (forgery_data, _) = parse_message(&args["forgery"])?;

    let forgery_ghash = ghash(
        reverse_bits_in_bytevec(h_candidate.to_vec()),
        forgery_data.ad.clone(),
        forgery_data.ciphertext.clone(),
        forgery_data.l_field.clone(),
    )
    .unwrap();

    let forgery_auth_tag = xor_bytes(&eky0, forgery_ghash).unwrap();

    if eky0.is_empty() {
        eky0 = vec![0; 16];
    }

    Ok(CrackAnswer {
        tag: BASE64_STANDARD.encode(forgery_auth_tag),
        H: h_candidate.to_b64(),
        mask: BASE64_STANDARD.encode(eky0),
    })
}
