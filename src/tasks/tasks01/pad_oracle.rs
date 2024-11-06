use anyhow::Result;
use base64::prelude::*;
use serde_json::Value;
use std::io::prelude::*;
use std::net::TcpStream;
use std::time::Duration;
use std::{thread, usize};

pub fn padding_oracle(args: &Value) -> Result<Vec<u8>> {
    let hostname: String = serde_json::from_value(args["hostname"].clone())?;

    let port_val: Value = serde_json::from_value(args["port"].clone())?;
    let port: u64 = port_val.as_u64().expect("Failure in parsing port number");

    let iv_string: String = serde_json::from_value(args["iv"].clone())?;
    let iv: Vec<u8> = BASE64_STANDARD.decode(iv_string)?;

    let cipher_text: String = serde_json::from_value(args["ciphertext"].clone())?;
    let ciphertext: Vec<u8> = BASE64_STANDARD.decode(cipher_text)?;

    // Initialise tracker to adapt correct byte
    let byte_counter = 15;
    eprintln!("byte_counter is: {}", byte_counter);

    let mut plaintext: Vec<u8> = vec![];
    eprintln!("Ciphertext: {:002X?}", ciphertext);

    let cipher_chunks: Vec<&[u8]> = ciphertext.chunks(16).rev().collect();
    let mut chunk_counter = 0;

    for chunk in &cipher_chunks {
        let mut stream = TcpStream::connect(format!("{}:{}", hostname, port))?;
        stream.set_nonblocking(false)?;

        // Track value sent to server
        let mut attack_counter: Vec<u8> = vec![0; 16];

        // Amount of q blocks to send to server.
        // TODO:: May be increased via function
        let q_block_count: u16 = 255;

        //Send the first ciphertext chunk
        eprintln!("Sending Ciphertext chunk: {:002X?}", chunk);
        stream.flush()?;
        stream.write_all(&chunk)?;
        stream.flush()?;

        for i in (0..=15).rev() {
            // Craft length message
            // FIXME: Assignment is redundant for now
            // TODO: Goal is to maybe add speed increase in the future
            let l_msg: [u8; 2] = q_block_count.to_le_bytes();
            //eprintln!("Sending l_msg: {:02X?}", l_msg);
            stream.write_all(&l_msg)?;
            stream.flush()?;
            //eprintln!("L_msg sent");

            // Generate attack blocks
            for j in 0..q_block_count {
                // Next byte
                //eprintln!("Sending attack block: {:02X?}", attack_counter);

                //thread::sleep(Duration::from_millis(1000));
                stream.write_all(&attack_counter)?;
                stream.flush()?;
                attack_counter[i as usize] += 1;
            }

            // Read server response
            let mut buf = [0u8; 0xFF];
            stream.read_exact(&mut buf)?;
            //eprintln!("{:02X?}", buf);

            // extract valid position
            let valid_val = buf.iter().position(|&r| r == 0x01).expect("No valid found") as u8;
            //eprintln!("Valid value found: {:02X?}", valid_val);

            // Craft next attack vector padding; 0x01, 0x02, ...
            attack_counter[i as usize] = valid_val;

            if chunk_counter + 1 < cipher_chunks.len() {
                eprintln!("XOR Next Ciph block");
                plaintext.push(
                    cipher_chunks[chunk_counter + 1][i]
                        ^ (attack_counter[i as usize] ^ (15 - i as u8 + 1)),
                );
            } else {
                eprintln!("XOR IV");

                plaintext.push(iv[i] ^ (attack_counter[i as usize] ^ (15 - i as u8 + 1)));
            }
            //eprintln!("Attack counter after set: {:02X?}", attack_counter);
            for pos in i..=15 {
                //eprintln!("i is: {:02X?}", i);
                //eprintln!("i + 1 is: {:02X?}", ((16 - i) as u8).to_le());
                /*
                eprintln!(
                    "attack_counter[pos as usize]: {:02X?}",
                    attack_counter[pos as usize]
                );
                eprintln!(
                    "attack_counter[pos as usize] ^ 0x02 {:02X?}",
                    attack_counter[pos as usize] ^ (15 - i as u8 + 1)
                );
                */
                let intermediate = attack_counter[pos as usize] ^ (15 - i as u8 + 1);

                attack_counter[pos as usize] = intermediate ^ ((15 - i as u8 + 1) + 1);
            }
            stream.flush()?;

            // Write plaintext
            //eprintln!("{:02X?}", plaintext);
        }
        chunk_counter += 1;
        stream.flush()?;
        // break;
        drop(stream);
    }

    plaintext.reverse();

    eprintln!("{:02X?}", BASE64_STANDARD.encode(&plaintext));
    Ok(plaintext)
} // the stream is closed here

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_connection() -> Result<()> {
        Ok(())
    }
}
