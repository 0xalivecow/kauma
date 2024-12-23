use anyhow::Result;
use base64::prelude::*;
use serde_json::Value;
use std::io::prelude::*;
use std::net::TcpStream;
use std::usize;

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
        stream.set_nodelay(true).expect("Error on no delay");
        stream.set_nonblocking(false)?;

        // Track value sent to server
        let mut attack_counter: Vec<u8> = vec![0; 16];

        // Amount of q blocks to send to server.
        // TODO:: May be increased via function
        let q_block_count: u16 = 256;

        //Send the first ciphertext chunk
        stream.flush()?;
        stream.write_all(&chunk)?;
        stream.flush()?;

        for i in (0..=15).rev() {
            // Craft length message
            // FIXME: Assignment is redundant for now
            // TODO: Goal is to maybe add speed increase in the future
            let l_msg: [u8; 2] = q_block_count.to_le_bytes();

            // Generate attack blocks
            //  TODO: Collect all and send in one
            let mut payload: Vec<u8> = Vec::with_capacity(2 + 16 * 265);
            payload.extend(l_msg.to_vec());
            for _j in 0..q_block_count {
                // Next byte
                payload.extend(&attack_counter);
                attack_counter[i as usize] += 1;
            }

            stream.write_all(&payload)?;
            stream.flush()?;

            // Read server response
            let mut server_q_resp = [0u8; 256];
            stream.read_exact(&mut server_q_resp)?;

            // extract valid position
            let valid_val = server_q_resp
                .iter()
                .position(|&r| r == 0x01)
                .unwrap_or(0x00) as u8;
            if valid_val == 0x00 {
                eprintln!("No valid found in main loop");
            }
            // Craft next attack vector padding; 0x01, 0x02, ...
            attack_counter[i as usize] = valid_val;

            // Check for edgecase
            if i == 15 {
                let mut l_msg_check: Vec<u8> = vec![0x01, 0x00];
                let mut check_q_block: Vec<u8> = vec![0; 16];
                check_q_block[15] = attack_counter[15];
                check_q_block[14] = !check_q_block[15];

                l_msg_check.extend(check_q_block.as_slice());

                stream.write_all(&l_msg_check)?;
                let mut buf = [0u8; 0x01];
                stream.read(&mut buf)?;
                if buf == [0x01] {
                } else {
                    // Search for second hit
                    let valid_val = 255
                        - server_q_resp
                            .iter()
                            .rev()
                            .position(|&r| r == 0x01)
                            .unwrap_or(0x00) as u8;
                    if valid_val == 0x00 {
                        eprintln!("No valid found");
                    }
                    // Craft next attack vector padding; 0x01, 0x02, ...
                    attack_counter[i as usize] = valid_val;
                }
            }

            if chunk_counter + 1 < cipher_chunks.len() {
                plaintext.push(
                    cipher_chunks[chunk_counter + 1][i]
                        ^ (attack_counter[i as usize] ^ (15 - i as u8 + 1)),
                );
            } else {
                plaintext.push(iv[i] ^ (attack_counter[i as usize] ^ (15 - i as u8 + 1)));
            }
            let range = i;
            for pos in range..=15 {
                let intermediate = attack_counter[pos as usize] ^ (15 - i as u8 + 1);

                attack_counter[pos as usize] = intermediate ^ ((15 - i as u8 + 1) + 1);
            }

            stream.flush()?;

            // Write plaintext
        }
        chunk_counter += 1;
        stream.flush()?;
        drop(stream);
    }

    plaintext.reverse();

    eprintln!("{:02X?}", BASE64_STANDARD.encode(&plaintext));
    Ok(plaintext)
} // the stream is closed here

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connection() -> Result<()> {
        Ok(())
    }
}
