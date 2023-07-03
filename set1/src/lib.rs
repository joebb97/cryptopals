use anyhow::{anyhow, bail};
use base64::engine::general_purpose;
use std::io::Write;

// Challenge 1
pub fn hex_to_base64(hex: &[u8]) -> anyhow::Result<Vec<u8>> {
    let decoded = hex::decode(hex)?;
    let ret = Vec::new();
    let mut enc = base64::write::EncoderWriter::new(ret, &general_purpose::STANDARD);
    enc.write_all(&decoded)?;
    Ok(enc.into_inner())
}

// Challenge 2
pub fn fixed_xor(buf1: &[u8], buf2: &[u8]) -> anyhow::Result<Vec<u8>> {
    if buf1.len() != buf2.len() {
        bail!("Buffers are not the same fixed size {:?} {:?}", buf1, buf2);
    }
    let ret: Vec<u8> = buf1
        .iter()
        .zip(buf2.iter())
        .map(|(b1, b2)| b1 ^ b2)
        .collect();
    Ok(ret)
}

pub fn fixed_xor_single(buf1: &[u8], single_char: u8) -> Vec<u8> {
    // let mut ret = vec![0; buf1.len()];
    // for (idx, b) in buf1.iter().enumerate() {
    //     ret[idx]  = b ^ single_char;
    // }
    // ret
    buf1.iter().map(|b| b ^ single_char).collect()
}

pub fn fixed_xor_single_inplace(buf1: &mut [u8], single_char: u8) {
    for b in buf1.iter_mut() {
        *b ^= single_char;
    }
}

const ENGLISH_FREQ: [f64; 26] = [
    0.08167, 0.01492, 0.02782, 0.04253, 0.12702, 0.02228, 0.02015, // A-G
    0.06094, 0.06966, 0.00153, 0.00772, 0.04025, 0.02406, 0.06749, // H-N
    0.07507, 0.01929, 0.00095, 0.05987, 0.06327, 0.09056, 0.02758, // O-U
    0.00978, 0.02360, 0.00150, 0.01974, 0.00074, // V-Z
];

#[allow(dead_code)]
fn get_chi2(bytes: &[u8]) -> f64 {
    let count: &mut [u32] = &mut [0; 26];
    let mut ignored = 0;
    for byte in bytes {
        let byte = usize::from(*byte);
        match byte {
            65..=90 => count[byte - 65] += 1,
            97..=122 => count[byte - 97] += 1,
            32..=126 | 9 | 10 | 13 => ignored += 1,
            _ => (),
        }
        if (65..=90).contains(&byte) {
            count[byte - 65] += 1;
        } else if (97..122).contains(&byte) {
            count[byte - 97] += 1;
        }
    }
    let mut chi2 = 0.0;
    for i in 0..26 {
        let observed = f64::from(count[i]);
        let expected = f64::from(u32::try_from(bytes.len()).unwrap() - ignored) * ENGLISH_FREQ[i];
        let difference = observed - expected;
        chi2 += (difference * difference) / expected;
    }
    chi2
}

// based on https://github.com/Lukasa/cryptopals/blob/master/cryptopals/challenge_one/three.py
pub fn englishness(cand_plaintext: &[u8]) -> f64 {
    let mut byte_counts = [0_u32; 256];
    for x in cand_plaintext.iter() {
        let mut c = char::from(*x);
        if c.is_ascii_uppercase() {
            c.make_ascii_lowercase();
            let idx = u8::try_from(c).unwrap(); // won't panic since we check ascii uppercase
            byte_counts[idx as usize] += 1;
            continue;
        }
        byte_counts[*x as usize] += 1;
    }
    let total_characters = cand_plaintext.len() as u32;
    let mut total = 0.;
    for idx in 97..=122 {
        let freq = ENGLISH_FREQ[idx - 97];
        let val = byte_counts[idx];
        let a = (freq * (val as f64 / total_characters as f64)).sqrt();
        total += a;
    }
    total
    // byte_counts
    //     .iter()
    //     .enumerate()
    //     .map(|(idx, val)| {
    //         if (97..=122).contains(&idx) {
    //             let idx = idx - 97;
    //             let freq = ENGLISH_FREQ[idx];
    //             let a = (freq * (*val as f64 / total_characters as f64)).sqrt();
    //             return a;
    //         }
    //         0.0
    //     })
    //     .sum()
}

// Find Single Byte Key
pub fn single_byte_key_decrypt(cipher: &[u8]) -> (f64, char, Vec<u8>) {
    #[derive(Default)]
    struct RetData {
        cand_plaintext: Vec<u8>,
        frequency_score: f64,
        cand_char: char,
    }

    let mut best: Option<RetData> = None;
    for cand in 0..=255 {
        let cand_char = char::from(cand);

        // let cand_key = vec![cand; cipher.len()];
        let cand_plaintext = fixed_xor_single(cipher, cand);

        let frequency_score: f64 = englishness(&cand_plaintext);
        let cand = RetData {
            cand_plaintext,
            frequency_score,
            cand_char,
        };
        best = match best {
            None => Some(cand),
            Some(top) => {
                match top.frequency_score.total_cmp(&frequency_score) {
                    std::cmp::Ordering::Less => Some(cand),
                    std::cmp::Ordering::Equal => {
                        let lowercase_counts = top
                            .cand_plaintext
                            .iter()
                            .zip(cand.cand_plaintext.iter())
                            .fold((0, 0), |acc, (left_byte, right_byte)| {
                                (
                                    if char::from(*left_byte).is_lowercase() {
                                        acc.0 + 1
                                    } else {
                                        acc.0
                                    },
                                    if char::from(*right_byte).is_lowercase() {
                                        acc.1 + 1
                                    } else {
                                        acc.1
                                    },
                                )
                            });
                        Some(if lowercase_counts.0 > lowercase_counts.1 {
                            top
                        } else {
                            cand
                        })
                    }
                    _ => Some(top)
                }
            }
            // Some(top) if top.frequency_score < frequency_score => Some(cand),
            // Some(top) if (top.frequency_score - frequency_score).abs() < f64::EPSILON =>             }
            // _ => best,
        };
    }
    let best = best.unwrap();
    (best.frequency_score, best.cand_char, best.cand_plaintext)
    // let mut best: Vec<RetData> = (0..=255)
    //     .map(|cand| {
    //         let cand_char = char::from(cand);

    //         // let cand_key = vec![cand; cipher.len()];
    //         let cand_plaintext = fixed_xor_single(cipher, cand);

    //         // let frequency_score: f64 = englishness(&cand_plaintext);
    //         let frequency_score: f64 = get_chi2(&cand_plaintext);
    //         // let frequency_score = 0.;

    //         RetData {
    //             cand_plaintext,
    //             frequency_score,
    //             cand_char,
    //         }
    //     })
    //     .collect();
    // let max = best
    //     .iter()
    //     .enumerate()
    //     .max_by(|a, b| a.1.frequency_score.total_cmp(&b.1.frequency_score))
    //     .ok_or(anyhow!("No items?")).unwrap()
    //     .0;
    // best.swap(0, max);
    // let max = best[1..]
    //     .iter()
    //     .enumerate()
    //     .max_by(|a, b| a.1.frequency_score.total_cmp(&b.1.frequency_score))
    //     .ok_or(anyhow!("No items?")).unwrap()
    //     .0;
    // best.swap(1, max + 1);
    // // if cfg!(debug_assertions) {
    // //     best.iter().rev().for_each(|item| {
    // //         let copy = item.cand_plaintext.clone();
    // //         let the_string = String::from_utf8(copy);
    // //         println!(
    // //             "{:?} yields {:?} with {:?}",
    // //             item.cand_char, item.frequency_score, the_string
    // //         )
    // //     });
    // // }
    // let mut best_idx = 0;
    // if (best[0].frequency_score - best[1].frequency_score).abs() < f64::EPSILON {
    //     let lowercase_counts = best[0]
    //         .cand_plaintext
    //         .iter()
    //         .zip(best[1].cand_plaintext.iter())
    //         .fold((0, 0), |acc, (left_byte, right_byte)| {
    //             (
    //                 if char::from(*left_byte).is_lowercase() {
    //                     acc.0 + 1
    //                 } else {
    //                     acc.0
    //                 },
    //                 if char::from(*right_byte).is_lowercase() {
    //                     acc.1 + 1
    //                 } else {
    //                     acc.1
    //                 },
    //             )
    //         });
    //     if lowercase_counts.0 < lowercase_counts.1 {
    //         best_idx = 1;
    //     }
    // }
    // (
    //     best[best_idx].frequency_score,
    //     best[best_idx].cand_char,
    //     best[best_idx].cand_plaintext.clone(),
    // )
}

// Challenge 4
pub fn detect_single_character_xor() -> (f64, char, Vec<u8>) {
    let lines = include_str!("challenge4-data.txt").lines();
    lines
        .map(|line| {
            let line = hex::decode(line).unwrap();
            single_byte_key_decrypt(&line)
            // let clone = ans.2.clone();
            // if let Ok(cand) = String::from_utf8(clone) {
            //     println!("{:?} {:?}", ans.0, cand);
            // }
        })
        .max_by(|a, b| (a.0).total_cmp(&b.0))
        .unwrap()
}

#[cfg(test)]
mod tests {
    use crate::*;

    #[test]
    fn test_hex_to_base64() {
        let ans = hex_to_base64(b"49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d");
        assert_eq!(
            ans.unwrap(),
            b"SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
        )
    }

    #[test]
    fn test_fixed_or() {
        let out = fixed_xor(
            &hex::decode(b"1c0111001f010100061a024b53535009181c").unwrap(),
            &hex::decode(b"686974207468652062756c6c277320657965").unwrap(),
        )
        .unwrap();
        let ans = hex::decode(b"746865206b696420646f6e277420706c6179").unwrap();
        assert_eq!(out, ans)
    }

    #[test]
    fn test_single_byte_key_decrypt() {
        let ans = single_byte_key_decrypt(
            &hex::decode(b"1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
                .unwrap(),
        );
        let as_string = String::from_utf8(ans.2).unwrap();
        assert_eq!(as_string, "Cooking MC's like a pound of bacon");
        // technically x and X have the same score, but X looks nicer and just happens to win
        assert_eq!(ans.1, 'X');
    }

    #[test]
    fn test_detect_single_character_xor() {
        let best = detect_single_character_xor();
        let as_string = String::from_utf8(best.2).unwrap();
        assert_eq!(as_string, "Now that the party is jumping\n");
        assert_eq!(best.1, '5');
    }
}
