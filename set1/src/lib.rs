use aes::cipher::{generic_array::GenericArray, BlockDecrypt, KeyInit};
use aes::Aes128Dec;
use anyhow::bail;
use base64::engine::general_purpose;
use std::collections::HashSet;
use std::io::Write;

pub const AES_128_BLOCK_SIZE: usize = 16;
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

pub fn fixed_xor_inplace(buf1: &mut [u8], buf2: &[u8]) -> anyhow::Result<()> {
    if buf1.len() != buf2.len() {
        bail!("Buffers are not the same fixed size {:?} {:?}", buf1, buf2);
    }
    buf1.iter_mut()
        .zip(buf2.iter())
        .for_each(|(b1, b2)| *b1 ^= b2);
    Ok(())
}

pub fn fixed_xor_single(buf1: &[u8], single_char: u8) -> Vec<u8> {
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
}

// Find Single Byte Key
pub fn single_byte_key_decrypt(ciphertext: &[u8]) -> (f64, u8, Vec<u8>) {
    #[derive(Default)]
    struct RetData {
        cand_plaintext: Vec<u8>,
        frequency_score: f64,
        cand_byte: u8,
    }

    let mut best: Option<RetData> = None;
    for cand in 0..=255 {
        // let cand_key = vec![cand; cipher.len()];
        let cand_plaintext = fixed_xor_single(ciphertext, cand);

        let frequency_score: f64 = englishness(&cand_plaintext);
        let cand = RetData {
            cand_plaintext,
            frequency_score,
            cand_byte: cand,
        };
        best = match best {
            None => Some(cand),
            Some(top) => match top.frequency_score.total_cmp(&frequency_score) {
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
                _ => Some(top),
            },
        };
    }
    let best = best.unwrap();
    (best.frequency_score, best.cand_byte, best.cand_plaintext)
}

// Challenge 4
pub fn detect_single_character_xor() -> (f64, u8, Vec<u8>) {
    let lines = include_str!("challenge4-data.txt").lines();
    lines
        .map(|line| {
            let line = hex::decode(line).unwrap();
            single_byte_key_decrypt(&line)
        })
        .max_by(|a, b| (a.0).total_cmp(&b.0))
        .unwrap()
}

// Challenge 5
pub fn repeating_key_xor(plaintext: &[u8], key: &[u8]) -> Vec<u8> {
    let mut ret = Vec::from(plaintext);
    for (i, b) in ret.iter_mut().enumerate() {
        *b ^= key[i % key.len()];
    }
    ret
}

/// Run selection sort outer loop k times.
/// Although we accept a usize, k is meant to be very small. Probably k < 10
pub fn k_smallest<T: PartialOrd>(arr: &mut [T], k: usize) {
    for start in 0..k {
        let mut best = start;
        for i in (start + 1)..arr.len() {
            if arr[best] > arr[i] {
                best = i
            }
        }
        arr.swap(start, best)
    }
}

// Challenge 6
pub fn break_repeating_key_xor(ciphertext: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let mut distances = Vec::with_capacity(ciphertext.len());
    for keysize in 2..=40 {
        let dist = score_keysize(ciphertext, keysize);
        distances.push((dist, keysize));
    }
    // We can solve the challenge by actually just taking the smallest.
    // I do this helper function because doing min on a vec of floats is annoying.
    k_smallest(&mut distances, 1);
    let keysize = distances[0].1;
    let chunks = ciphertext.chunks(keysize);
    let mut cand_key = Vec::with_capacity(chunks.len());
    let mut message = Vec::with_capacity(ciphertext.len());
    for idx in 0..keysize {
        let mut block = Vec::with_capacity(chunks.len());
        for chunk in chunks.clone() {
            if idx < chunk.len() {
                block.push(chunk[idx]);
            }
            // let single = single_byte_key_decrypt(chunk).1;
            // cand_key.push(single);
        }
        let single = single_byte_key_decrypt(&block).1;
        cand_key.push(single);
        message.append(&mut block);
    }
    let plaintext = repeating_key_xor(ciphertext, &cand_key);
    (cand_key, plaintext)
}

fn score_keysize(cipher: &[u8], keysize: usize) -> f64 {
    let mut chunks = cipher.chunks(keysize);
    let total = chunks.len();
    let mut score = 0.;
    // To be honest I totally cheated here with
    // https://www.gkbrk.com/wiki/cryptopals-solutions/#6---break-repeating-key-xor
    //
    // Since the fucking instructions on the cryptopals site or step 3 do not actually work
    // when executed as instructed.
    //
    // The instructions imply changing this "while let" to be an "if let", i.e only executed once
    while let (Some(c1), Some(c2)) = (chunks.next(), chunks.next()) {
        let hamming_distance = hamming_distance(c1, c2);
        score += f64::from(hamming_distance);
    }
    score /= keysize as f64;
    // The instructions also do not imply doing this whatsoever. People just happen to have
    // this in their solutions.
    score /= (total - 1) as f64;
    score
}

pub fn hamming_distance(b1: &[u8], b2: &[u8]) -> u32 {
    let mut accum = 0;
    for (b1, b2) in b1.iter().zip(b2) {
        let mut dist = 0;
        let mut val = b1 ^ b2;
        loop {
            if val == 0 {
                break;
            }
            val = val & (val - 1);
            dist += 1;
        }
        accum += dist;
    }
    accum
}

// Challenge 7
pub fn aes_ecb_mode_decrypt(ciphertext: &mut [u8], key: [u8; AES_128_BLOCK_SIZE]) {
    let key = GenericArray::from(key);
    let cipher = Aes128Dec::new(&key);
    for chunk in ciphertext.chunks_mut(AES_128_BLOCK_SIZE) {
        let block = GenericArray::from_mut_slice(chunk);
        cipher.decrypt_block(block);
    }
}

// Challenge 8
pub fn detect_aes_ecb() -> Vec<String> {
    include_str!("challenge8-data.txt")
        .lines()
        .filter(|line| {
            let ciphertext = hex::decode(line).unwrap();
            let mut blocks: HashSet<&[u8]> = HashSet::new();
            for block in ciphertext.chunks(AES_128_BLOCK_SIZE) {
                if blocks.contains(block) {
                    return true;
                }
                blocks.insert(block);
            }
            false
        })
        .map(|s| s.to_string())
        .collect::<Vec<String>>()
}

#[macro_export]
macro_rules! challenge_data {
    ($fname:literal) => {
        // Decoding with newlines works in python, but not with the base64 crate
        {
            use base64::{engine::general_purpose, Engine as _};
            let dat: Vec<u8> = include_bytes!($fname)
                .iter()
                .copied()
                .filter(|c| *c != b'\n')
                .collect();
            general_purpose::STANDARD
                .decode(dat)
                .expect("should decode")
        }
    };
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
    fn test_fixed_xor() {
        let out = fixed_xor(
            &hex::decode(b"1c0111001f010100061a024b53535009181c").unwrap(),
            &hex::decode(b"686974207468652062756c6c277320657965").unwrap(),
        )
        .unwrap();
        let ans = hex::decode(b"746865206b696420646f6e277420706c6179").unwrap();
        assert_eq!(out, ans)
    }

    #[test]
    fn test_fixed_or_inplace() {
        let mut data = hex::decode(b"1c0111001f010100061a024b53535009181c").unwrap();
        fixed_xor_inplace(
            &mut data,
            &hex::decode(b"686974207468652062756c6c277320657965").unwrap(),
        )
        .unwrap();
        let ans = hex::decode(b"746865206b696420646f6e277420706c6179").unwrap();
        assert_eq!(data, ans)
    }

    #[test]
    fn test_single_byte_key_decrypt() {
        let ans = single_byte_key_decrypt(
            &hex::decode(b"1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
                .unwrap(),
        );
        let as_string = String::from_utf8(ans.2).unwrap();
        assert_eq!(as_string, "Cooking MC's like a pound of bacon");
        assert_eq!(ans.1, b'X');
    }

    #[test]
    fn test_detect_single_character_xor() {
        let best = detect_single_character_xor();
        let as_string = String::from_utf8(best.2).unwrap();
        assert_eq!(as_string, "Now that the party is jumping\n");
        assert_eq!(best.1, b'5');
    }

    #[test]
    fn test_repeating_key_xor() {
        let plaintext =
            b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
        let cipher = repeating_key_xor(plaintext, b"ICE");
        let expected = hex::decode(b"0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f").unwrap();
        assert_eq!(cipher, expected);
    }

    #[test]
    fn test_hamming_distance() {
        assert_eq!(hamming_distance(b"this is a test", b"wokka wokka!!!"), 37)
    }

    #[test]
    fn test_k_smallest() {
        let mut test = [5., 2., 3., 4., 88., 0., f64::NAN];
        k_smallest(&mut test, 4);
        assert_eq!(test[0..3], [0., 2., 3.]);
    }

    #[test]
    fn test_break_repeating_key_xor() {
        let (key, plaintext) = break_repeating_key_xor(&challenge_data!("challenge6-data.txt"));
        assert_eq!(key, b"Terminator X: Bring the noise");
        let correct_plaintext = include_bytes!("challenge6-soln.txt");
        assert_eq!(plaintext, correct_plaintext);
    }

    #[test]
    fn test_aes_in_ecb_mode() {
        let key = b"YELLOW SUBMARINE";
        let mut ciphertext = challenge_data!("challenge7-data.txt");
        aes_ecb_mode_decrypt(&mut ciphertext, *key);
        let soln_data = include_bytes!("challenge7-soln.txt");
        let without_padding = &ciphertext[..ciphertext.len() - 4];
        assert_eq!(without_padding, soln_data);
        let padding = b"\x04\x04\x04\x04";
        assert_eq!(ciphertext[ciphertext.len() - 4..], *padding)
    }

    #[test]
    fn test_detect_aes_ecb() {
        let result = detect_aes_ecb();
        assert_eq!(result[0], "d880619740a8a19b7840a8a31c810a3d08649af70dc06f4fd5d2d69c744cd283e2dd052f6b641dbf9d11b0348542bb5708649af70dc06f4fd5d2d69c744cd2839475c9dfdbc1d46597949d9c7e82bf5a08649af70dc06f4fd5d2d69c744cd28397a93eab8d6aecd566489154789a6b0308649af70dc06f4fd5d2d69c744cd283d403180c98c8f6db1f2a3f9c4040deb0ab51b29933f2c123c58386b06fba186a");
    }
}
