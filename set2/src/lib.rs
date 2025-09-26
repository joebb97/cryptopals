use aes::cipher::{generic_array::GenericArray, BlockDecrypt, BlockEncrypt, KeyInit};
use aes::{Aes128Dec, Aes128Enc};
use rand::rngs::ThreadRng;
use rand::Rng;
use set1::{fixed_xor_inplace, AES_128_BLOCK_SIZE};

pub fn pkcs7_pad(buf: &mut Vec<u8>, block_size: u8) {
    let rem = buf.len() % usize::from(block_size);
    let pad_size: u8 = block_size - u8::try_from(rem).unwrap();
    let mut padding = vec![pad_size; pad_size.into()];
    buf.append(&mut padding);
}

// Challenge 9
pub fn pkcs7_unpad(buf: &mut Vec<u8>) {
    let pad_len = buf.last().unwrap();
    let new_len = buf.len().saturating_sub(usize::from(*pad_len));
    buf.truncate(new_len);
}

// Challenge 10
pub fn aes_cbc_encrypt(
    plaintext: &mut Vec<u8>,
    key: [u8; AES_128_BLOCK_SIZE],
    iv: [u8; AES_128_BLOCK_SIZE],
) {
    pkcs7_pad(plaintext, AES_128_BLOCK_SIZE.try_into().unwrap());
    let key = GenericArray::from(key);
    let cipher = Aes128Enc::new(&key);
    let mut previous_block = &iv[..];
    for block in plaintext.chunks_mut(AES_128_BLOCK_SIZE) {
        fixed_xor_inplace(block, previous_block).unwrap();
        cipher.encrypt_block(GenericArray::from_mut_slice(block));
        previous_block = block;
    }
}

pub fn aes_cbc_decrypt(
    ciphertext: &mut Vec<u8>,
    key: [u8; AES_128_BLOCK_SIZE],
    iv: [u8; AES_128_BLOCK_SIZE],
) {
    let key = GenericArray::from(key);
    let cipher = Aes128Dec::new(&key);
    let mut previous_block = Vec::from(&iv[..]);
    for block in ciphertext.chunks_mut(AES_128_BLOCK_SIZE) {
        let copy = block.to_vec();
        cipher.decrypt_block(GenericArray::from_mut_slice(block));
        fixed_xor_inplace(block, &previous_block).unwrap();
        previous_block = copy;
    }
    pkcs7_unpad(ciphertext)
}

// Challenge 10
pub fn random_array<const SIZE: usize>() -> [u8; SIZE] {
    use rand::prelude::*;
    let mut rng = rand::rng();

    // Generate a Vec<u8> with random values
    let mut random_key: [u8; SIZE] = [0; SIZE];
    for b in random_key.iter_mut() {
        *b = rng.random()
    }
    random_key
}

pub fn aes_ecb_mode_decrypt(ciphertext: &mut Vec<u8>, key: [u8; AES_128_BLOCK_SIZE]) {
    set1::aes_ecb_mode_decrypt(ciphertext, key);
    pkcs7_unpad(ciphertext);
}

pub fn aes_ecb_mode_encrypt(plaintext: &mut Vec<u8>, key: [u8; AES_128_BLOCK_SIZE]) {
    pkcs7_pad(plaintext, AES_128_BLOCK_SIZE.try_into().unwrap());
    set1::aes_ecb_mode_encrypt(plaintext, key);
}

// Challenge 11
pub fn encryption_oracle(plaintext: &mut Vec<u8>) {
    let mut rng = rand::rng();
    fn random_vector(rng: &mut ThreadRng) -> Vec<u8> {
        let amt_to_add = rng.random_range(5..=10);
        (0..=amt_to_add).map(|_| rng.random()).collect::<Vec<u8>>()
    }
    let mut bytes_to_prepend = random_vector(&mut rng);
    bytes_to_prepend.append(plaintext);
    let mut new_plaintext = bytes_to_prepend;

    let mut bytes_to_append = random_vector(&mut rng);
    new_plaintext.append(&mut bytes_to_append);

    let rand_key: [u8; AES_128_BLOCK_SIZE] = random_array();
    let use_ecb: bool = rng.random();
    if use_ecb {
        aes_ecb_mode_encrypt(&mut new_plaintext, rand_key);
    } else {
        // use cbc
        let rand_iv: [u8; AES_128_BLOCK_SIZE] = random_array();
        aes_cbc_encrypt(&mut new_plaintext, rand_key, rand_iv);
    }
    *plaintext = new_plaintext;
}

#[derive(PartialEq, Debug)]
pub enum DetectResult {
    Ecb,
    Cbc,
}

pub fn detect_aes_ecb_or_cbc(ciphertext: &[u8]) -> DetectResult {
    // I cheated and copied this persion https://github.com/ricpacca/cryptopals/blob/master/S2C11.py
    if set1::count_aes_ecb_repetitions(ciphertext) > 0 {
        DetectResult::Ecb
    } else {
        DetectResult::Cbc
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    #[test]
    fn test_pkcs7_pad() {
        let mut buf = b"YELLOW SUBMARINE".to_vec();
        pkcs7_pad(&mut buf, 20);
        assert_eq!(buf, b"YELLOW SUBMARINE\x04\x04\x04\x04");

        let mut buf = vec![2; 36];
        pkcs7_pad(&mut buf, 20);
        assert_eq!(buf.len(), 40);
        assert_eq!(&buf[buf.len() - 4..], b"\x04\x04\x04\x04");

        let mut buf = vec![2; 300];
        pkcs7_pad(&mut buf, 16);
        assert_eq!(buf.len(), 304);
        assert_eq!(&buf[buf.len() - 4..], b"\x04\x04\x04\x04");

        let mut buf = vec![2; 15];
        pkcs7_pad(&mut buf, 16);
        assert_eq!(buf.len(), 16);
        assert_eq!(*buf.last().unwrap(), 1);

        let mut buf = vec![2; 16];
        pkcs7_pad(&mut buf, 16);
        assert_eq!(buf.len(), 32);
        assert_eq!(&buf[buf.len() - 16..], vec![16; 16]);
    }

    #[test]
    fn test_pkcs7_unpad() {
        let mut buf = b"YELLOW SUBMARINE\x04\x04\x04\x04".to_vec();
        pkcs7_unpad(&mut buf);
        assert_eq!(&buf, b"YELLOW SUBMARINE");

        let mut buf = vec![2; 16];
        let original = buf.clone();
        pkcs7_pad(&mut buf, 16);
        pkcs7_unpad(&mut buf);
        assert_eq!(buf, original);

        let mut buf = vec![2; 15];
        let original = buf.clone();
        pkcs7_pad(&mut buf, 16);
        pkcs7_unpad(&mut buf);
        assert_eq!(buf, original);
    }

    #[test]
    fn test_aes_cbc() {
        let mut ciphertext = set1::challenge_data!("challenge10-data.txt");
        let copy = ciphertext.clone();
        let iv = [b'\x00'; AES_128_BLOCK_SIZE];
        let key = b"YELLOW SUBMARINE";
        aes_cbc_decrypt(&mut ciphertext, *key, iv);
        let plaintext = String::from_utf8(ciphertext).unwrap();
        assert_eq!(plaintext, include_str!("challenge10-soln.txt"));
        let mut plaintext = plaintext.into_bytes();
        aes_cbc_encrypt(&mut plaintext, *key, iv);
        assert_eq!(plaintext, copy);
    }

    #[test]
    fn test_detect_aes_ecb_or_cbc() {
        let ciphertext = hex::decode(b"d880619740a8a19b7840a8a31c810a3d08649af70dc06f4fd5d2d69c744cd283e2dd052f6b641dbf9d11b0348542bb5708649af70dc06f4fd5d2d69c744cd2839475c9dfdbc1d46597949d9c7e82bf5a08649af70dc06f4fd5d2d69c744cd28397a93eab8d6aecd566489154789a6b0308649af70dc06f4fd5d2d69c744cd283d403180c98c8f6db1f2a3f9c4040deb0ab51b29933f2c123c58386b06fba186a").unwrap();
        assert_eq!(detect_aes_ecb_or_cbc(&ciphertext), DetectResult::Ecb)
    }
}
