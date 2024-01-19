use aes::cipher::{generic_array::GenericArray, BlockDecrypt, BlockEncrypt, KeyInit};
use aes::{Aes128Dec, Aes128Enc};
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
        fixed_xor_inplace(block, &previous_block).unwrap();
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
}
