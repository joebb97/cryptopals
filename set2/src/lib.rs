pub fn pkcs7_pad(buf: &mut Vec<u8>, block_length: u8) {
    let pad_size: u8 = block_length - u8::try_from(buf.len() % usize::from(block_length)).unwrap();
    let mut padding = vec![pad_size; pad_size.into()];
    buf.append(&mut padding);
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
    }
}
