use set1::single_byte_key_decrypt;

fn main() {
    let ans = single_byte_key_decrypt(
        &hex::decode(b"1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736").unwrap()
    )
    .unwrap();
    println!("{ans:?}");
    let string = String::from_utf8(ans.2);
    println!("{string:?}");
}
