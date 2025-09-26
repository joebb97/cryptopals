use set2::encryption_oracle;

fn main() {
    let plaintext = &mut "I am I am I am I am I am I am I am I am I am I am I am I am I am"
        .to_string()
        .into_bytes();
    encryption_oracle(plaintext);
    // println!("{}", hex::encode(plaintext));
    let sixteen: Vec<Vec<u8>> = plaintext.chunks(16).map(|chunk| chunk.to_vec()).collect();
    sixteen.iter().for_each(|chunk| println!("{:?}", chunk));
    // println!("{:?}", sixteen);
}
