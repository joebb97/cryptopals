use set1::{challenge6_data, break_repeating_key_xor};

fn main() {
    // let x = set1::detect_single_character_xor();
    // let detected_plaintext = x.2.clone();
    // let detected_plaintext = String::from_utf8(detected_plaintext).expect("Should be valid utf8");
    // println!("{x:?} \n decodes to -> {detected_plaintext:?}")
    break_repeating_key_xor(&challenge6_data());
}
