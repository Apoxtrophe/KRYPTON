use crate::analysis::match_percentage;


pub fn vdecode(encrypted: &str, table: &[Vec<char>]) -> String {
    let encrypted_chars: Vec<char> = encrypted.to_uppercase().chars().collect();
    let mut decrypted_chars: Vec<char> = Vec::with_capacity(encrypted_chars.len());

    for (index, &encrypted_char) in encrypted_chars.iter().enumerate() {
        let wrapped_index = (index % (table.len() - 1)) + 1;
        if let Some(pointer) = table[wrapped_index].iter().position(|&c| c == encrypted_char) {
            decrypted_chars.push(table[0][pointer]);
        }
    }
    decrypted_chars.into_iter().collect()
}

pub fn vigenere(plain_text: &str, key: &str) -> String {
    // Remove all unicode and non-ascii characters from key
    let key: String = key.chars().filter(|&c| c.is_ascii_alphabetic()).collect();
    let key = key.to_ascii_lowercase();

    let key_len = key.len();
    if key_len == 0 {
        return String::from(plain_text);
    }

    let mut index = 0;

    plain_text
        .chars()
        .map(|c| {
            if c.is_ascii_alphabetic() {
                let first = if c.is_ascii_lowercase() { b'a' } else { b'A' };
                let shift = key.as_bytes()[index % key_len] - b'a';
                index += 1;
                // modulo the distance to keep character range
                (first + (c as u8 + shift - first) % 26) as char
            } else {
                c
            }
        })
        .collect()
}





