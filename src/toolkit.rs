use crate::vig2table;

pub fn vigenere_one_encrypt(plaintext: &str, key: &str) -> String {
    let key = if key.is_empty() {
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ".to_string()
    } else {
        key.to_string()
    };
    let key = key.chars().cycle();
    plaintext.chars()
        .zip(key)
        .map(|(p, k)| {
            let p = p as u8 - b'A';
            let k = k as u8 - b'A';
            (b'A' + (p + k) % 26) as char
        })
        .collect()
}

pub fn vigenere_one_decrypt(ciphertext: &str, key: &str) -> String {
    let key = if key.is_empty() {
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ".to_string()
    } else {
        key.to_string()
    };
    let key = key.chars().cycle();
    ciphertext.chars()
        .zip(key)
        .map(|(c, k)| {
            let c = c as u8 - b'A';
            let k = k as u8 - b'A';
            (b'A' + (c + 26 - k) % 26) as char
        })
        .collect()
}

pub fn vigenere_two_encrypt(plaintext: &str, key1: &str, key2: &str) -> String {
    let key1 = if key1.is_empty() {
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ".to_string()
    } else {
        key1.to_string()
    };
    let key2 = if key2.is_empty() {
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ".to_string()
    } else {
        key2.to_string()
    };
    let table = vig2table(&key1, &key2);
    let plaintext_chars: Vec<char> = plaintext.to_uppercase().chars().collect();
    let mut encrypted_chars: Vec<char> = Vec::with_capacity(plaintext_chars.len());

    for (index, &plain_char) in plaintext_chars.iter().enumerate() {
        if let Some(position) = table[0].iter().position(|&c| c == plain_char) {
            let wrapped_index = (index % (table.len() - 1)) + 1;
            encrypted_chars.push(table[wrapped_index][position]);
        }
    }
    encrypted_chars.into_iter().collect()
}

pub fn vigenere_two_decrypt(encrypted: &str, key1: &str, key2: &str) -> String {
    let key1 = if key1.is_empty() {
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ".to_string()
    } else {
        key1.to_string()
    };
    let key2 = if key2.is_empty() {
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ".to_string()
    } else {
        key2.to_string()
    };
    let table = vig2table(&key1, &key2);
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

