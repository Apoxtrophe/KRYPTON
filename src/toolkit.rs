 use std::sync::{Arc, Mutex};

use itertools::Itertools;
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};

use crate::{analysis::{aster_score, chi_squared_score, match_percentage}, ALPHABET};

pub fn generate_vigenere_table(keyword1: &str, keyword2: &str) -> Vec<Vec<char>> {
    let alphabet: Vec<char> = "ABCDEFGHIJKLMNOPQRSTUVWXYZ".chars().collect();
    let key1: Vec<char> = keyword1.to_uppercase().chars().collect();
    let key2: Vec<char> = keyword2.to_uppercase().chars().collect();

    let filtered_alphabet: Vec<char> = alphabet.into_iter().filter(|&c| !key1.contains(&c)).collect();
    let combined_alphabet: Vec<char> = [&key1[..], &filtered_alphabet[..]].concat();

    let size = key2.len();
    let mut table: Vec<Vec<char>> = vec![vec![' '; 26]; size + 1];

    for (i, &c) in key2.iter().enumerate() {
        let mut index = combined_alphabet.iter().position(|&x| x == c).unwrap();
        for j in 0..26 {
            table[i + 1][j] = combined_alphabet[index % 26];
            index += 1;
        }
    }
    table[0] = combined_alphabet;
    table
}

pub fn vig2table(keyword1: &str, keyword2: &str) -> Vec<Vec<char>> {
    generate_vigenere_table(keyword1, keyword2)
}

pub fn generate_key(key: &str, default: &str) -> String {
    if key.is_empty() {
        default.to_string()
    } else {
        key.to_string()
    }
}

pub fn vigenere_encrypt(plaintext: &str, key1: &str, key2: Option<&str>) -> String {
    let key1 = generate_key(key1, "ABCDEFGHIJKLMNOPQRSTUVWXYZ");
    let plaintext = plaintext.to_uppercase();
    
    if let Some(key2) = key2 {
        let key2 = generate_key(key2, "ABCDEFGHIJKLMNOPQRSTUVWXYZ");
        let table = generate_vigenere_table(&key1, &key2);
        plaintext.chars()
            .enumerate()
            .filter_map(|(index, plain_char)| {
                table[0].iter().position(|&c| c == plain_char)
                    .map(|position| table[(index % (table.len() - 1)) + 1][position])
            })
            .collect()
    } else {
        let key1 = key1.chars().cycle();
        plaintext.chars()
            .zip(key1)
            .map(|(p, k)| {
                let p = p as u8 - b'A';
                let k = k as u8 - b'A';
                (b'A' + (p + k) % 26) as char
            })
            .collect()
    }
}

pub fn vigenere_decrypt(ciphertext: &str, key1: &str, key2: Option<&str>) -> String {
    let key1 = generate_key(key1, "ABCDEFGHIJKLMNOPQRSTUVWXYZ");
    let ciphertext = ciphertext.to_uppercase();
    
    if let Some(key2) = key2 {
        let key2 = generate_key(key2, "ABCDEFGHIJKLMNOPQRSTUVWXYZ");
        let table = vig2table(&key1, &key2);
        ciphertext.chars()
            .enumerate()
            .filter_map(|(index, encrypted_char)| {
                let wrapped_index = (index % (table.len() - 1)) + 1;
                table[wrapped_index].iter().position(|&c| c == encrypted_char)
                    .map(|pointer| table[0][pointer])
            })
            .collect()
    } else {
        let key1 = key1.chars().cycle();
        ciphertext.chars()
            .zip(key1)
            .map(|(c, k)| {
                let c = c as u8 - b'A';
                let k = k as u8 - b'A';
                (b'A' + (c + 26 - k) % 26) as char
            })
            .collect()
    }
}

pub fn atbash_transform(text: &str) -> String {
    text.chars()
        .map(|c| {
            if c.is_ascii_alphabetic() {
                if c.is_ascii_lowercase() {
                    (b'z' - (c as u8 - b'a')) as char
                } else {
                    (b'Z' - (c as u8 - b'A')) as char
                }
            } else {
                c
            }
        })
        .collect()
}

