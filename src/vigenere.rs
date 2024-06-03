use crate::analysis::match_percentage;

pub fn vig2table(keyword1: &str, keyword2: &str) -> Vec<Vec<char>> {
    let alphabet: Vec<char> = "ABCDEFGHIJKLMNOPQRSTUVWXYZ".chars().collect();
    let key1: Vec<char> = keyword1.to_uppercase().chars().collect();
    let key2: Vec<char> = keyword2.to_uppercase().chars().collect();

    let alphabet: Vec<char> = alphabet.into_iter().filter(|&c| !key1.contains(&c)).collect();

    let combined_alphabet: Vec<char> = [&key1[..], &alphabet[..]].concat();

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

pub fn vig1table(keyword2: &str) -> Vec<Vec<char>> {
    let keyword1 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    let alphabet: Vec<char> = "ABCDEFGHIJKLMNOPQRSTUVWXYZ".chars().collect();
    let key1: Vec<char> = keyword1.to_uppercase().chars().collect();
    let key2: Vec<char> = keyword2.to_uppercase().chars().collect();

    let alphabet: Vec<char> = alphabet.into_iter().filter(|&c| !key1.contains(&c)).collect();

    let combined_alphabet: Vec<char> = [&key1[..], &alphabet[..]].concat();

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

pub fn kryptos(
    keyword1: &str,
    encrypted: &str,
    comparison: &str,
    key_length: usize,
    ) -> String{
    let mut best_score = 0.0;
    let mut best_keyword2 = String::new();
    let mut best_decrypted = String::new();

    let mut keyword2: Vec<char> = vec!['A'; key_length];

    for _ in 0..2 {
        for i in 0..key_length {
            let mut best_char = keyword2[i];

            for index in 'A'..='Z' {
                keyword2[i] = index;

                let table = vig2table(keyword1, &keyword2.iter().collect::<String>());
                let decrypted = vdecode(encrypted, &table);
                let score = match_percentage(comparison, &decrypted);

                if score > best_score {
                    best_score = score;
                    best_decrypted = decrypted;
                    best_char = index;
                }
            }

            keyword2[i] = best_char;
        }
    }

    best_keyword2 = keyword2.iter().collect();

    
    if best_score >80.0 {  
        println!("length: {} best score: {:?} best_key: {} k1: {}
        \nbest_decrypted:                    {}",key_length,  best_score as u8, best_keyword2,keyword1, best_decrypted);
    }

    

    best_keyword2
    
}

