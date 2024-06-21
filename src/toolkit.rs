 use itertools::Itertools;

use crate::{analysis::aster_score, ALPHABET};

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

pub fn bullshark_vigenere(
    keyword1: &str,
    encrypted_text: &str,
    plaintext: &str,
    key_length: usize,
) -> String {
    let mut best_score = 0.0;
    let mut best_keyword2 = String::new();
    let mut best_decrypted = String::new();
    let mut keyword2: Vec<char> = vec!['A'; key_length];

    for _ in 0..2 {
        for i in 0..key_length {
            let mut best_char = keyword2[i];

            for index in 'A'..='Z' {
                keyword2[i] = index;
                let decrypted = vigenere_decrypt(encrypted_text, keyword1, Some(&keyword2.iter().collect::<String>()));
                let score = aster_score(plaintext, &decrypted);

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

    format!("BestScore: {}\nBest Keyword: {}\nDecrypted: {}", best_score, best_keyword2, best_decrypted)
}

pub fn remora_vigenere(
    keyword1: &str,
    encrypted_text: &str,
    plaintext: &str,
    key_length: usize,
) -> (String, f64) {
    let mut best_score = 0.0;
    let mut best_keyword2 = String::new();
    let mut best_decrypted = String::new();
    let mut keyword2: Vec<char> = vec!['A'; key_length];

    for _ in 0..2 {
        for i in 0..key_length {
            let mut best_char = keyword2[i];

            for index in 'A'..='Z' {
                keyword2[i] = index;
                let decrypted = vigenere_decrypt(encrypted_text, keyword1, Some(&keyword2.iter().collect::<String>()));
                let score = aster_score(plaintext, &decrypted);

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
    return (best_keyword2, best_score);
}

pub fn tigershark(
    key_length1: usize,
    key_length2: usize,
    encrypted_text: &str,
    plaintext: &str,
) {
    // Define the alphabet in reverse order
    let alphabet: [char; 26] = [
        'Z', 'Y', 'X', 'W', 'V', 'U', 'T', 'S', 'R', 'Q', 'P', 'O', 'N', 
        'M', 'L', 'K', 'J', 'I', 'H', 'G', 'F', 'E', 'D', 'C', 'B', 'A' 
    ];

    let mut keyword1: Vec<char> = alphabet[..key_length1].to_vec();

    let mut best_score = 0.0;
    let mut best_keyword1 = String::new();
    let mut best_keyword2 = String::new();

    // Iterate 10 times to find the best keyword
    for iteration in 0..5 {
        for index in 0..key_length1 {
            let mut best_char = keyword1[index];
            // Try each character in the alphabet at the current index
            for i in alphabet.iter() {
                keyword1[index] = *i;
                let (keyword2, score) = remora_vigenere(&keyword1.iter().collect::<String>(), encrypted_text, plaintext, key_length2);
                if score > best_score {
                    best_score = score;
                    best_keyword1 = keyword1.iter().collect();
                    best_keyword2 = keyword2;
                    best_char = *i;
                }
            }
            keyword1[index] = best_char;
        }
        println!(
            "End of iteration {}\nbestest score: {}\nbestest keyword1: {}\nbestest keyword2: {}\n",
            iteration + 1, best_score, best_keyword1, best_keyword2
        );
    }

    // Perform post-processing to check all permutations of best_keyword1
    println!("Post-processing all permutations of best_keyword1: {:?}", best_keyword1);
    let best_keyword1_chars: Vec<char> = best_keyword1.chars().collect();
    let mut best_permutation_score = best_score;
    let mut best_permutation_keyword1 = best_keyword1.clone();
    let mut best_permutation_keyword2 = best_keyword2.clone();

    for permutation in best_keyword1_chars.iter().permutations(best_keyword1.len()) {
        let perm_keyword: String = permutation.iter().map(|&&c| c).collect();
        let (keyword2, score) = remora_vigenere(&perm_keyword, encrypted_text, plaintext, key_length2);
        if score > best_permutation_score {
            best_permutation_score = score;
            best_permutation_keyword1 = perm_keyword;
            best_permutation_keyword2 = keyword2;
            println!(
                "Best permutation keyword1: {}, keyword2: {}, Score: {}",
                best_permutation_keyword1, best_permutation_keyword2, best_permutation_score
            );
        }
    }

    println!(
        "Best permutation keyword1: {}, keyword2: {}, Score: {}",
        best_permutation_keyword1, best_permutation_keyword2, best_permutation_score
    );
    println!("Final BEST KEYWORD1: {:?}", best_permutation_keyword1);
    println!("Final BEST KEYWORD2: {:?}", best_permutation_keyword2);
}

pub fn bullshark_beaufort(
    keyword1: &str,
    encrypted_text: &str,
    plaintext: &str,
    key_length: usize,
) -> String {
    let mut best_score = 0.0;
    let mut best_keyword2 = String::new();
    let mut best_decrypted = String::new();
    let mut keyword2: Vec<char> = vec!['A'; key_length];

    // Apply Atbash transformation to encrypted_text and keyword1
    let transformed_encrypted_text = atbash_transform(encrypted_text);
    let transformed_keyword1 = atbash_transform(keyword1);

    for _ in 0..2 {
        for i in 0..key_length {
            let mut best_char = keyword2[i];

            for index in 'A'..='Z' {
                keyword2[i] = index;
                let decrypted = vigenere_decrypt(&transformed_encrypted_text, &transformed_keyword1, Some(&keyword2.iter().collect::<String>()));
                let score = aster_score(plaintext, &decrypted);

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
    let true_key = atbash_transform(&best_keyword2);

    format!("BestScore: {}\nBest Keyword: {}\nDecrypted: {}", best_score, true_key, best_decrypted)
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

