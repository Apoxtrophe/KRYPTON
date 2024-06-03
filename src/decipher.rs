use crate::{analysis::{aster_score, best_phi, match_percentage, substitution_cipher_score}, vdecode};


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

pub fn vig1table(keyword2: &str) -> Vec<Vec<char>> {
    generate_vigenere_table("ABCDEFGHIJKLMNOPQRSTUVWXYZ", keyword2)
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
                let score = aster_score(comparison, &decrypted);

                if score > best_score {
                    best_score = score;
                    best_decrypted = decrypted;
                    best_char = index;
                }
            }

            keyword2[i] = best_char;
        }
    }

    println!("Best Score: {} Keyword: {}", best_score, best_keyword2);
    println!("{}", best_decrypted);
    println!("{}", comparison);
    best_keyword2 = keyword2.iter().collect();

    best_keyword2
    
}

pub fn kryptos2(
    encrypted: &str,
    comparison: &str,
    key1_length: usize,
    key2_length: usize,
) -> (String, String) {
    let mut best_score = 0.0;
    let mut best_keyword1 = String::new();
    let mut best_keyword2 = String::new();
    let mut best_decrypted = String::new();

    let mut keyword1: Vec<char> = vec!['A'; key1_length];
    let mut keyword2: Vec<char> = vec!['A'; key2_length];

    for i in 0..key1_length {
        for j in 0..key2_length {
            for index1 in 'A'..='Z' {
                keyword1[i] = index1;

                for index2 in 'A'..='Z' {
                    keyword2[j] = index2;

                    let table = vig2table(&keyword1.iter().collect::<String>(), &keyword2.iter().collect::<String>());
                    let decrypted = vdecode(encrypted, &table);
                    //let score = match_percentage(comparison, &decrypted);
                    let score = aster_score(comparison, &decrypted);

                    if score > best_score {
                        best_score = score;
                        best_decrypted = decrypted;
                        best_keyword1 = keyword1.iter().collect();
                        best_keyword2 = keyword2.iter().collect();
                    }
                }
            }
        }
    }

    (best_keyword1, best_keyword2)
}