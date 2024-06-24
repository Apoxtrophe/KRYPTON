use crate::{analysis::aster_score, atbash_transform, vigenere_decrypt};

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