use crate::{analysis::{aster_score, best_phi, match_percentage, substitution_cipher_score}, vdecode, ALPHABET};

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

pub fn print_vigenere_table(table: &Vec<Vec<char>>) {
    println!();
    for i in 0..table.len() {
        let mut string = "".to_string();
        for j in 0..table[0].len() {
            string.push(char::from(table[i][j]));
            string.push(' ');
        }
        println!("{}", string);
    }
}

pub fn every_nth_letter(s: &str, n: usize) -> String {
    s.char_indices()
        .filter(|(i, _)| i % n == 0)
        .map(|(_, c)| c)
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

pub fn keyless(
    encrypted_text: &str,
    plaintext: &str,
    max_key_length: usize,
) {
    let enc_block = string_to_grid(encrypted_text, max_key_length);
    let pln_block = string_to_grid(plaintext, max_key_length);

    let enc_columns: Vec<String> = transpose(&enc_block).iter().map(|col| col.iter().collect()).collect();
    let pln_columns: Vec<String> = transpose(&pln_block).iter().map(|col| col.iter().collect()).collect();
    
    let enc_rows = enc_block.iter().map(|row| row.iter().collect::<String>()).collect::<Vec<String>>();
    let pln_rows = pln_block.iter().map(|row| row.iter().collect::<String>()).collect::<Vec<String>>();

    for i in 0..enc_columns.len() {
        println!("Line: {} Score: {:?} Code: {}",i + 1, substitution_cipher_score(&enc_columns[i], &pln_columns[i]), enc_columns[i]);
    }   
    let alphabet = ALPHABET;
    let mut new_table = create_decipher_grid(&alphabet, max_key_length);

    for column in 0..pln_columns.len(){
        let enc_col_sub = &enc_columns[column];
        let pln_col_sub = &pln_columns[column];
        for (index, c) in alphabet.char_indices() {
            for i in pln_col_sub.char_indices()  {
                if c == i.1 {
                    let enc_char = enc_col_sub.chars().nth(i.0).unwrap();
                    new_table[column + 1][index] = enc_char;
                }
            }
        }
        
    }
    println!("{}", pretty_grid(&new_table));
    print_grid(&new_table);

}

fn create_decipher_grid(key: &str, n: usize) -> Vec<Vec<char>> {
    let mut grid = vec![key.chars().collect()];

    for _ in 0..n {
        let mut row = vec![' '; key.len()];
        grid.push(row);
    }

    grid
}

fn string_to_grid(s: &str, n: usize) -> Vec<Vec<char>> {
    let mut grid = Vec::new();
    let mut row = Vec::new();

    for (i, c) in s.chars().enumerate() {
        row.push(c);

        if (i + 1) % n == 0 {
            grid.push(row);
            row = Vec::new();
        }
    }

    if !row.is_empty() {
        grid.push(row);
    }

    grid
}

fn transpose(grid: &Vec<Vec<char>>) -> Vec<Vec<char>> {
    if grid.is_empty() {
        return vec![];
    }

    let num_rows = grid.len();
    let num_cols = grid[0].len();
    let mut transposed: Vec<Vec<char>> = vec![vec![]; num_cols];

    for row in grid {
        for (j, &val) in row.iter().enumerate() {
            transposed[j].push(val);
        }
    }

    transposed
}



fn pretty_grid(grid: &Vec<Vec<char>>) -> String {
    let mut result = String::new();

    // Print the header row
    result.push_str("   ");
    for (i, _) in grid[0].iter().enumerate() {
        result.push_str(&format!("| {} ", i + 1));
    }
    result.push_str("|\n");

    // Print the separator row
    result.push_str("   ");
    for _ in 0..grid[0].len() {
        result.push_str("|---");
    }
    result.push_str("|\n");

    // Print the grid rows
    for (i, row) in grid.iter().enumerate() {
        if i == 0 {
            result.push_str("   ");
            for &cell in row {
                result.push_str(&format!("| {} ", cell));
            }
            result.push_str("|\n");
        } else {
            result.push_str(&format!("{:2} ", i));
            for &cell in row {
                result.push_str(&format!("| {} ", cell));
            }
            result.push_str("|\n");
        }
    }

    result
}

fn print_grid(grid: &Vec<Vec<char>>) {
    for row in grid {
        for ch in row {
            if *ch == ' ' {
                print!("_");
            } else {
                print!("{}", ch);
            }
        }
        println!();
    }
}