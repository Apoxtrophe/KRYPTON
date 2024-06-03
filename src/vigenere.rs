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