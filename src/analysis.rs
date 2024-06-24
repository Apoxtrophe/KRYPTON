use std::{collections::{HashMap, HashSet}, iter};

use itertools::Itertools;

        

pub fn chi_squared_score(encrypted_text: &str) -> f64 {
    // Expected frequencies of letters in the English language
    let frequencies = [
        0.08167, 0.01492, 0.02782, 0.04253, 0.12702, 0.02228, 0.02015,
        0.06094, 0.06966, 0.00153, 0.00772, 0.04025, 0.02406, 0.06749,
        0.07507, 0.01929, 0.00095, 0.05987, 0.06327, 0.09056, 0.02758,
        0.00978, 0.02360, 0.00150, 0.01974, 0.00074,
    ];

    // Array to store counts of each letter
    let mut counts = [0.0; 26];
    counts = [0.0; 26];


    // Calculate total count of alphabetic characters and their respective counts
    let total_count = encrypted_text
        .as_bytes()
        .iter()
        .filter(|&&b| matches!(b, b'A'..=b'Z' | b'a'..=b'z'))
        .fold(0.0, |acc, &b| {
            counts[(b.to_ascii_uppercase() - b'A') as usize] += 1.0;
            acc + 1.0
        });

    // Normalize the counts to get observed frequencies
    let normalized_counts: Vec<f64> = counts.iter().map(|&count| count / total_count).collect();

    // Calculate the chi-squared score
    let chi_score = normalized_counts
        .iter()
        .zip(frequencies.iter())
        .map(|(&observed, &expected)| {
            let diff = observed - expected;
            diff * diff / expected
        })
        .sum::<f64>();

    chi_score
}

pub fn match_percentage(str1: &str, str2: &str) -> f64 {
    let chars1: Vec<char> = str1.chars().filter(|&c| c != ' ').collect();
    let chars2: Vec<char> = str2.chars().filter(|&c| c != ' ').collect();

    let mut matches = 0;
    let max_length = chars1.len().max(chars2.len());

    for i in 0..max_length {
        if i < chars1.len() && i < chars2.len() && chars1[i] == chars2[i] {
            matches += 1;
        }
    }

    if max_length == 0 {
        return 0.0;
    }

    (matches as f64 / max_length as f64) * 100.0
}

pub fn kasiski_examination(ciphertext: &str, excluded_factors: &[usize]) -> Vec<usize> {
    if ciphertext.len() < 3 {
        return vec![];
    }

    let mut substring_positions: HashMap<&str, Vec<usize>> = HashMap::new();
    let mut distances: Vec<f64> = Vec::new();

    // Set for fast exclusion checks
    let excluded_factors_set: HashSet<usize> = excluded_factors.iter().cloned().collect();

    // Find repeating substrings and their positions
    for i in 0..ciphertext.len() - 2 {
        for j in 3..=10 {
            if i + j <= ciphertext.len() {
                let substring = &ciphertext[i..i + j];
                substring_positions.entry(substring)
                    .or_insert_with(Vec::new)
                    .push(i);
            }
        }
    }

    // Calculate distances between repeating substrings and normalize them
    let ciphertext_length = ciphertext.len() as f64;
    for positions in substring_positions.values() {
        for (i, j) in positions.iter().tuple_combinations() {
            let distance = (j - i) as f64 / ciphertext_length;
            distances.push(distance);
        }
    }

    // Find the most common factors among the normalized distances, excluding the specified factors
    let mut factor_counts: HashMap<usize, f64> = HashMap::new();
    for &distance in &distances {
        for factor in 2..=(distance * ciphertext_length) as usize {
            if ((distance * ciphertext_length) as usize) % factor == 0 && !excluded_factors_set.contains(&factor) {
                *factor_counts.entry(factor).or_insert(0.0) += 1.0;
            }
        }
    }

    // Normalize the factor counts
    for count in factor_counts.values_mut() {
        *count /= distances.len() as f64;
    }

    // Sort the factors by their normalized frequencies in descending order
    let mut sorted_factors: Vec<(usize, f64)> = factor_counts.into_iter().collect();
    sorted_factors.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());

    // Return the top 5 factors
    sorted_factors.into_iter().take(5).map(|(factor, _)| factor).collect()
}

fn friedman_test(text: &str) -> f64 {
    let text = text.to_uppercase();
    let len = text.len() as f64;
    let mut freq = [0; 26];

    // Count frequency of each letter
    for c in text.chars() {
        if c.is_ascii_alphabetic() {
            freq[(c as u8 - b'A') as usize] += 1;
        }
    }

    // Calculate the sum for the index of coincidence
    let sum: f64 = freq.iter().map(|&count| (count as f64) * (count as f64 - 1.0)).sum();
    let index_of_coincidence = sum / (len * (len - 1.0));

    index_of_coincidence
}

pub fn friedman_key_length(text: &str, key_length: usize) -> f64 {
    let text = text.to_uppercase();
    let mut sum_ic = 0.0;

    // Calculate IC for each column in the key length
    for i in 0..key_length {
        let column: String = text.chars().skip(i).step_by(key_length).collect();
        sum_ic += friedman_test(&column);
    }

    // Calculate the average IC for the given key length
    let avg_ic = sum_ic / key_length as f64;

    avg_ic
}

fn shift_and_subtract(s: &str, n: usize) -> String {
    // Handle cases where n is greater than or equal to the length of the string
    if n >= s.len() {
        return s.to_string();
    }

    let shifted = s.chars().skip(n).chain(iter::repeat('_').take(n)).collect::<String>();
    let mut result = String::with_capacity(s.len());
    for (c1, c2) in s.chars().zip(shifted.chars()) {
        if c2 == '_' {
            result.push(c1);
        } else {
            let diff = ((c1 as u8 - b'A') as i32 - (c2 as u8 - b'A') as i32 + 26) % 26;
            result.push((diff as u8 + b'A') as char);
        }
    }

    result.truncate(s.len() - n);
    if !result.is_empty() {
        result.remove(0);
    }
    result
}

fn subtract_strings(s1: &str, s2: &str) -> String {
    let len = s1.len().max(s2.len());
    s1.chars()
        .chain(iter::repeat('A'))
        .zip(s2.chars().chain(iter::repeat('A')))
        .take(len)
        .map(|(c1, c2)| {
            let diff = ((c1 as i32 - b'A' as i32) - (c2 as i32 - b'A' as i32) + 26) % 26;
            (diff as u8).wrapping_add(b'A') as char
        })
        .collect()
}

pub fn key_elimination(key_length: usize, encrypted_text: &str, plaintext: &str) -> (usize, f64, String) {
    let shifted_encrypt = shift_and_subtract(encrypted_text, key_length);
    let shifted_plain = shift_and_subtract(plaintext, key_length);

    let score = match_percentage(&shifted_encrypt, &shifted_plain);

    // Normalize the score based on the length of the strings
    let normalized_score = score / (shifted_encrypt.len().min(shifted_plain.len()) as f64);

    let best_sequence = subtract_strings(encrypted_text, plaintext).chars().take(key_length).collect();

    (key_length, normalized_score, best_sequence)
}

pub fn percentage_blocks(value: f64, min: f64, max: f64) -> String {
    let bounded_value = value.clamp(min, max);
    let percentage = (bounded_value - min) / (max - min);
    let filled_blocks = (percentage * 10.0).round() as usize;
    let empty_blocks = 10 - filled_blocks;

    let filled_str = "■".repeat(filled_blocks);
    let empty_str = "_".repeat(empty_blocks);

    format!("[{}{}]", filled_str, empty_str)
}

fn index_of_coincidence(text: &str) -> f64 {
    let mut freq = [0; 26];
    let mut total = 0;

    for c in text.chars() {
        if c.is_ascii_alphabetic() {
            let idx = (c.to_ascii_lowercase() as u8 - b'a') as usize;
            freq[idx] += 1;
            total += 1;
        }
    }
    let mut sum = 0.0;
    for &f in &freq {
        sum += f as f64 * (f as f64 - 1.0);
    }

    let ic = sum / (total as f64 * (total as f64 - 1.0));

    (ic * 26.0) / 1.73
}

pub fn phi_test(text: &str, period: usize) -> f64 {
    let text = text.to_ascii_uppercase();
    let text: String = text.chars().filter(|c| c.is_ascii_alphabetic()).collect();

    let ic_total = index_of_coincidence(&text);
    let mut ic_sum = 0.0;

    for i in 0..period {
        let column: String = text.chars().skip(i).step_by(period).collect();
        let ic_column = index_of_coincidence(&column);
        ic_sum += ic_column;
    }

    let ic_avg = ic_sum / period as f64;
    ic_avg / ic_total
}

pub fn aster_score(encrypted_text: &str, plaintext: &str) -> f64 {
    let mut score = 0.0;
    let mut count = 0;

    for (c1, c2) in encrypted_text.chars().zip(plaintext.chars()) {
        if c1 == '_' || c2 == '_' {
            continue;
        }

        count += 1;

        if c1 == c2 {
            score += 1.0;
        } else {
            let dist1 = ((c1 as i32 - c2 as i32 + 26) % 26).abs();
            let dist2 = ((c2 as i32 - c1 as i32 + 26) % 26).abs();
            let dist = dist1.min(dist2);
            score += 1.0 / (dist as f64 + 1.0);
        }
    }

    if count == 0 {
        0.0
    } else {
        score / count as f64 * 100.0
    }
}

pub fn substitution_cipher_score(str1: &str, str2: &str) -> Option<f64> {
    if str1.len() != str2.len() {
        return None;
    }

    let mut char_map = std::collections::HashMap::new();
    let mut used_chars = std::collections::HashSet::new();
    let mut match_count = 0;
    let mut total_count = 0;

    for (c1, c2) in str1.chars().zip(str2.chars()) {
        if c1 == '_' || c2 == '_' {
            continue;
        }

        if !c1.is_ascii_uppercase() || !c2.is_ascii_uppercase() {
            return None;
        }

        total_count += 1;

        if let Some(&mapped_char) = char_map.get(&c1) {
            if mapped_char == c2 {
                match_count += 1;
            }
        } else {
            if !used_chars.contains(&c2) {
                char_map.insert(c1, c2);
                used_chars.insert(c2);
                match_count += 1;
            }
        }
    }

    if total_count == 0 {
        return Some(100.0);
    }

    let score = (match_count as f64 / total_count as f64) * 100.0;
    Some(score)
}

pub fn ioc(text: &str) -> f64 {
    // Filter the text to include only alphabetic characters and convert to lowercase
    let filtered_text: Vec<char> = text
        .chars()
        .filter(|c| c.is_alphabetic())
        .map(|c| c.to_ascii_lowercase())
        .collect();

    let length = filtered_text.len();
    if length <= 1 {
        return 0.0;
    }

    // Calculate frequency of each character
    let mut frequencies = [0; 26];
    for &c in &filtered_text {
        frequencies[(c as usize) - ('a' as usize)] += 1;
    }

    // Calculate the Index of Coincidence
    let mut ic = 0.0;
    for &freq in &frequencies {
        ic += (freq * (freq - 1)) as f64;
    }
    ic /= (length * (length - 1)) as f64;

    ic
}