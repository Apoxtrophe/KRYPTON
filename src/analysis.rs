use std::collections::HashMap;


pub fn analysis(
    encrypted_text: &str,
    plaintext: &str,
    max_key_length: usize,
    excluded_factors: &[usize],
) -> String {
    let chi_score = chi_squared_score(encrypted_text);
    let match_percent = match_percentage(plaintext, encrypted_text);                                                                                                                                                        
    let kasiski = kasiski_examination(encrypted_text, excluded_factors);
    let friedman = friedman_key_length(encrypted_text, max_key_length);
    let key_elim = key_elimation(max_key_length, encrypted_text, plaintext);
    let chi_elim = chi_elimation(max_key_length, encrypted_text, plaintext);
    //let key_elim = key_elimination(encrypted_text, plaintext);

    let output = format!("Chi Score:         {}  
                                \nMatch Score:      %{}
                                \nKasiski Keys:      {:?}
                                \nFriedman Key:     [{}] Confidence: {}
                                \nKey Elimation:     {}
                                \nChi Elimation:     {}", chi_score, match_percent, kasiski, friedman.0, friedman.1, key_elim, chi_elim);

    output
}

pub fn chi_squared_score(encrypted_text: &str) -> f64 {
    let frequencies = [
        0.08167, 0.01492, 0.02782, 0.04253, 0.12702, 0.02228, 0.02015,
        0.06094, 0.06966, 0.00153, 0.00772, 0.04025, 0.02406, 0.06749,
        0.07507, 0.01929, 0.00095, 0.05987, 0.06327, 0.09056, 0.02758,
        0.00978, 0.02360, 0.00150, 0.01974, 0.00074,
    ];

    let mut counts = [0; 26];
    let mut total_count = 0;

    for c in encrypted_text.chars() {
        if c.is_ascii_alphabetic() {
            let index = (c.to_ascii_uppercase() as u8 - b'A') as usize;
            counts[index] += 1;
            total_count += 1;
        }
    }

    let mut chi_score = 0.0;

    for i in 0..26 {
        let observed = counts[i] as f64;
        let expected = frequencies[i] * total_count as f64;
        let diff = observed - expected;
        chi_score += diff * diff / expected;
    }

    10000.0 / chi_score
}

pub fn match_percentage(str1: &str, str2: &str) -> f64 {
    if str1.len() != str2.len() {
        panic!("Strings must have the same length");
    }

    let mut matches = 0;
    let mut total_chars = 0;

    for (c1, c2) in str1.chars().zip(str2.chars()) {
        if c1 != '_' && c2 != '_' {
            if c1 == c2 {
                matches += 1;
            }
            total_chars += 1;
        }
    }

    if total_chars == 0 {
        return 0.0;
    }

    (matches as f64 / total_chars as f64) * 100.0
}

pub fn kasiski_examination(ciphertext: &str, excluded_factors: &[usize]) -> Vec<usize> {
    let mut substring_positions: HashMap<&str, Vec<usize>> = HashMap::new();
    let mut distances: Vec<usize> = Vec::new();

    // Find repeating substrings and their positions
    for i in 0..ciphertext.len() - 2 {
        for j in 3..=10 {
            if i + j <= ciphertext.len() {
                let substring = &ciphertext[i..i + j];
                substring_positions
                    .entry(substring)
                    .or_insert_with(Vec::new)
                    .push(i);
            }
        }
    }

    // Calculate distances between repeating substrings
    for positions in substring_positions.values() {
        for i in 0..positions.len() - 1 {
            for j in i + 1..positions.len() {
                let distance = positions[j] - positions[i];
                distances.push(distance);
            }
        }
    }

    // Find the most common factors among the distances, excluding the specified factors
    let mut factor_counts: HashMap<usize, usize> = HashMap::new();
    for &distance in &distances {
        for i in 2..=distance {
            if distance % i == 0 && !excluded_factors.contains(&i) {
                *factor_counts.entry(i).or_insert(0) += 1;
            }
        }
    }

    // Sort the factors by their frequencies in descending order
    let mut sorted_factors: Vec<(usize, usize)> = factor_counts.into_iter().collect();
    sorted_factors.sort_by(|a, b| b.1.cmp(&a.1));

    // Return the top 4 factors
    sorted_factors.into_iter().take(5).map(|(factor, _)| factor).collect()
}

fn friedman_test(text: &str) -> f64 {
    let text = text.to_uppercase();
    let len = text.len() as f64;
    let mut freq = [0; 26];

    for c in text.chars() {
        if c.is_ascii_alphabetic() {
            freq[(c as u8 - b'A') as usize] += 1;
        }
    }

    let mut sum = 0.0;
    for &count in &freq {
        sum += (count as f64) * (count as f64 - 1.0);
    }

    let index_of_coincidence = sum / (len * (len - 1.0));
    index_of_coincidence
}

pub fn friedman_key_length(text: &str, max_key_length: usize) -> (usize, f64) {
    let mut avg_ics = Vec::new();

    for key_length in 1..=max_key_length {
        let mut sum_ic = 0.0;

        for i in 0..key_length {
            let column: String = text.chars().skip(i).step_by(key_length).collect();
            sum_ic += friedman_test(&column);
        }

        let avg_ic = sum_ic / key_length as f64;
        avg_ics.push(avg_ic);
    }

    let overall_avg_ic = avg_ics.iter().sum::<f64>() / max_key_length as f64;
    let mut best_key_length = 0;
    let mut best_confidence = 0.0;

    for (i, &avg_ic) in avg_ics.iter().enumerate() {
        let confidence = (avg_ic - overall_avg_ic) / overall_avg_ic;
        if confidence > best_confidence {
            best_key_length = i + 1;
            best_confidence = confidence;
        }
    }

    (best_key_length, best_confidence)
}

fn shift_and_subtract(s: &str, n: usize) -> String {
    let shifted = s.chars().skip(n).chain(std::iter::repeat('_').take(n)).collect::<String>();
    let mut result = String::with_capacity(s.len());
    for (c1, c2) in s.chars().zip(shifted.chars()) {
        if c2 == '_' {
            result.push(c1);
        } else {
            let diff = ((c1 as u8 - b'A') - (c2 as u8 - b'A') + 26) % 26;
            result.push((diff + b'A') as char);
        }
    }

    result.truncate(s.len() - n);
    if !result.is_empty() {
        result.drain(..1);
    }
    result
}

fn subtract_strings(s1: &str, s2: &str) -> String {
    let mut result = String::new();
    let len = s1.len().max(s2.len());

    for i in 0..len {
        let c1 = s1.chars().nth(i).unwrap_or('A');
        let c2 = s2.chars().nth(i).unwrap_or('A');

        let diff = ((c1 as u8 - b'A') - (c2 as u8 - b'A') + 26) % 26;
        let char_diff = (diff + b'A') as char;
        result.push(char_diff);
    }

    result
}

fn key_elimation (
    max_key_length: usize,
    encrypted_text: &str,
    plaintext: &str,
) -> String {
    let mut best_score = 0.0;
    let mut best_sequence = "".to_string();
    let mut best_key_length = 0;
    for i in 1..=max_key_length {
        let shifted_encrypt = shift_and_subtract(encrypted_text, i);
        let shifted_plain = shift_and_subtract(plaintext, i);

        let score = match_percentage(&shifted_encrypt, &shifted_plain);

        if score > best_score {
            best_score = score;
            best_sequence = subtract_strings(encrypted_text, plaintext).chars().take(i).collect();
            best_key_length = i;
        }
    }

    format!("Key Length: {} Match Score: {} Possible Key: {}", best_key_length, best_score, best_sequence)
}

fn chi_elimation (
    max_key_length: usize,
    encrypted_text: &str,
    plaintext: &str,
) -> String {
    let mut best_score = 0.0;
    let mut best_sequence = "".to_string();
    let mut best_key_length = 0;
    let mut best_encoded = "".to_string();
    for i in 1..=max_key_length {
        let shifted_encrypt = shift_and_subtract(encrypted_text, i);
        let shifted_plain = shift_and_subtract(plaintext, i);

        let score = chi_squared_score(&shifted_encrypt);

        println!("length: {} encoded: {}", i, shifted_encrypt );

        if score > best_score {
            best_score = score;
            best_sequence = subtract_strings(encrypted_text, plaintext).chars().take(i).collect();
            best_key_length = i;
            best_encoded = shifted_encrypt;
        }
    }
    println!("{}", best_encoded);
    format!("Key Length: {} Match Score: {} Possible Key: {}", best_key_length, best_score, best_sequence)
}

fn chi_eval (
    max_key_length: usize,
    encrypted_text: &str,
) -> String {
    let mut best_score = 0.0;
    let mut best_key_length = 0;
    let mut best_encoded = "".to_string();
    for i in 1..=max_key_length {
        let shifted_encrypt = shift_and_subtract(encrypted_text, i);

        let score = chi_squared_score(&shifted_encrypt);

        if score > best_score {
            best_score = score;
            best_key_length = i;
            best_encoded = shifted_encrypt;
        }
    }

    format!("Key Length: {} Match Score: {} Best Encoded:", best_key_length, best_score, best_encoded)
}