use core::arch;
use std::{collections::HashMap, vec};

use itertools::rev;

use crate::analysis::percentage_blocks;

pub fn split_and_transform(s: &str, n: usize) -> Option<Vec<Vec<char>>> {
    if s.is_empty() || n == 0 {
        println!("Kullback input empty");
        return None;
    }
    let chars: Vec<char> = s.chars().collect();
    let mut result = Vec::new();

    for chunk in chars.chunks(n) {
        if chunk.len() == n {
            result.push(chunk.to_vec());
        }
    }
    if result.is_empty() {
        println!("Kullback result empty");
        return None;
    }
    let mut transformed = vec![vec![' '; result.len()]; n];
    for i in 0..n {
        for j in 0..result.len() {
            transformed[i][j] = result[j][i];
        }
    }

    Some(transformed)
}

pub fn kullback_ioc(input: Vec<Vec<char>>) -> (Vec<Vec<String>>, f64) {
    fn calculate_ioc(row: &Vec<char>) -> f64 {
        let mut freq = HashMap::new();
        let len = row.len();

        for &c in row {
            *freq.entry(c).or_insert(0) += 1;
        }

        let mut ioc = 0.0;
        for &count in freq.values() {
            ioc += count as f64 * (count as f64 - 1.0);
        }
        
        ioc / (len as f64 * (len as f64 - 1.0))
    }

    let mut string_matrix = vec![];
    let mut ioc_sum = 0.0;

    for row in input {
        let string_row: Vec<String> = row.iter().map(|&c| c.to_string()).collect();
        string_matrix.push(string_row);

        let ioc = calculate_ioc(&row);
        ioc_sum += ioc;
    }

    let avg_ioc = ioc_sum / string_matrix.len() as f64;
    (string_matrix, avg_ioc)
}

pub fn kullback (
    encrypted_text: &str,
    key_length: usize,
) -> String{
    let mut aggr_ioc: Vec<f64> = vec![0.0; 60];

    for i in 1..60{
        let transformed = split_and_transform(encrypted_text, i).unwrap_or_default();
        let result = kullback_ioc(transformed);
        aggr_ioc[i] = result.1;
    }
    ascii_graph(aggr_ioc)
    //ascii_graph2(aggr_ioc)
}

fn ascii_graph(values: Vec<f64>) -> String {
    let length = values.len();
    let min = 0.038;
    let max = 0.068;
    let mut graph = vec![String::new(); 60];
    
    for i in 0..length {
        let slice = blocks(values[i], min, max);
        graph[i] = slice; 
    }
    let height = 10;
    let mut graphy = String::new();
    for i in (0..height).rev() {
        for j in (1..60) {
            let indexed_char = graph[j].chars().nth(i).unwrap();
            graphy.push_str(&indexed_char.to_string());
        }
        graphy.push_str("\n");
    }
    let mut notables = String::new();
    let mut noted = String::new();

    for i in 0..length{

        if values[i] > 0.058 {
            noted = i.to_string();
            noted.push_str(",");
            notables.push_str(&noted);
        }
    }



   
    
    graphy.push_str(&notables);
    graphy
    
}

pub fn blocks(value: f64, min: f64, max: f64) -> String {
    let bounded_value = value.clamp(min, max);
    let percentage = (bounded_value - min) / (max - min);
    let filled_blocks = (percentage * 10.0).round() as usize;
    let empty_blocks = 20 - filled_blocks;
    
    let mut filled_str = "▒".repeat(filled_blocks);
    if percentage > 0.8{
        filled_str = "█".repeat(filled_blocks);
    }
    let empty_str = " ".repeat(empty_blocks);

    format!("[{}{}]", filled_str, empty_str)
}

fn ascii_graph2(values: Vec<f64>) -> String {
    let min = 0.038;
    let max = 0.068;
    let height = 20; // height of the graph in rows
    let width = values.len(); // width of the graph in columns
    let mut graph = vec![vec![' '; width]; height];
    
    // Scale values to fit within the graph height
    for (i, &value) in values.iter().enumerate() {
        let scaled_value = ((value - min) / (max - min) * (height - 1) as f64).round() as usize;
        if scaled_value < height {
            graph[height - 1 - scaled_value][i] = '*';
        }
    }
    
    // Convert the graph to a single string
    let mut graph_string = String::new();
    for row in graph {
        for col in row {
            graph_string.push(col);
        }
        graph_string.push('\n');
    }
    
    graph_string
}