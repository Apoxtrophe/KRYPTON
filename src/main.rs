use std::fmt::Pointer;

use analysis::{analyze, AnalysisResult};
use eframe::egui;

mod analysis;

mod crypt;
use crypt::*;

mod decipher;
use decipher::*;

mod vigenere;
use egui::FontId;
use vigenere::*;

struct MyApp {
    result: Option<AnalysisResult>,
    selected_k1: String,
    selected_k1p: String,
    key_length: usize,
    key1: String,
    key2: String,
    output: String,
}

impl Default for MyApp {
    fn default() -> Self {
        Self {
            result: None,
            selected_k1: "ENCRYPTED".to_string(),
            selected_k1p: "PLAINTEXT".to_string(),
            output: "OUTPUT".to_string(),
            key_length: Default::default(),
            key1: String::new(),
            key2: String::new(),
        }
    }
}

impl eframe::App for MyApp {
    fn update(&mut self, ctx: &egui::Context, frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.vertical_centered(|ui| {
                ui.heading(egui::RichText::new("KRYPTON").font(FontId::monospace(48.0)).color(egui::Color32::WHITE));
            });

            let k1_options = vec![
                ("Kryptos Section 1 Encrypted".to_string(), K1.to_string()),
                ("Kryptos Section 2 Encrypted".to_string(), K2.to_string()),
                ("Kryptos Section 3 Encrypted".to_string(), K3.to_string()),
                ("Kryptos Section 4 Encrypted".to_string(), K4.to_string()),
            ];

            let k1p_options = vec![
                ("Kryptos Section 1 Plaintext".to_string(), K1p.to_string()),
                ("Kryptos Section 2 Plaintext".to_string(), K2p.to_string()),
                ("Kryptos Section 3 Plaintext".to_string(), K3p.to_string()),
                ("Kryptos Section 4 Plaintext".to_string(), K4p.to_string()),
            ];

            ui.horizontal(|ui| {
                ui.add_sized(
                    [500.0, 200.0],
                    egui::TextEdit::multiline(&mut self.selected_k1)
                        .font(FontId::monospace(16.0))
                        .hint_text("Encrypted Text"),
                );
            
                ui.add_sized(
                    [500.0, 200.0],
                    egui::TextEdit::multiline(&mut self.selected_k1p)
                        .font(FontId::monospace(16.0))
                        .hint_text("Known Plain Text"),
                );
            });
            if ui.add_sized([500.0, 50.0],(egui::Button::new(egui::RichText::new("Analyze Encrypted & Plaintext").size(24.0).color(egui::Color32::LIGHT_GREEN)))).clicked() {
                self.result = Some(analyze(&self.selected_k1, &self.selected_k1p, self.key_length, &[1, 2, 4]));
            } 
            ui.horizontal(|ui| {
                
                ui.add_space(1.0);
                
            });

            ui.add_space(16.0); 
            ui.add_space(16.0);
             ui.add_sized(
                [200.0, 20.0],
                egui::TextEdit::singleline(&mut self.key1)
                    .font(FontId::monospace(16.0))
                    .hint_text("Key 1"),
            );
            ui.add_space(16.0);
            ui.add_sized(
                [200.0, 20.0],
                egui::TextEdit::singleline(&mut self.key2)
                    .font(FontId::monospace(16.0))
                    .hint_text("Key 2"),
            );                                                                                                                                            
            ui.add_space(16.0);
            egui::ComboBox::from_label("Selected Encrypted Text")
                .selected_text(k1_options.iter().find(|&(_, v)| *v == self.selected_k1).unwrap_or_else(|| &k1_options[0]).0.clone())
                .show_ui(ui, |ui| {
                    for (display, value) in &k1_options {
                        ui.selectable_value(&mut self.selected_k1, value.clone(), display);
                    }
                });
            ui.add_space(16.0);
            egui::ComboBox::from_label("Select Known Plaintext")
                .selected_text(k1p_options.iter().find(|&(_, v)| *v == self.selected_k1p).unwrap_or_else(|| &k1p_options[0]).0.clone())
                .show_ui(ui, |ui| {
                    for (display, value) in &k1p_options {
                        ui.selectable_value(&mut self.selected_k1p, value.clone(), display);
                    }
                });
            ui.add_space(16.0);
            ui.add(egui::Slider::new(&mut self.key_length, 1..=25).text("Max Key Length"));
            ui.add_space(16.0);
            // Run the function and update the result
            if let Some(_) = &self.result{
                let value = &self.result.as_ref().unwrap();

                ui.heading(egui::RichText::new(format!("Chi Score:                 {}", value.chi_percent))
                    .color(egui::Color32::LIGHT_GREEN)
                    .font(FontId::monospace(16.0)));
                ui.heading(egui::RichText::new(format!("Index of Coincidence:      {}", value.coincidence))
                    .color(egui::Color32::LIGHT_GREEN)
                    .font(FontId::monospace(16.0)));
                ui.heading(egui::RichText::new(format!("Key Elimination Score:     {} Length: {} Likely Key: {}", value.key_elim_score,value.key_elim_key_length, value.key_elim_key))
                    .color(egui::Color32::LIGHT_GREEN)
                    .font(FontId::monospace(16.0)));
                ui.heading(egui::RichText::new(format!("Match Score:               {}", value.match_percent))
                    .color(egui::Color32::LIGHT_GREEN)
                    .font(FontId::monospace(16.0)));
                ui.heading(egui::RichText::new(format!("Friedman Confidence:       {} Length: {}", value.friedman_confidence, value.friedman_key_length))
                    .color(egui::Color32::LIGHT_GREEN)
                    .font(FontId::monospace(16.0)));
                ui.heading(egui::RichText::new(format!("Kasiski Key Length:        {:?}", value.kasiski))
                    .color(egui::Color32::LIGHT_GREEN)
                    .font(FontId::monospace(16.0)));
                ui.heading(egui::RichText::new(format!("Phi Test Confidence:       {} Length: {}", value.phi_score, value.phi_key))
                    .color(egui::Color32::LIGHT_GREEN)
                    .font(FontId::monospace(16.0)));
                ui.heading(egui::RichText::new(format!("Aster Score:               {}", value.aster_score))
                    .color(egui::Color32::LIGHT_GREEN)
                    .font(FontId::monospace(16.0)));
                ui.heading(egui::RichText::new(format!("Substitution Score:        {}", value.substitution_score))
                    .color(egui::Color32::LIGHT_GREEN)
                    .font(FontId::monospace(16.0)));
            }
            ui.add_space(16.0);
            ui.add_sized(
                [500.0, 200.0],
                egui::TextEdit::multiline(&mut self.output)
                    .font(FontId::monospace(16.0))
                    .hint_text("Output Text"),
            );
            if ui.add_sized([500.0, 50.0],(egui::Button::new(egui::RichText::new("Analyze Output & Plaintext").size(24.0).color(egui::Color32::LIGHT_GREEN)))).clicked() {
                self.result = Some(analyze(&self.output, &self.selected_k1p, self.key_length, &[1, 2, 4]));
            } 
            
        });
        egui::SidePanel::right("right_panel")
            .min_width(600.0)
            .resizable(false)
            .show(ctx, |ui| {
                ui.vertical_centered(|ui| {
                    ui.heading("Right Panel");
                });

                ui.label("This is the right panel");
                
                if ui.button("Button").clicked() {
                    // Handle button click event
                }
            
        });
    }
}

fn main() -> Result<(), eframe::Error> {

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_inner_size([1920.0, 1080.0]),
        ..Default::default()
    };
    eframe::run_native(
        "My egui App",
        options,
        Box::new(|cc| {
            // This gives us image support:
            egui_extras::install_image_loaders(&cc.egui_ctx);

            Box::<MyApp>::default()
        }),
    )
}