use std::fmt::Pointer;

use analysis::analyze;
use eframe::egui;

mod analysis;

mod crypt;
use crypt::*;

mod vigenere;
use egui::FontId;
use vigenere::*;

struct MyApp {
    result: (String, String, Vec<usize>, usize, String, String, usize, String),
    selected_k1: String,
    selected_k1p: String,
    key_length: usize,
}

impl Default for MyApp {
    fn default() -> Self {
        Self {
            result: Default::default(),
            selected_k1: String::new(),
            selected_k1p: String::new(),
            key_length: Default::default(),
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
            if ui.add_sized([1010.0, 50.0],(egui::Button::new(egui::RichText::new("Analyze").size(24.0).color(egui::Color32::LIGHT_GREEN)))).clicked() {
                self.result = analyze(&self.selected_k1, &self.selected_k1p, self.key_length, &[1, 2, 4]);
            }                                                                                                                                                   

            egui::ComboBox::from_label("Selected Encrypted Text")
                .selected_text(k1_options.iter().find(|&(_, v)| *v == self.selected_k1).unwrap_or_else(|| &k1_options[0]).0.clone())
                .show_ui(ui, |ui| {
                    for (display, value) in &k1_options {
                        ui.selectable_value(&mut self.selected_k1, value.clone(), display);
                    }
                });
        
            egui::ComboBox::from_label("Select Known Plaintext")
                .selected_text(k1p_options.iter().find(|&(_, v)| *v == self.selected_k1p).unwrap_or_else(|| &k1p_options[0]).0.clone())
                .show_ui(ui, |ui| {
                    for (display, value) in &k1p_options {
                        ui.selectable_value(&mut self.selected_k1p, value.clone(), display);
                    }
                });

            ui.add(egui::Slider::new(&mut self.key_length, 1..=25).text("Max Key Length"));
            
            // Run the function and update the result
            if !self.result.0.is_empty() {
                let value = &self.result;

                ui.heading(egui::RichText::new(format!("Chi Score:                 {}", value.0))
                    .color(egui::Color32::LIGHT_GREEN)
                    .font(FontId::monospace(16.0)));
                ui.heading(egui::RichText::new(format!("Match Score:               {}", value.1))
                    .color(egui::Color32::LIGHT_GREEN)
                    .font(FontId::monospace(16.0)));
                ui.heading(egui::RichText::new(format!("Kasiski Key Length:        {:?}", value.2))
                    .color(egui::Color32::LIGHT_GREEN)
                    .font(FontId::monospace(16.0)));
                ui.heading(egui::RichText::new(format!("Friedman Confidence:       {} Length: {}", value.4, value.3))
                    .color(egui::Color32::LIGHT_GREEN)
                    .font(FontId::monospace(16.0)));
                ui.heading(egui::RichText::new(format!("Key Elimination Score:     {} Length: {} Likely Key: {}", value.5, value.6, value.7))
                    .color(egui::Color32::LIGHT_GREEN)
                    .font(FontId::monospace(16.0)));
                

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