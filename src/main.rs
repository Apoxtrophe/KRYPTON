use std::fmt::Pointer;

use analysis::{analyze, percentage_blocks, AnalysisResult};
use eframe::egui;

mod analysis;

mod crypt;
use crypt::*;

mod decipher;
use decipher::*;

mod vigenere;
use egui::{style::HandleShape, FontId};
use vigenere::*;

mod toolkit;
use toolkit::*;

struct MyApp {
    analysis: Option<AnalysisResult>,
    encrypted: String,
    plaintext: String,
    key_length: usize,
    key1: String,
    key2: String,
    output: String,
    terminal1: String, 
    terminal2: String, 
    terminal3: String, 
    terminal4: String, 
    
    
}

impl Default for MyApp {
    fn default() -> Self {
        Self {
            analysis: None,
            encrypted: "ENCRYPTED".to_string(),
            plaintext: "PLAINTEXT".to_string(),
            output: "OUTPUT".to_string(),
            key_length: Default::default(),
            key1: String::new(),
            key2: String::new(),
            terminal1: String::new(),
            terminal2: String::new(),
            terminal3: String::new(),
            terminal4: String::new(),
        }
    }
}

impl eframe::App for MyApp {
    fn update(&mut self, ctx: &egui::Context, frame: &mut eframe::Frame) {
        egui::SidePanel::left("ANALYSIS")
            .min_width(ctx.available_rect().width() * 0.25)
            .resizable(false)
            .show(ctx, |ui| {
                ui.vertical_centered(|ui| {
                    ui.heading(egui::RichText::new("ANALYSIS").size(48.0).color(egui::Color32::LIGHT_GREEN).font(FontId::monospace(32.0)));
                    ui.separator();
                    ui.add_space(32.0);

                    if let Some(_) = &self.analysis{
                        let value = &self.analysis.as_ref().unwrap();
                        ui.horizontal(|ui| {
                            ui.heading(egui::RichText::new(format!("CHI SCORE:                 |")).color(egui::Color32::LIGHT_GREEN).font(FontId::monospace(16.0)));
                            ui.heading(egui::RichText::new(format!("{}   |", percentage_blocks(value.chi_score, 0.0, 10.0))).color(egui::Color32::LIGHT_GREEN).font(FontId::monospace(16.0)));
                            ui.heading(egui::RichText::new(format!("{:?}", value.chi_score)).color(egui::Color32::WHITE).font(FontId::monospace(16.0)));                          
                        });
                        ui.horizontal(|ui| {
                            ui.heading(egui::RichText::new(format!("MATCH SCORE:               |")).color(egui::Color32::LIGHT_GREEN).font(FontId::monospace(16.0)));
                            ui.heading(egui::RichText::new(format!("{}   |", percentage_blocks(value.match_score, 0.0, 100.0))).color(egui::Color32::LIGHT_GREEN).font(FontId::monospace(16.0)));
                            ui.heading(egui::RichText::new(format!("{:?}", value.match_score)).color(egui::Color32::WHITE).font(FontId::monospace(16.0)));
                        });
                       
                        ui.horizontal(|ui| {
                            ui.heading(egui::RichText::new(format!("FRIEDMAN TEST:             |")).color(egui::Color32::LIGHT_GREEN).font(FontId::monospace(16.0)));
                            ui.heading(egui::RichText::new(format!("{}   |", percentage_blocks(value.friedman.1, 0.0, 1.0))).color(egui::Color32::LIGHT_GREEN).font(FontId::monospace(16.0)));
                            ui.heading(egui::RichText::new(format!("{:?}", value.friedman)).color(egui::Color32::WHITE).font(FontId::monospace(16.0)));
                        });

                        ui.horizontal(|ui| {
                            ui.heading(egui::RichText::new(format!("KEY ELIMINATION:           |")).color(egui::Color32::LIGHT_GREEN).font(FontId::monospace(16.0)));
                            ui.heading(egui::RichText::new(format!("{}   |", percentage_blocks(value.key_elim.1, 0.0, 0.6))).color(egui::Color32::LIGHT_GREEN).font(FontId::monospace(16.0)));
                            ui.heading(egui::RichText::new(format!("{:?}", value.key_elim)).color(egui::Color32::WHITE).font(FontId::monospace(16.0)));
                        });

                        ui.horizontal(|ui| {
                            ui.heading(egui::RichText::new(format!("INCIDENCE OF COINCIDENCE:  |")).color(egui::Color32::LIGHT_GREEN).font(FontId::monospace(16.0)));
                            ui.heading(egui::RichText::new(format!("{}   |", percentage_blocks(value.IOC, 0.572, 1.04))).color(egui::Color32::LIGHT_GREEN).font(FontId::monospace(16.0)));
                            ui.heading(egui::RichText::new(format!("{:?}", value.IOC)).color(egui::Color32::WHITE).font(FontId::monospace(16.0)));
                        });

                        ui.horizontal(|ui| {
                            ui.heading(egui::RichText::new(format!("AVG INDEX OF COINCIDENCE:  |")).color(egui::Color32::LIGHT_GREEN).font(FontId::monospace(16.0)));
                            ui.heading(egui::RichText::new(format!("{}   |", percentage_blocks(value.phi.1, 1.0, 2.5))).color(egui::Color32::LIGHT_GREEN).font(FontId::monospace(16.0)));
                            ui.heading(egui::RichText::new(format!("{:?}", value.phi)).color(egui::Color32::WHITE).font(FontId::monospace(16.0)));
                        });

                        ui.horizontal(|ui| {
                            ui.heading(egui::RichText::new(format!("ASTER SCORE:               |")).color(egui::Color32::LIGHT_GREEN).font(FontId::monospace(16.0)));
                            ui.heading(egui::RichText::new(format!("{}   |", percentage_blocks(value.aster, 0.0, 100.0))).color(egui::Color32::LIGHT_GREEN).font(FontId::monospace(16.0)));
                            ui.heading(egui::RichText::new(format!("{:?}", value.aster)).color(egui::Color32::WHITE).font(FontId::monospace(16.0)));
                        });

                        ui.horizontal(|ui| {
                            ui.heading(egui::RichText::new(format!("SUBSTITUTION SCORE:        |")).color(egui::Color32::LIGHT_GREEN).font(FontId::monospace(16.0)));
                            ui.heading(egui::RichText::new(format!("{}   |", percentage_blocks(value.substitution_match, 0.0, 100.0))).color(egui::Color32::LIGHT_GREEN).font(FontId::monospace(16.0)));
                            ui.heading(egui::RichText::new(format!("{:?}", value.substitution_match)).color(egui::Color32::WHITE).font(FontId::monospace(16.0)));
                        });
                        ui.horizontal(|ui| {
                            ui.heading(egui::RichText::new(format!("KASISKI EXAMINATION:       |")).color(egui::Color32::LIGHT_GREEN).font(FontId::monospace(16.0)));
                            ui.heading(egui::RichText::new(format!("{:?}|", value.kasiski)).color(egui::Color32::LIGHT_GREEN).font(FontId::monospace(16.0)));
                        });
                        
                    } 
                });
        });
        egui::SidePanel::right("TOOLKIT")
            .min_width(ctx.available_rect().width() * 0.25)
            .resizable(false)
            .show(ctx, |ui| {
                ui.vertical_centered(|ui| {
                    ui.heading(egui::RichText::new("TOOLKIT").size(48.0).color(egui::Color32::LIGHT_GREEN).font(FontId::monospace(32.0)));
                    ui.separator();
                    ui.add_space(32.0);
                });

                ui.vertical_centered_justified( |ui | {
                    ui.label(egui::RichText::new("Key 1").size(24.0).color(egui::Color32::LIGHT_GREEN));
                    ui.add_sized(
                        [100.0, 32.0],
                        egui::TextEdit::singleline(&mut self.key1)
                            .font(FontId::monospace(20.0))
                            .hint_text("Key 1").text_color(egui::Color32::LIGHT_YELLOW),
                    );
                    ui.label(egui::RichText::new("Key 2").size(24.0).color(egui::Color32::LIGHT_GREEN));
                    ui.add_sized(
                        [100.0, 32.0],
                        egui::TextEdit::singleline(&mut self.key2)
                            .font(FontId::monospace(20.0))
                            .hint_text("Key 2").text_color(egui::Color32::LIGHT_YELLOW),
                    );
                    ui.add_space(16.0);
                    ui.style_mut().spacing.slider_width = 300.0;
                    ui.style_mut().spacing.slider_rail_height = 16.0;
                    ui.add(egui::Slider::new(&mut self.key_length, 1..=25)
                    .prefix("Max Key Length:  ")
                    .handle_shape(HandleShape::Rect { aspect_ratio: (2.0) })
                    .text_color(egui::Color32::LIGHT_YELLOW));
                    if ui.add_sized([300.0,20.0],egui::Button::new(egui::RichText::new("Encrypt Viginere 1 Key\nPlaintext, Key1 -> Output").size(16.0).color(egui::Color32::LIGHT_GREEN))).clicked() {
                        self.output = vigenere_one_encrypt(&self.plaintext, &self.key1);
                    } 

                    if ui.add_sized([300.0,20.0],egui::Button::new(egui::RichText::new("Encrypt Viginere 2 Key\nPlaintext, Key1, Key2 -> Output").size(16.0).color(egui::Color32::LIGHT_GREEN))).clicked() {
                        self.output = vigenere_two_encrypt(&self.plaintext, &self.key1, &self.key2);
                    } 
                    ui.add_space(16.0);
                    if ui.add_sized([300.0,20.0],egui::Button::new(egui::RichText::new("Decrypt Viginere 1 Key\nEncrypted, Key1 -> Output").size(16.0).color(egui::Color32::LIGHT_GREEN))).clicked() {
                        self.output = vigenere_one_decrypt(&self.encrypted, &self.key1);
                    } 

                    if ui.add_sized([300.0,20.0], egui::Button::new(egui::RichText::new("Decrypt Viginere 2 Key\nEncrypted, Key1, Key2 -> Output").size(16.0).color(egui::Color32::LIGHT_GREEN))).clicked() {
                        self.output = vigenere_two_decrypt(&self.encrypted, &self.key1, &self.key2);
                    }       
                    ui.add_space(16.0);     
                });
        });
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.vertical_centered(|ui| {
                ui.heading(egui::RichText::new("KRYPTON").size(48.0).color(egui::Color32::WHITE).font(FontId::monospace(48.0)));
                ui.separator();
                ui.add_space(32.0);
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
                    [800.0, 200.0],
                    egui::TextEdit::multiline(&mut self.encrypted)
                        .font(FontId::monospace(16.0))
                        .hint_text("Encrypted Text"),
                );
            
                ui.add_sized(
                    [800.0, 200.0],
                    egui::TextEdit::multiline(&mut self.plaintext)
                        .font(FontId::monospace(16.0))
                        .hint_text("Known Plain Text"),
                );
            });
            if ui.add_sized([500.0, 50.0],(egui::Button::new(egui::RichText::new("Analyze Encrypted & Plaintext").size(24.0).color(egui::Color32::LIGHT_GREEN)))).clicked() {
                self.analysis = Some(analyze(&self.encrypted, &self.plaintext, self.key_length));
            } 
            ui.horizontal(|ui| {
                
                ui.add_space(1.0);
                
            });

            ui.add_space(16.0); 
            ui.add_space(16.0);
            
            ui.add_space(16.0);                                                                                                                
            ui.add_space(16.0);

           
            egui::ComboBox::from_label("Select Encrypted Text")
                .selected_text(k1_options.iter().find(|&(_, v)| *v == self.encrypted).unwrap_or_else(|| &k1_options[0]).0.clone())
                .show_ui(ui, |ui| {
                    for (display, value) in &k1_options {
                        ui.selectable_value(&mut self.encrypted, value.clone(), egui::RichText::new(display).size(16.0));
                    }
                });
            ui.add_space(16.0);
            egui::ComboBox::from_label("Select Known Plaintext")
                .selected_text(k1p_options.iter().find(|&(_, v)| *v == self.plaintext).unwrap_or_else(|| &k1p_options[0]).0.clone())
                .show_ui(ui, |ui| {
                    for (display, value) in &k1p_options {
                        ui.selectable_value(&mut self.plaintext, value.clone(), egui::RichText::new(display).size(16.0));
                    }
                });
            
            ui.add_space(16.0);
            ui.horizontal(|ui| {
                ui.add_sized(
                    [800.0, 200.0],
                    egui::TextEdit::multiline(&mut self.output)
                        .font(FontId::monospace(16.0))
                        .hint_text("Output Text"),
                );   
            ui.add_space(16.0);
            ui.label(egui::RichText::new(&self.terminal1).color(egui::Color32::WHITE).font(FontId::monospace(16.0)));
            ui.add_space(16.0);
            ui.label(egui::RichText::new(&self.terminal2).color(egui::Color32::WHITE).font(FontId::monospace(16.0)));
            ui.add_space(16.0);
            ui.label(egui::RichText::new(&self.terminal3).color(egui::Color32::WHITE).font(FontId::monospace(16.0)));
            ui.add_space(16.0);
            ui.label(egui::RichText::new(&self.terminal4).color(egui::Color32::WHITE).font(FontId::monospace(16.0)));
            });
            
        });
        
        
    }
}

fn main() -> Result<(), eframe::Error> {

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_inner_size([3440.0, 1440.0]).with_fullscreen(true),
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