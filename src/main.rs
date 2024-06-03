use std::fmt::Pointer;

use eframe::egui;

mod analysis;
use analysis::*;

mod crypt;
use crypt::*;

mod vigenere;
use vigenere::*;

struct MyApp {
    result: String,
}

impl Default for MyApp {
    fn default() -> Self {
        Self {
            result: String::new(),
        }
    }
}

impl eframe::App for MyApp {
    fn update(&mut self, ctx: &egui::Context, frame: &mut eframe::Frame) {


        egui::CentralPanel::default().show(ctx, |ui| {
            ui.vertical_centered(|ui| {
                ui.heading("KRYPTON");
            });

            ui.label(&self.result);
        });

        // Run the function and update the result
        if self.result.is_empty() {
            self.result = analysis(K4, K4p, 200, &[1, 2, 4]);
        }
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