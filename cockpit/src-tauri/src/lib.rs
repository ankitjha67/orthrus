// ORTHRUS cockpit — Tauri 2.0 desktop shell around the React frontend.
// The window loads the built SPA (../dist), which talks to the ORTHRUS REST API.

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .run(tauri::generate_context!())
        .expect("error while running the ORTHRUS cockpit");
}
