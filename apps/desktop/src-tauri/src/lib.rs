//! Least-privilege native shell for the shared Constellation web application.

/// Starts the desktop application.
pub fn run() {
    let result = tauri::Builder::default().run(tauri::generate_context!());
    if let Err(error) = result {
        eprintln!("Constellation desktop failed to start: {error}");
        std::process::exit(1);
    }
}
