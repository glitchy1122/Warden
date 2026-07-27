mod bloom;
mod bypass;
mod db;
mod dns;
mod engine;
mod lookup;

#[cfg(windows)]
#[path = "ip_block.rs"]
mod ip_block;

#[cfg(not(windows))]
#[path = "ip_block_stub.rs"]
mod ip_block;

#[cfg(windows)]
#[path = "wfp.rs"]
mod wfp;

#[cfg(not(windows))]
#[path = "wfp_stub.rs"]
mod wfp;

#[cfg(windows)]
#[path = "vpn_guard.rs"]
mod vpn_guard;

#[cfg(not(windows))]
#[path = "vpn_guard_stub.rs"]
mod vpn_guard;

use engine::{
    add_custom_domain, check_domain, get_status, list_custom_domains, remove_custom_domain,
    set_protection, AppState,
};
use tauri::Manager;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .setup(|app| {
            let state = AppState::initialize(app.handle()).map_err(|e| {
                Box::<dyn std::error::Error>::from(e)
            })?;
            app.manage(state);
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            get_status,
            set_protection,
            list_custom_domains,
            add_custom_domain,
            remove_custom_domain,
            check_domain
        ])
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { .. } = event {
                let state = window.state::<AppState>();
                let _ = state.disable_protection();
            }
        })
        .run(tauri::generate_context!())
        .expect("error while running Warden");
}
