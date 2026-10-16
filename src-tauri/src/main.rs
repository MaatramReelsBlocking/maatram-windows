#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]

mod logic;

#[cfg(windows)]
mod windows_app;
#[cfg(target_os = "linux")]
mod linux_app;

#[cfg(windows)]
fn main() {
    windows_app::run();
}

#[cfg(target_os = "linux")]
fn main() {
    linux_app::run();
}

#[cfg(not(any(windows, target_os = "linux")))]
compile_error!("Maatram Hard Lock currently supports Windows and Linux builds only.");
