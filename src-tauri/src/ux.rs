//! Linux and macOS window. The guard (`guard/`, runs as root) does the locking. This window shows its
//! state and sends it requests. The first request installs the guard: one admin prompt, then none.

use crate::logic;
use serde::{Deserialize, Serialize};
use std::{
    env, fs,
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::Path,
    process::Command,
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tauri::Manager;

// Built by CI into src-tauri/guard-bin/ before the window is built; a plain `cargo check` gets an empty stand-in (build.rs).
static GUARD: &[u8] = include_bytes!(env!("MAATRAM_GUARD_BIN"));

const MAX_MIN: u32 = 90;
const MAX_CUSTOM: usize = 30;

#[cfg(target_os = "linux")]
const DIR: &str = "/var/lib/maatram";
#[cfg(target_os = "linux")]
const ALIVE: &str = "/run/maatram-guard.alive";
#[cfg(target_os = "linux")]
const BIN: &str = "/usr/local/libexec/maatram/maatram-guard";

#[cfg(target_os = "macos")]
const DIR: &str = "/Library/Application Support/Maatram";
#[cfg(target_os = "macos")]
const ALIVE: &str = "/var/run/maatram-guard.alive";
#[cfg(target_os = "macos")]
const BIN: &str = "/Library/PrivilegedHelperTools/in.co.maatram.guard";

#[derive(Deserialize)]
struct Lock {
    start_ms: u64,
    end_ms: u64,
    sites: Vec<String>,
    apps: Vec<String>,
    blocked: u32,
}

#[derive(Serialize)]
struct State {
    active: bool,
    remaining_secs: u64,
    total_secs: u64,
    blocked: u32,
    custom_sites: Vec<String>,
    custom_apps: Vec<String>,
}

#[derive(Serialize)]
struct Blocklist {
    sites: Vec<&'static str>,
    apps: Vec<&'static str>,
}

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

fn read(name: &str) -> String {
    fs::read_to_string(Path::new(DIR).join(name)).unwrap_or_default().trim().to_string()
}

fn load() -> Option<Lock> {
    serde_json::from_str(&read("lock.json")).ok()
}

fn guard_ok() -> bool {
    let fresh = fs::metadata(ALIVE).and_then(|m| m.modified()).ok().and_then(|t| t.elapsed().ok()).is_some_and(|e| e < Duration::from_secs(6));
    fresh && read("guard-version") == logic::GUARD_VERSION
}

// ---------- installing the guard ----------

#[cfg(target_os = "linux")]
fn elevate(tmp: &Path) -> Result<(), String> {
    const SCRIPT: &str = "set -e; install -d -m 755 /usr/local/libexec/maatram; install -m 755 \"$1\" /usr/local/libexec/maatram/maatram-guard; /usr/local/libexec/maatram/maatram-guard --install";
    let st = Command::new("pkexec").args(["/bin/sh", "-c", SCRIPT, "sh"]).arg(tmp).status().map_err(|_| manual())?;
    if st.success() {
        Ok(())
    } else {
        Err(format!("Admin permission was not given, so Hard Lock could not be set up. {}", manual()))
    }
}

#[cfg(target_os = "macos")]
fn elevate(tmp: &Path) -> Result<(), String> {
    let script = format!(
        "do shell script \"mkdir -p /Library/PrivilegedHelperTools && install -m 755 '{}' '{BIN}' && '{BIN}' --install\" with administrator privileges",
        tmp.display()
    );
    let st = Command::new("osascript").args(["-e", &script]).status().map_err(|e| format!("Cannot ask for admin permission: {e}"))?;
    if st.success() {
        Ok(())
    } else {
        Err("Admin permission was not given, so Hard Lock could not be set up.".into())
    }
}

fn manual() -> String {
    "Or open a terminal and run: sudo maatram-hardlock --install-guard".into()
}

/// One admin prompt the first time; afterwards the guard is already running and nothing is asked.
fn ensure_guard() -> Result<(), String> {
    if guard_ok() {
        return Ok(());
    }
    if GUARD.is_empty() {
        return Err("This copy has no guard program inside. Download Maatram again from maatram.co.in/download.".into());
    }
    let tmp = env::temp_dir().join(format!("maatram-guard-{}", std::process::id()));
    fs::write(&tmp, GUARD).and_then(|_| fs::set_permissions(&tmp, fs::Permissions::from_mode(0o755))).map_err(|e| format!("Cannot prepare the guard: {e}"))?;
    let res = elevate(&tmp);
    let _ = fs::remove_file(&tmp);
    res?;
    for _ in 0..40 {
        if guard_ok() {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(250));
    }
    Err("The guard did not start. Try again, or run: sudo maatram-hardlock --install-guard".into())
}

/// `sudo maatram-hardlock --install-guard`: the same install, for desktops with no admin prompt.
fn install_cli() {
    let res = (|| -> Result<(), String> {
        let bin = Path::new(BIN);
        fs::create_dir_all(bin.parent().ok_or("bad path")?).map_err(|e| format!("Run this with sudo ({e})"))?;
        fs::write(bin, GUARD).map_err(|e| e.to_string())?;
        fs::set_permissions(bin, fs::Permissions::from_mode(0o755)).map_err(|e| e.to_string())?;
        let ok = Command::new(bin).arg("--install").status().map(|s| s.success()).unwrap_or(false);
        if ok { Ok(()) } else { Err("The guard install failed".into()) }
    })();
    match res {
        Ok(()) => println!("Maatram guard installed. Open Maatram and start a Hard Lock."),
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    }
}

// ---------- requests to the guard ----------

fn send(req: serde_json::Value) -> Result<(), String> {
    let p = Path::new(DIR).join("inbox").join(format!("{}-{}.json", now_ms(), std::process::id()));
    let mut f = fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&p).map_err(|e| format!("Cannot reach the guard: {e}"))?;
    f.write_all(req.to_string().as_bytes()).map_err(|e| e.to_string())
}

// ---------- commands ----------

#[tauri::command]
fn get_blocklist() -> Blocklist {
    let mut sites: Vec<&'static str> = logic::SITES.to_vec();
    sites.extend_from_slice(logic::EXTRA_HOSTS);
    Blocklist { sites, apps: logic::APPS.to_vec() }
}

#[tauri::command]
fn get_state() -> State {
    match load() {
        Some(l) if now_ms() < l.end_ms => State {
            active: true,
            remaining_secs: logic::remaining_secs(l.end_ms, now_ms()),
            total_secs: (l.end_ms - l.start_ms) / 1000,
            blocked: l.blocked,
            custom_sites: l.sites,
            custom_apps: l.apps,
        },
        _ => State { active: false, remaining_secs: 0, total_secs: 0, blocked: 0, custom_sites: vec![], custom_apps: vec![] },
    }
}

// async: Tauri runs sync commands on the UI thread, and the admin prompt would freeze the window.
#[tauri::command]
async fn start_lock(minutes: u32, sites: Vec<String>, apps: Vec<String>) -> Result<(), String> {
    if !(1..=MAX_MIN).contains(&minutes) {
        return Err(format!("Pick 1 to {MAX_MIN} minutes"));
    }
    if sites.len() + apps.len() > MAX_CUSTOM {
        return Err(format!("Add at most {MAX_CUSTOM} custom entries"));
    }
    if get_state().active {
        return Err("A lock is already running".into());
    }
    let sites = sites.iter().map(|s| logic::clean_site(s)).collect::<Result<Vec<_>, _>>()?;
    let apps = apps.iter().map(|s| logic::clean_app(s)).collect::<Result<Vec<_>, _>>()?;
    ensure_guard()?;
    send(serde_json::json!({ "cmd": "start", "minutes": minutes, "sites": sites, "apps": apps }))?;
    for _ in 0..20 {
        if get_state().active {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(250));
    }
    Err("The guard could not start the lock. Run the app again, or see the README.".into())
}

#[tauri::command]
fn get_link() -> String {
    read("link.txt")
}

/// Saves a link code (blank unlinks) and returns it cleaned.
#[tauri::command]
async fn set_link(code: String) -> Result<String, String> {
    let c = logic::clean_code(&code)?;
    if c.is_empty() && !guard_ok() {
        return Ok(c); // nothing is linked and no guard is running
    }
    ensure_guard()?;
    send(serde_json::json!({ "cmd": "link", "code": c }))?;
    for _ in 0..12 {
        if read("link.txt") == c {
            return Ok(c);
        }
        thread::sleep(Duration::from_millis(250));
    }
    Err("The guard did not save the link code".into())
}

#[tauri::command]
fn get_platform() -> &'static str {
    if cfg!(target_os = "macos") { "macos" } else { "linux" }
}

pub fn main() {
    if env::args().any(|a| a == "--install-guard") {
        return install_cli();
    }
    tauri::Builder::default()
        .setup(|app| {
            if let Some(w) = app.get_webview_window("main") {
                let _ = w.show();
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![get_state, get_blocklist, start_lock, get_link, set_link, get_platform])
        .run(tauri::generate_context!())
        .expect("failed to start Maatram Hard Lock");
}
