#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod logic;

use serde::{Deserialize, Serialize};
use std::{
    collections::HashSet,
    env, fs,
    path::PathBuf,
    process::Command,
    sync::Mutex,
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use sysinfo::{Process, ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind};
use tauri::{
    menu::{Menu, MenuItem},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
    AppHandle, Manager,
};

const TASK: &str = "MaatramHardLock"; // logon task -> main app (hidden to tray)
const DOG: &str = "MaatramWatchdog"; // logon task -> watchdog
const MAX_MIN: u32 = 90;
const MAX_CUSTOM: usize = 30; // same cap as the UI
#[cfg(windows)]
const NO_WINDOW: u32 = 0x0800_0000; // CREATE_NO_WINDOW

static IO: Mutex<()> = Mutex::new(());

#[derive(Serialize, Deserialize, Clone)]
struct Lock {
    start_ms: u64,
    end_ms: u64,
    sites: Vec<String>, // custom only; built-ins live in logic.rs
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

// ---------- paths, time, storage ----------

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

fn data_dir() -> PathBuf {
    let base = env::var("ProgramData").unwrap_or_else(|_| "C:\\ProgramData".into());
    let d = PathBuf::from(base).join("Maatram");
    let _ = fs::create_dir_all(&d);
    d
}

fn lock_path() -> PathBuf {
    data_dir().join("lock.json")
}

fn hosts_path() -> PathBuf {
    PathBuf::from(env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".into())).join(r"System32\drivers\etc\hosts")
}

fn guard() -> std::sync::MutexGuard<'static, ()> {
    IO.lock().unwrap_or_else(|e| e.into_inner())
}

fn load_raw() -> Option<Lock> {
    serde_json::from_str(&fs::read_to_string(lock_path()).ok()?).ok()
}

fn load() -> Option<Lock> {
    let _g = guard();
    load_raw()
}

fn save(l: &Lock) -> Result<(), String> {
    let _g = guard();
    let json = serde_json::to_string(l).map_err(|e| e.to_string())?;
    fs::write(lock_path(), json).map_err(|e| format!("Cannot save lock: {e}"))
}

fn bump(n: u32) {
    let _g = guard();
    if let Some(mut l) = load_raw() {
        l.blocked += n;
        if let Ok(json) = serde_json::to_string(&l) {
            let _ = fs::write(lock_path(), json);
        }
    }
}

fn is_locked() -> bool {
    load().is_some_and(|l| now_ms() < l.end_ms)
}

// ---------- process helpers ----------

fn run(cmd: &str, args: &[&str]) -> bool {
    let mut c = Command::new(cmd);
    c.args(args);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        c.creation_flags(NO_WINDOW);
    }
    c.output().map(|o| o.status.success()).unwrap_or(false)
}

fn exe_name() -> String {
    env::current_exe()
        .ok()
        .and_then(|p| p.file_name().map(|n| n.to_string_lossy().to_lowercase()))
        .unwrap_or_default()
}

fn is_dog(p: &Process) -> bool {
    p.cmd().iter().any(|a| a == "--watchdog")
}

fn refresh(sys: &mut System) {
    sys.refresh_processes_specifics(
        ProcessesToUpdate::All,
        true,
        ProcessRefreshKind::nothing().with_cmd(UpdateKind::OnlyIfNotSet),
    );
}

/// (other main instances, other watchdogs with a lower PID), excluding this process.
/// The lower-PID rule picks exactly one surviving watchdog when several start at once.
fn peers(sys: &mut System) -> (usize, usize) {
    refresh(sys);
    let (me, name) = (std::process::id(), exe_name());
    let (mut mains, mut dogs) = (0, 0);
    for (pid, p) in sys.processes() {
        if pid.as_u32() == me || p.name().to_string_lossy().to_lowercase() != name {
            continue;
        }
        if is_dog(p) {
            if pid.as_u32() < me {
                dogs += 1;
            }
        } else {
            mains += 1;
        }
    }
    (mains, dogs)
}

fn spawn_self(arg: &str) {
    if let Ok(exe) = env::current_exe() {
        let mut c = Command::new(exe);
        c.arg(arg);
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            c.creation_flags(NO_WINDOW);
        }
        let _ = c.spawn();
    }
}

/// Start via Task Scheduler so the new process is NOT a child of the caller
/// ("End process tree" in Task Manager then cannot take both down). Falls back to a direct spawn.
fn launch(task: &str, arg: &str) {
    if !run("schtasks", &["/Run", "/TN", task]) {
        spawn_self(arg);
    }
}

fn create_task(name: &str, arg: &str) {
    let Ok(exe) = env::current_exe() else { return };
    let exe_s = exe.to_string_lossy().to_string();
    // XML so the task also runs on battery and never times out (schtasks CLI defaults cannot).
    let xml = format!(
        r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Triggers><LogonTrigger><Enabled>true</Enabled></LogonTrigger></Triggers>
  <Principals><Principal id="A"><LogonType>InteractiveToken</LogonType><RunLevel>HighestAvailable</RunLevel></Principal></Principals>
  <Settings>
    <MultipleInstancesPolicy>Parallel</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Hidden>true</Hidden>
    <Enabled>true</Enabled>
  </Settings>
  <Actions Context="A"><Exec><Command>{}</Command><Arguments>{}</Arguments></Exec></Actions>
</Task>"#,
        exe_s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;"),
        arg
    );
    // schtasks /XML reliably reads only UTF-16 LE with BOM (the format Task Scheduler itself exports).
    let bytes: Vec<u8> = std::iter::once(0xFEFF).chain(xml.encode_utf16()).flat_map(u16::to_le_bytes).collect();
    let path = data_dir().join(format!("{name}.xml"));
    let made = fs::write(&path, bytes).is_ok()
        && run("schtasks", &["/Create", "/TN", name, "/XML", &path.to_string_lossy(), "/F"]);
    if !made {
        run("schtasks", &["/Create", "/TN", name, "/TR", &format!("\"{exe_s}\" {arg}"), "/SC", "ONLOGON", "/RL", "HIGHEST", "/F"]);
    }
}

// ---------- blocking ----------

fn merged_apps(l: &Lock) -> HashSet<String> {
    logic::APPS.iter().map(|s| s.to_string()).chain(l.apps.iter().cloned()).collect()
}

fn read_hosts() -> String {
    fs::read(hosts_path()).map(|b| String::from_utf8_lossy(&b).into_owned()).unwrap_or_default()
}

/// Writes the block only when the file differs, so a user edit is repaired within one tick.
fn apply_hosts(l: &Lock) -> Result<(), String> {
    let cur = read_hosts();
    let want = logic::with_block(&cur, &logic::hosts_block(&l.sites));
    if want != cur {
        clear_readonly();
        fs::write(hosts_path(), want).map_err(|e| format!("Cannot edit the hosts file ({e}). Run Maatram as administrator."))?;
        run("ipconfig", &["/flushdns"]);
    }
    Ok(())
}

/// Some PCs (and some "hosts protection" tools) mark the hosts file read-only, which makes every write fail.
#[allow(clippy::permissions_set_readonly_false)]
fn clear_readonly() {
    if let Ok(m) = fs::metadata(hosts_path()) {
        let mut p = m.permissions();
        if p.readonly() {
            p.set_readonly(false);
            let _ = fs::set_permissions(hosts_path(), p);
        }
    }
}

fn restore_hosts() {
    let cur = read_hosts();
    if logic::has_block(&cur) {
        clear_readonly();
        let _ = fs::write(hosts_path(), logic::strip_block(&cur));
        run("ipconfig", &["/flushdns"]);
    }
}

fn end_lock() {
    restore_hosts();
    for t in [TASK, DOG] {
        run("schtasks", &["/Delete", "/TN", t, "/F"]);
    }
    let _g = guard();
    let _ = fs::remove_file(lock_path());
}

/// `seen`: apps killed on the previous tick. One open attempt = one app name appearing,
/// however many processes it spawns (Discord, Steam run several) and however many ticks it retries.
fn tick(sys: &mut System, last_dog_launch: &mut Instant, seen: &mut HashSet<String>) {
    let Some(l) = load() else { return };
    if now_ms() >= l.end_ms {
        end_lock();
        return;
    }
    let _ = apply_hosts(&l);
    refresh(sys);
    let (names, me, exe) = (merged_apps(&l), std::process::id(), exe_name());
    let mut dogs = 0u32;
    let mut killed = HashSet::new();
    for (pid, p) in sys.processes() {
        let n = p.name().to_string_lossy().to_lowercase();
        if names.contains(&n) {
            if p.kill() {
                killed.insert(n);
            }
        } else if n == exe && pid.as_u32() != me && is_dog(p) {
            dogs += 1;
        }
    }
    let new = killed.difference(seen).count() as u32;
    if new > 0 {
        bump(new);
    }
    *seen = killed;
    if dogs == 0 && last_dog_launch.elapsed() > Duration::from_secs(5) {
        launch(DOG, "--watchdog");
        *last_dog_launch = Instant::now();
    }
}

fn show_flag() -> PathBuf {
    data_dir().join("show")
}

fn enforce(app: AppHandle) {
    let mut sys = System::new();
    let mut last = Instant::now() - Duration::from_secs(60);
    let mut seen = HashSet::new();
    loop {
        tick(&mut sys, &mut last, &mut seen);
        // A second launch left a note instead of opening a duplicate: bring this window up.
        if fs::remove_file(show_flag()).is_ok() {
            show(&app);
        }
        thread::sleep(Duration::from_secs(1));
    }
}

/// Second process: if the app disappears during a lock, bring it back; clean up if the lock expired.
fn watchdog() {
    let mut sys = System::new();
    let mut last = Instant::now() - Duration::from_secs(60);
    loop {
        let (mains, older_dogs) = peers(&mut sys);
        if older_dogs > 0 {
            return; // another watchdog wins; never two, never zero
        }
        match load() {
            None => return,
            Some(l) if now_ms() >= l.end_ms => {
                end_lock();
                return;
            }
            Some(_) => {
                if mains == 0 && last.elapsed() > Duration::from_secs(5) {
                    launch(TASK, "--autostart");
                    last = Instant::now();
                }
            }
        }
        thread::sleep(Duration::from_secs(2));
    }
}

/// Run by the uninstaller (`--cleanup`): uninstalling mid-lock must never leave sites blocked forever.
fn cleanup() {
    {
        let _g = guard();
        let _ = fs::remove_file(lock_path());
    }
    thread::sleep(Duration::from_secs(3)); // watchdog sees no lock and exits instead of relaunching
    let mut sys = System::new();
    refresh(&mut sys);
    let (me, name) = (std::process::id(), exe_name());
    for (pid, p) in sys.processes() {
        if pid.as_u32() != me && p.name().to_string_lossy().to_lowercase() == name {
            p.kill();
        }
    }
    end_lock();
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

// async: Tauri runs sync commands on the UI thread, and the schtasks/ipconfig calls here
// would freeze the window ("Not responding") for a second or two.
#[tauri::command]
async fn start_lock(minutes: u32, sites: Vec<String>, apps: Vec<String>) -> Result<(), String> {
    if !(1..=MAX_MIN).contains(&minutes) {
        return Err(format!("Pick 1 to {MAX_MIN} minutes"));
    }
    if sites.len() + apps.len() > MAX_CUSTOM {
        return Err(format!("Add at most {MAX_CUSTOM} custom entries"));
    }
    if is_locked() {
        return Err("A lock is already running".into());
    }
    let sites = sites.iter().map(|s| logic::clean_site(s)).collect::<Result<Vec<_>, _>>()?;
    let apps = apps.iter().map(|s| logic::clean_app(s)).collect::<Result<Vec<_>, _>>()?;
    let now = now_ms();
    let l = Lock { start_ms: now, end_ms: now + u64::from(minutes) * 60_000, sites, apps, blocked: 0 };
    save(&l)?;
    // Never start a lock that cannot block (e.g. not admin): undo and report.
    if let Err(e) = apply_hosts(&l) {
        let _g = guard();
        let _ = fs::remove_file(lock_path());
        return Err(e);
    }
    create_task(TASK, "--autostart");
    create_task(DOG, "--watchdog");
    launch(DOG, "--watchdog");
    Ok(())
}

// ---------- app ----------

fn show(app: &AppHandle) {
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.show();
        let _ = w.unminimize();
        let _ = w.set_focus();
    }
}

fn main() {
    if env::args().any(|a| a == "--watchdog") {
        return watchdog();
    }
    if env::args().any(|a| a == "--cleanup") {
        return cleanup();
    }
    if peers(&mut System::new()).0 > 0 {
        // One main instance only. Ask the running one (maybe hidden in the tray) to show itself.
        let _ = fs::write(show_flag(), "");
        return;
    }
    let _ = fs::remove_file(show_flag()); // stale note from a crash must not pop the window later

    tauri::Builder::default()
        .setup(|app| {
            let open = MenuItem::with_id(app, "open", "Open", true, None::<&str>)?;
            let quit = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;
            let menu = Menu::with_items(app, &[&open, &quit])?;
            let mut tray = TrayIconBuilder::new()
                .menu(&menu)
                .show_menu_on_left_click(false)
                .on_menu_event(|app, ev| match ev.id().as_ref() {
                    "open" => show(app),
                    // Quit is refused during a lock; show the timer so the click is not silently ignored.
                    "quit" if is_locked() => show(app),
                    "quit" => app.exit(0),
                    _ => {}
                })
                .tooltip("Maatram Hard Lock")
                .on_tray_icon_event(|tray, ev| {
                    if let TrayIconEvent::Click { button: MouseButton::Left, button_state: MouseButtonState::Up, .. } = ev {
                        show(tray.app_handle());
                    }
                });
            if let Some(icon) = app.default_window_icon() {
                tray = tray.icon(icon.clone());
            }
            tray.build(app)?;

            if !(env::args().any(|a| a == "--autostart") && is_locked()) {
                show(app.handle());
            }
            let handle = app.handle().clone();
            thread::spawn(move || enforce(handle));
            Ok(())
        })
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                if is_locked() {
                    api.prevent_close();
                    let _ = window.hide();
                }
            }
        })
        .invoke_handler(tauri::generate_handler![get_state, get_blocklist, start_lock])
        .run(tauri::generate_context!())
        .expect("failed to start Maatram Hard Lock");
}
