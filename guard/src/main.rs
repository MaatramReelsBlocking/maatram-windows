//! Maatram guard for Linux and macOS. No window, runs as root.
//!
//! One admin prompt installs it (the window does that the first time). After that it keeps the lock:
//! it edits the hosts file, closes the apps, follows the link code, and takes start requests from the
//! window through a drop folder (`inbox/`). A normal user cannot end it: the lock file is root-owned.
//!
//!   maatram-guard --daemon      run the guard (the service runs this)
//!   maatram-guard --install     install and start the service (needs root)
//!   maatram-guard --uninstall   remove the service, the lock and the hosts block (needs root)
//!   maatram-guard --restore     end any lock and clean the hosts file (needs root)

#[allow(dead_code)]
#[path = "../../src-tauri/src/logic.rs"]
mod logic;

use serde::{Deserialize, Serialize};
use std::{
    collections::HashSet,
    env, fs,
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    process::Command,
    sync::Mutex,
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, System};

const MAX_MIN: u32 = 90;
const MAX_CUSTOM: usize = 30; // same cap as the window
const API: &str = "https://maatram.co.in/api/link"; // shared lock with the phone app, website and Chrome

#[cfg(target_os = "linux")]
const BIN: &str = "/usr/local/libexec/maatram/maatram-guard";
#[cfg(target_os = "linux")]
const DIR: &str = "/var/lib/maatram";
#[cfg(target_os = "linux")]
const ALIVE: &str = "/run/maatram-guard.alive";
#[cfg(target_os = "linux")]
const UNIT: &str = "/etc/systemd/system/maatram-guard.service";

#[cfg(target_os = "macos")]
const BIN: &str = "/Library/PrivilegedHelperTools/in.co.maatram.guard";
#[cfg(target_os = "macos")]
const DIR: &str = "/Library/Application Support/Maatram";
#[cfg(target_os = "macos")]
const ALIVE: &str = "/var/run/maatram-guard.alive";
#[cfg(target_os = "macos")]
const PLIST: &str = "/Library/LaunchDaemons/in.co.maatram.guard.plist";

static IO: Mutex<()> = Mutex::new(());

#[derive(Serialize, Deserialize, Clone)]
struct Lock {
    start_ms: u64,
    end_ms: u64,
    sites: Vec<String>, // custom only; built-ins live in logic.rs
    apps: Vec<String>,
    blocked: u32,
    #[serde(default)]
    seen_ms: u64, // wall time of the last check, so a clock change can't end the lock (see logic::shift_end)
}

// ---------- paths, time, storage ----------

// Debug builds only: point the guard at a scratch folder so it can be tested without touching /etc.
fn dir() -> PathBuf {
    #[cfg(debug_assertions)]
    if let Ok(d) = env::var("MAATRAM_DIR") {
        return PathBuf::from(d);
    }
    PathBuf::from(DIR)
}

fn hosts_path() -> PathBuf {
    #[cfg(debug_assertions)]
    if let Ok(h) = env::var("MAATRAM_HOSTS") {
        return PathBuf::from(h);
    }
    PathBuf::from("/etc/hosts")
}

fn alive_path() -> PathBuf {
    #[cfg(debug_assertions)]
    if env::var("MAATRAM_DIR").is_ok() {
        return dir().join("alive");
    }
    PathBuf::from(ALIVE)
}

fn lock_path() -> PathBuf {
    dir().join("lock.json")
}

fn link_path() -> PathBuf {
    dir().join("link.txt")
}

fn inbox_path() -> PathBuf {
    dir().join("inbox")
}

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

fn guard() -> std::sync::MutexGuard<'static, ()> {
    IO.lock().unwrap_or_else(|e| e.into_inner())
}

/// Files the window reads: readable by everyone, writable only by root.
fn write_public(path: &PathBuf, data: &str) -> Result<(), String> {
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, data)
        .and_then(|_| fs::set_permissions(&tmp, fs::Permissions::from_mode(0o644)))
        .and_then(|_| fs::rename(&tmp, path))
        .map_err(|e| format!("Cannot write {}: {e}", path.display()))
}

fn load_raw() -> Option<Lock> {
    serde_json::from_str(&fs::read_to_string(lock_path()).ok()?).ok()
}

fn load() -> Option<Lock> {
    let _g = guard();
    load_raw()
}

fn write_raw(l: &Lock) -> Result<(), String> {
    write_public(&lock_path(), &serde_json::to_string(l).map_err(|e| e.to_string())?)
}

fn bump(n: u32) {
    let _g = guard();
    if let Some(mut l) = load_raw() {
        l.blocked += n;
        let _ = write_raw(&l);
    }
}

/// Loads the lock with its end moved by any wall-clock jump since the last check, and records this check.
/// `last`: when this process last checked (None = first check, so time the guard wasn't running counts as paused).
fn advance(last: &mut Option<Instant>) -> Option<Lock> {
    let _g = guard();
    let mut l = load_raw()?;
    let now = now_ms();
    let expected = last.map_or(0, |t| t.elapsed().as_millis() as u64);
    let end = logic::shift_end(l.end_ms, l.seen_ms, now, expected);
    l.start_ms = (i128::from(l.start_ms) + i128::from(end) - i128::from(l.end_ms)).max(0) as u64; // keep the total
    l.end_ms = end;
    l.seen_ms = now;
    *last = Some(Instant::now());
    let _ = write_raw(&l);
    Some(l)
}

fn link_code() -> String {
    fs::read_to_string(link_path()).unwrap_or_default().trim().to_string()
}

fn is_locked() -> bool {
    load().is_some_and(|l| now_ms() < l.end_ms)
}

// ---------- helpers ----------

fn run(cmd: &str, args: &[&str]) -> bool {
    Command::new(cmd).args(args).output().map(|o| o.status.success()).unwrap_or(false)
}

/// curl ships with Linux desktops and macOS, so no HTTP crate. None on any failure, including HTTP errors.
fn curl(args: &[&str]) -> Option<String> {
    let o = Command::new("curl").args(["-s", "-f", "-m", "8"]).args(args).output().ok()?;
    o.status.success().then(|| String::from_utf8_lossy(&o.stdout).into_owned())
}

fn flush_dns() {
    #[cfg(target_os = "macos")]
    {
        run("dscacheutil", &["-flushcache"]);
        run("killall", &["-HUP", "mDNSResponder"]);
    }
    #[cfg(target_os = "linux")]
    {
        // The hosts file is read live, so this only clears caches some setups keep. Best effort.
        let _ = run("resolvectl", &["flush-caches"]) || run("systemd-resolve", &["--flush-caches"]);
        run("nscd", &["-i", "hosts"]);
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
        fs::write(hosts_path(), want).map_err(|e| format!("Cannot edit the hosts file: {e}"))?;
        flush_dns();
    }
    Ok(())
}

fn restore_hosts() {
    let cur = read_hosts();
    if logic::has_block(&cur) {
        let _ = fs::write(hosts_path(), logic::strip_block(&cur));
        flush_dns();
    }
}

fn end_lock() {
    restore_hosts();
    let _g = guard();
    let _ = fs::remove_file(lock_path());
}

fn refresh(sys: &mut System) {
    sys.refresh_processes_specifics(ProcessesToUpdate::All, true, ProcessRefreshKind::nothing());
}

/// `seen`: apps killed on the previous tick. One open attempt = one app name appearing,
/// however many processes it spawns (Discord, Steam run several) and however many ticks it retries.
fn tick(sys: &mut System, seen: &mut HashSet<String>, checked: &mut Option<Instant>) {
    let Some(l) = advance(checked) else {
        restore_hosts(); // no lock: never leave sites blocked (also repairs a block left by a crash)
        seen.clear();
        return;
    };
    if now_ms() >= l.end_ms {
        end_lock();
        seen.clear();
        return;
    }
    let _ = apply_hosts(&l);
    refresh(sys);
    let (names, me) = (merged_apps(&l), std::process::id());
    let mut killed = HashSet::new();
    for (pid, p) in sys.processes() {
        if pid.as_u32() == me || pid.as_u32() == 1 {
            continue;
        }
        let n = p.name().to_string_lossy().to_lowercase();
        if names.contains(&n) && p.kill() {
            killed.insert(n);
        }
    }
    let new = killed.difference(seen).count() as u32;
    if new > 0 {
        bump(new);
    }
    *seen = killed;
}

// ---------- linked devices ----------

/// Checks the shared lock and starts or extends the lock here if it ends later than ours (like Link.kt).
fn poll_link() {
    let code = link_code();
    if code.is_empty() {
        return;
    }
    let Some(body) = curl(&[&format!("{API}?code={code}")]) else { return };
    let Ok(d) = serde_json::from_str::<serde_json::Value>(&body) else { return };
    let n = |k: &str| d[k].as_u64().unwrap_or(0);
    let now = now_ms();
    let ours = load().filter(|l| now < l.end_ms).map_or(0, |l| l.end_ms);
    if let Some(end) = logic::link_end(n("end"), n("now"), n("minutes"), now, ours, u64::from(MAX_MIN)) {
        adopt(end);
    }
}

/// Starts a lock ending at `end` with the built-in blocklist, or extends the running one (keeping its custom list).
fn adopt(end: u64) {
    let now = now_ms();
    let l = {
        let _g = guard();
        let l = match load_raw() {
            Some(l) if now < l.end_ms => Lock { end_ms: l.end_ms.max(end), ..l },
            _ => Lock { start_ms: now, end_ms: end, sites: vec![], apps: vec![], blocked: 0, seen_ms: now },
        };
        if write_raw(&l).is_err() {
            return;
        }
        l
    };
    let _ = apply_hosts(&l);
}

/// Tells the other linked devices about a lock started here. A 409 (a longer lock runs) is fine.
fn push_link(minutes: u32) {
    let code = link_code();
    if code.is_empty() {
        return;
    }
    let body = serde_json::json!({ "code": code, "minutes": minutes, "by": "pc" }).to_string();
    curl(&["-X", "POST", "-H", "Content-Type: application/json", "-d", &body, API]);
}

// ---------- requests from the window ----------

/// Every field is checked again here: this program is root, the inbox is writable by anyone.
fn handle(body: &str) -> Result<(), String> {
    let v: serde_json::Value = serde_json::from_str(body).map_err(|e| e.to_string())?;
    let list = |k: &str| -> Result<Vec<String>, String> {
        v[k].as_array()
            .map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect())
            .ok_or_else(|| format!("missing {k}"))
    };
    match v["cmd"].as_str() {
        Some("start") => {
            let minutes = v["minutes"].as_u64().unwrap_or(0) as u32;
            let (sites, apps) = (list("sites")?, list("apps")?);
            if !(1..=MAX_MIN).contains(&minutes) || sites.len() + apps.len() > MAX_CUSTOM || is_locked() {
                return Err("refused".into());
            }
            let sites = sites.iter().map(|s| logic::clean_site(s)).collect::<Result<Vec<_>, _>>()?;
            let apps = apps.iter().map(|s| logic::clean_app(s)).collect::<Result<Vec<_>, _>>()?;
            let now = now_ms();
            let l = Lock { start_ms: now, end_ms: now + u64::from(minutes) * 60_000, sites, apps, blocked: 0, seen_ms: now };
            write_raw(&l)?;
            if let Err(e) = apply_hosts(&l) {
                let _g = guard();
                let _ = fs::remove_file(lock_path()); // never keep a lock that cannot block
                return Err(e);
            }
            thread::spawn(move || push_link(minutes));
            Ok(())
        }
        Some("link") => {
            let c = logic::clean_code(v["code"].as_str().unwrap_or(""))?;
            if c.is_empty() {
                let _ = fs::remove_file(link_path());
            } else {
                write_public(&link_path(), &c)?;
                thread::spawn(poll_link);
            }
            Ok(())
        }
        _ => Err("unknown command".into()),
    }
}

fn process_inbox() {
    let Ok(rd) = fs::read_dir(inbox_path()) else { return };
    for e in rd.flatten().take(20) {
        let p = e.path();
        // Real small files only: never follow a link someone planted.
        let ok = fs::symlink_metadata(&p).map(|m| m.is_file() && m.len() < 8192).unwrap_or(false);
        let body = if ok { fs::read_to_string(&p).ok() } else { None };
        let _ = fs::remove_file(&p);
        if let Some(b) = body {
            let _ = handle(&b);
        }
    }
}

// ---------- daemon ----------

fn daemon() {
    let _ = fs::create_dir_all(inbox_path());
    // Sticky + writable by everyone: any user can drop a request, nobody can touch another's file.
    let _ = fs::set_permissions(dir(), fs::Permissions::from_mode(0o755));
    let _ = fs::set_permissions(inbox_path(), fs::Permissions::from_mode(0o1733));
    let _ = write_public(&dir().join("guard-version"), logic::GUARD_VERSION);
    let mut sys = System::new();
    let mut seen = HashSet::new();
    let mut checked = None;
    let mut last_poll = Instant::now() - Duration::from_secs(60);
    loop {
        process_inbox();
        tick(&mut sys, &mut seen, &mut checked);
        let _ = fs::write(alive_path(), now_ms().to_string());
        if last_poll.elapsed() >= Duration::from_secs(60) {
            last_poll = Instant::now();
            thread::spawn(poll_link); // own thread: a slow network must not pause the app killer
        }
        thread::sleep(Duration::from_secs(1));
    }
}

// ---------- install / uninstall ----------

fn install() -> Result<(), String> {
    fs::create_dir_all(inbox_path()).map_err(|e| format!("Cannot create {}: {e}", dir().display()))?;
    let _ = fs::set_permissions(dir(), fs::Permissions::from_mode(0o755));
    let _ = fs::set_permissions(inbox_path(), fs::Permissions::from_mode(0o1733));
    write_public(&dir().join("guard-version"), logic::GUARD_VERSION)?;
    #[cfg(target_os = "linux")]
    {
        let unit = format!(
            "[Unit]\nDescription=Maatram Hard Lock guard\nAfter=network.target\n\n[Service]\nExecStart={BIN} --daemon\nRestart=always\nRestartSec=1\n\n[Install]\nWantedBy=multi-user.target\n"
        );
        let ok = fs::write(UNIT, unit).is_ok()
            && run("systemctl", &["daemon-reload"])
            && run("systemctl", &["enable", "maatram-guard"])
            && run("systemctl", &["restart", "maatram-guard"]);
        if !ok {
            // No systemd: run it detached now. It will not come back after a reboot.
            Command::new("setsid").arg(BIN).arg("--daemon").spawn().map_err(|e| format!("Cannot start the guard: {e}"))?;
        }
    }
    #[cfg(target_os = "macos")]
    {
        let plist = format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\"><dict>\n<key>Label</key><string>in.co.maatram.guard</string>\n<key>ProgramArguments</key><array><string>{BIN}</string><string>--daemon</string></array>\n<key>RunAtLoad</key><true/>\n<key>KeepAlive</key><true/>\n</dict></plist>\n"
        );
        fs::write(PLIST, plist).map_err(|e| format!("Cannot write {PLIST}: {e}"))?;
        let _ = fs::set_permissions(PLIST, fs::Permissions::from_mode(0o644));
        run("launchctl", &["bootout", "system", PLIST]);
        if !run("launchctl", &["bootstrap", "system", PLIST]) && !run("launchctl", &["load", "-w", PLIST]) {
            return Err("launchctl could not start the guard".into());
        }
    }
    Ok(())
}

fn restore() {
    let _ = fs::remove_file(lock_path());
    restore_hosts();
}

fn uninstall() {
    #[cfg(target_os = "linux")]
    {
        run("systemctl", &["disable", "--now", "maatram-guard"]);
        let _ = fs::remove_file(UNIT);
        run("systemctl", &["daemon-reload"]);
        run("pkill", &["-f", "maatram-guard --daemon"]);
    }
    #[cfg(target_os = "macos")]
    {
        run("launchctl", &["bootout", "system", PLIST]);
        let _ = fs::remove_file(PLIST);
    }
    restore();
    let _ = fs::remove_file(alive_path());
    let _ = fs::remove_dir_all(dir());
    #[cfg(target_os = "linux")]
    let _ = fs::remove_dir_all("/usr/local/libexec/maatram");
    #[cfg(target_os = "macos")]
    let _ = fs::remove_file(BIN);
}

fn main() {
    let arg = env::args().nth(1).unwrap_or_default();
    match arg.as_str() {
        "--daemon" => daemon(),
        "--install" => match install() {
            Ok(()) => println!("Maatram guard installed."),
            Err(e) => {
                eprintln!("{e}");
                std::process::exit(1);
            }
        },
        "--uninstall" => {
            uninstall();
            println!("Maatram guard removed.");
        }
        "--restore" => {
            restore();
            println!("Lock ended and hosts file cleaned.");
        }
        "--version" => println!("{}", logic::GUARD_VERSION),
        _ => {
            eprintln!("Usage: maatram-guard --daemon | --install | --uninstall | --restore");
            std::process::exit(2);
        }
    }
}
