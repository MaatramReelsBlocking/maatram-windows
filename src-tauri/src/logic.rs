//! std-only helpers (no Tauri) so they can be unit-tested anywhere:
//! `rustc --edition 2021 --test src/logic.rs -o /tmp/logic_test && /tmp/logic_test`

use std::collections::BTreeSet;

/// Bump when the guard's files or inbox format change; the window reinstalls the guard on a mismatch (Linux/macOS).
pub const GUARD_VERSION: &str = "1";

/// Line ending of the hosts file on this OS.
#[cfg(windows)]
pub const NL: &str = "\r\n";
#[cfg(not(windows))]
pub const NL: &str = "\n";

pub const BEGIN: &str = "# MAATRAM-BEGIN";
pub const END: &str = "# MAATRAM-END";

/// Base domains. Each also gets a `www.` twin in the hosts block.
pub const SITES: &[&str] = &[
    "instagram.com",
    "youtube.com",
    "youtu.be",
    "tiktok.com",
    "snapchat.com",
    "facebook.com",
    "fb.com",
    "messenger.com",
    "twitter.com",
    "x.com",
    "reddit.com",
    "whatsapp.com",
    "telegram.org",
    "t.me",
    "discord.com",
    "discordapp.com",
    "twitch.tv",
];

/// Hosts files have no wildcards, so common subdomains are listed.
pub const EXTRA_HOSTS: &[&str] = &[
    "m.youtube.com",
    "music.youtube.com",
    "m.facebook.com",
    "web.whatsapp.com",
    "web.snapchat.com",
    "web.telegram.org",
    "old.reddit.com",
    "mobile.twitter.com",
];

/// Process names (lowercase) killed while a lock runs.
#[cfg(windows)]
pub const APPS: &[&str] = &[
    "whatsapp.exe",
    "whatsapp.root.exe",
    "instagram.exe",
    "tiktok.exe",
    "discord.exe",
    "telegram.exe",
    "messenger.exe",
    "steam.exe",
    "steamwebhelper.exe",
    "epicgameslauncher.exe",
    "minecraftlauncher.exe",
    "robloxplayerbeta.exe",
    "valorant-win64-shipping.exe",
    "fortniteclient-win64-shipping.exe",
];

/// Linux names are the kernel's process name (15 characters at most, so "telegram-desktop" shows as "telegram-deskto").
#[cfg(target_os = "linux")]
pub const APPS: &[&str] = &[
    "discord",
    "vesktop",
    "webcord",
    "telegram-desktop",
    "telegram-deskto",
    "whatsapp-for-linux",
    "whatsapp-for-lin",
    "zapzap",
    "steam",
    "steamwebhelper",
    "heroic",
    "lutris",
    "minecraft-launcher",
    "prismlauncher",
];

#[cfg(target_os = "macos")]
pub const APPS: &[&str] = &[
    "discord",
    "whatsapp",
    "telegram",
    "messenger",
    "steam_osx",
    "steam helper",
    "epicgameslauncher",
    "robloxplayer",
];

/// A custom blocklist entry may never kill these (would break the OS or this app's own window).
#[cfg(windows)]
const PROTECTED: &[&str] = &[
    "explorer.exe",
    "svchost.exe",
    "csrss.exe",
    "winlogon.exe",
    "wininit.exe",
    "services.exe",
    "lsass.exe",
    "smss.exe",
    "dwm.exe",
    "system.exe",
    "registry.exe",
    "conhost.exe",
    "msedgewebview2.exe",
    "maatram-hardlock.exe",
];

#[cfg(unix)]
const PROTECTED: &[&str] = &[
    "systemd",
    "init",
    "launchd",
    "kernel_task",
    "sshd",
    "dbus-daemon",
    "dbus-broker",
    "xorg",
    "xwayland",
    "gnome-shell",
    "gnome-session",
    "plasmashell",
    "kwin_x11",
    "kwin_wayland",
    "sddm",
    "gdm",
    "lightdm",
    "finder",
    "loginwindow",
    "windowserver",
    "dock",
    "systemuiserver",
    "bash",
    "zsh",
    "sh",
    "sudo",
    "login",
    "maatram-hardlock",
    "maatram-guard",
    "webkitwebprocess",
    "webkitnetworkprocess",
    "webkitgpuprocess",
];

/// "https://www.Instagram.com/reels?x=1" -> "instagram.com". Rejects anything that is not a plain hostname.
pub fn clean_site(raw: &str) -> Result<String, String> {
    let mut s = raw.trim().to_lowercase();
    if let Some(i) = s.find("://") {
        s = s[i + 3..].to_string();
    }
    if let Some(i) = s.find(['/', '?', '#']) {
        s.truncate(i);
    }
    if let Some(i) = s.find(':') {
        s.truncate(i);
    }
    if let Some(rest) = s.strip_prefix("www.") {
        s = rest.to_string();
    }
    let ok = (3..=100).contains(&s.len())
        && s.contains('.')
        && !s.contains("..")
        && !s.starts_with(['.', '-'])
        && !s.ends_with(['.', '-'])
        && s.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '.' || c == '-');
    if ok {
        Ok(s)
    } else {
        Err(format!("Not a valid site: {}", raw.trim()))
    }
}

/// "WhatsApp" or "C:\\x\\Foo.EXE" -> "whatsapp.exe" / "foo.exe". Refuses protected system processes.
#[cfg(windows)]
pub fn clean_app(raw: &str) -> Result<String, String> {
    let t = raw.trim().to_lowercase();
    let base = t.rsplit(['\\', '/']).next().unwrap_or("");
    let mut n = base.to_string();
    if !n.ends_with(".exe") {
        n.push_str(".exe");
    }
    let ok = (5..=64).contains(&n.len())
        && !n.starts_with('.')
        && n.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '_' | '-' | ' '));
    if !ok {
        return Err(format!("Not a valid app name: {}", raw.trim()));
    }
    if PROTECTED.contains(&n.as_str()) {
        return Err(format!("{n} is protected and cannot be blocked"));
    }
    Ok(n)
}

/// "Discord" or "/usr/bin/Discord" -> "discord". Names are the process name, no extension. Refuses protected processes.
#[cfg(unix)]
pub fn clean_app(raw: &str) -> Result<String, String> {
    let t = raw.trim().to_lowercase();
    let n = t.rsplit('/').next().unwrap_or("").to_string();
    let ok = (2..=64).contains(&n.len())
        && !n.starts_with(['.', '-'])
        && n.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '_' | '-' | ' ' | '+'));
    if !ok {
        return Err(format!("Not a valid app name: {}", raw.trim()));
    }
    if PROTECTED.contains(&n.as_str()) {
        return Err(format!("{n} is protected and cannot be blocked"));
    }
    Ok(n)
}

/// The full marked block: built-in sites + custom sites, each with www twin, IPv4 and IPv6.
pub fn hosts_block(custom: &[String]) -> String {
    let mut set = BTreeSet::new();
    for s in SITES.iter().copied().chain(custom.iter().map(String::as_str)) {
        set.insert(s.to_string());
        set.insert(format!("www.{s}"));
    }
    for h in EXTRA_HOSTS {
        set.insert((*h).to_string());
    }
    let mut out = format!("{BEGIN}{NL}");
    for h in set {
        out.push_str(&format!("0.0.0.0 {h}{NL}::1 {h}{NL}"));
    }
    out.push_str(END);
    out.push_str(NL);
    out
}

pub fn has_block(hosts: &str) -> bool {
    hosts.lines().any(|l| l.trim() == BEGIN)
}

/// Remove our block (BEGIN..END). A stray BEGIN with no END drops only that one line, never user entries.
pub fn strip_block(hosts: &str) -> String {
    let mut lines: Vec<&str> = hosts.lines().map(str::trim_end).collect();
    while let Some(b) = lines.iter().position(|l| l.trim() == BEGIN) {
        match lines[b + 1..].iter().position(|l| l.trim() == END) {
            Some(off) => {
                lines.drain(b..=b + 1 + off);
            }
            None => {
                lines.remove(b);
            }
        }
    }
    let joined = lines.join(NL);
    let t = joined.trim_end();
    if t.is_empty() {
        String::new()
    } else {
        format!("{t}{NL}")
    }
}

/// Idempotent: with_block(with_block(x, b), b) == with_block(x, b).
pub fn with_block(hosts: &str, block: &str) -> String {
    format!("{}{}", strip_block(hosts), block)
}

pub fn remaining_secs(end_ms: u64, now_ms: u64) -> u64 {
    end_ms.saturating_sub(now_ms).div_ceil(1000)
}

/// Keeps the time left steady across a wall-clock jump. `seen_ms`: wall time at the last check (0 = none);
/// `expected_ms`: real time since then on a steady clock (0 when this process hasn't checked before, so a gap
/// while the app was not running counts as paused). A drift over 3 s moves the end by the same amount.
pub fn shift_end(end_ms: u64, seen_ms: u64, now_ms: u64, expected_ms: u64) -> u64 {
    if seen_ms == 0 {
        return end_ms;
    }
    let drift = now_ms as i128 - seen_ms as i128 - expected_ms as i128;
    if drift.abs() > 3_000 {
        (end_ms as i128 + drift).max(0) as u64
    } else {
        end_ms
    }
}

/// "abcd-2345" -> "ABCD2345". Blank is Ok("") (unlink). Same alphabet as maatram.co.in/api/link: no I, O, 0, 1.
pub fn clean_code(raw: &str) -> Result<String, String> {
    let c = raw.chars().filter(char::is_ascii_alphanumeric).collect::<String>().to_ascii_uppercase();
    let ok = c.is_empty() || (c.len() == 8 && c.chars().all(|ch| matches!(ch, 'A'..='H' | 'J'..='N' | 'P'..='Z' | '2'..='9')));
    if ok {
        Ok(c)
    } else {
        Err("A link code is 8 letters and digits, like ABCD-2345".into())
    }
}

/// End time on this PC's clock for the shared lock, or None if it should not lock or extend here.
/// Same rules as the phone app (Link.kt): use the server's remaining time so clock skew does not matter,
/// ignore a lock about to end, and only extend by more than 5 s. Capped at `max_min` (the server's cap too).
pub fn link_end(server_end: u64, server_now: u64, minutes: u64, local_now: u64, local_end: u64, max_min: u64) -> Option<u64> {
    let left = server_end.saturating_sub(server_now).min(max_min * 60_000);
    let end = local_now + left;
    (minutes > 0 && left > 3_000 && end > local_end + 5_000).then_some(end)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn site_cleaning() {
        assert_eq!(clean_site("https://www.Instagram.com/reels?x=1").unwrap(), "instagram.com");
        assert_eq!(clean_site("old.reddit.com:443/r/x").unwrap(), "old.reddit.com");
        assert!(clean_site("evil.com\n0.0.0.0 google.com").is_err());
        assert!(clean_site("a b.com").is_err());
        assert!(clean_site("localhost").is_err());
        assert!(clean_site("-bad.com").is_err());
        assert!(clean_site("a..com").is_err());
        assert!(clean_site("").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn app_cleaning_unix() {
        assert_eq!(clean_app("Discord").unwrap(), "discord");
        assert_eq!(clean_app("/usr/bin/Steam").unwrap(), "steam");
        assert_eq!(clean_app("Steam Helper").unwrap(), "steam helper");
        assert!(clean_app("systemd").is_err());
        assert!(clean_app("Finder").is_err());
        assert!(clean_app("maatram-guard").is_err());
        assert!(clean_app("bad;name").is_err());
        assert!(clean_app("-x").is_err());
        assert!(clean_app("").is_err());
        assert!(clean_app("a").is_err());
    }

    #[cfg(windows)]
    #[test]
    fn app_cleaning() {
        assert_eq!(clean_app("WhatsApp").unwrap(), "whatsapp.exe");
        assert_eq!(clean_app("C:\\Program Files\\X\\Foo.EXE").unwrap(), "foo.exe");
        assert!(clean_app("explorer").is_err());
        assert!(clean_app("Explorer.exe").is_err());
        assert!(clean_app("msedgewebview2.exe").is_err());
        assert!(clean_app("bad;name").is_err());
        assert!(clean_app("").is_err());
    }

    #[test]
    fn block_has_builtins_custom_and_www() {
        let b = hosts_block(&["example.org".to_string()]);
        for want in ["0.0.0.0 instagram.com", "0.0.0.0 www.instagram.com", "::1 web.whatsapp.com", "0.0.0.0 example.org", "0.0.0.0 www.example.org"] {
            assert!(b.contains(want), "missing {want}");
        }
        assert!(b.starts_with(BEGIN) && b.trim_end().ends_with(END));
    }

    #[test]
    fn with_block_is_idempotent_and_keeps_user_lines() {
        let orig = "127.0.0.1 localhost\n10.0.0.5 nas.home\n";
        let b = hosts_block(&[]);
        let once = with_block(orig, &b);
        let twice = with_block(&once, &b);
        assert_eq!(once, twice);
        assert!(once.contains("10.0.0.5 nas.home") && has_block(&once));
        let back = strip_block(&once);
        assert!(!has_block(&back));
        assert!(back.contains("127.0.0.1 localhost") && back.contains("10.0.0.5 nas.home"));
        assert!(!back.contains("instagram"));
    }

    #[test]
    fn strip_without_end_only_drops_marker() {
        let h = format!("1.1.1.1 a\r\n{BEGIN}\r\n2.2.2.2 keepme\r\n");
        let s = strip_block(&h);
        assert!(s.contains("1.1.1.1 a") && s.contains("2.2.2.2 keepme") && !has_block(&s));
    }

    #[test]
    fn strip_handles_lf_and_empty() {
        assert_eq!(strip_block(""), "");
        let h = format!("a\n{BEGIN}\nx\n{END}\nb\n");
        assert_eq!(strip_block(&h), format!("a{NL}b{NL}"));
    }

    #[test]
    fn remaining() {
        assert_eq!(remaining_secs(10_000, 0), 10);
        assert_eq!(remaining_secs(10_001, 0), 11);
        assert_eq!(remaining_secs(5, 10), 0);
    }

    #[test]
    fn clock_jumps_do_not_change_time_left() {
        const T: u64 = 1_700_000_000_000;
        let end = T + 600_000; // 10 min left at wall T
        // Normal second: nothing moves.
        assert_eq!(shift_end(end, T, T + 1_000, 1_000), end);
        // Clock set 2 h forward during that second: end moves too, still 10 min left.
        let moved = shift_end(end, T, T + 7_200_000 + 1_000, 1_000);
        assert_eq!(remaining_secs(moved, T + 7_200_000 + 1_000), 599);
        // Clock set back: the lock is not stretched.
        let back = shift_end(end, T, T - 3_600_000 + 1_000, 1_000);
        assert_eq!(remaining_secs(back, T - 3_600_000 + 1_000), 599);
        // App was not running (restart, killed): the gap counts as paused.
        assert_eq!(shift_end(end, T, T + 60_000, 0), end + 60_000);
        // No previous check: unchanged.
        assert_eq!(shift_end(end, 0, 9_999_999, 0), end);
    }

    #[test]
    fn code_cleaning() {
        assert_eq!(clean_code(" abcd-2345 ").unwrap(), "ABCD2345");
        assert_eq!(clean_code("").unwrap(), "");
        assert!(clean_code("ABCD234").is_err());
        assert!(clean_code("ABCD2341").is_err()); // 1 is not in the alphabet
        assert!(clean_code("IOCD2345").is_err());
    }

    #[test]
    fn link_end_rules() {
        // Server says 10 min left; this PC's clock is way off: still 10 min from local now.
        assert_eq!(link_end(1_600_000, 1_000_000, 10, 5, 0, 90), Some(600_005));
        assert_eq!(link_end(1_002_000, 1_000_000, 10, 0, 0, 90), None); // about to end
        assert_eq!(link_end(0, 1_000_000, 0, 0, 0, 90), None); // no lock
        assert_eq!(link_end(1_600_000, 1_000_000, 0, 0, 0, 90), None);
        assert_eq!(link_end(1_600_000, 1_000_000, 10, 0, 598_000, 90), None); // ours already as long
        assert_eq!(link_end(1_600_000, 1_000_000, 10, 0, 500_000, 90), Some(600_000)); // extend
        assert_eq!(link_end(u64::MAX, 0, 10, 0, 0, 90), Some(90 * 60_000)); // capped
    }
}
