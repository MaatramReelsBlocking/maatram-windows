//! std-only helpers (no Tauri) so they can be unit-tested anywhere:
//! `rustc --edition 2021 --test src/logic.rs -o /tmp/logic_test && /tmp/logic_test`

use std::collections::BTreeSet;

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

/// A custom blocklist entry may never kill these (would break Windows or this app's own window).
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

/// "https://www.Instagram.com/reels?x=1" -> "instagram.com". Rejects anything that is not a plain hostname.
pub fn clean_site(raw: &str) -> Result<String, String> {
    let mut s = raw.trim().to_lowercase();
    if let Some(i) = s.find("://") {
        s = s[i + 3..].to_string();
    }
    if let Some(i) = s.find(|c| c == '/' || c == '?' || c == '#') {
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
    let mut out = format!("{BEGIN}\r\n");
    for h in set {
        out.push_str(&format!("0.0.0.0 {h}\r\n::1 {h}\r\n"));
    }
    out.push_str(END);
    out.push_str("\r\n");
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
    let joined = lines.join("\r\n");
    let t = joined.trim_end();
    if t.is_empty() {
        String::new()
    } else {
        format!("{t}\r\n")
    }
}

/// Idempotent: with_block(with_block(x, b), b) == with_block(x, b).
pub fn with_block(hosts: &str, block: &str) -> String {
    format!("{}{}", strip_block(hosts), block)
}

pub fn remaining_secs(end_ms: u64, now_ms: u64) -> u64 {
    end_ms.saturating_sub(now_ms).div_ceil(1000)
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
        assert_eq!(strip_block(&h), "a\r\nb\r\n");
    }

    #[test]
    fn remaining() {
        assert_eq!(remaining_secs(10_000, 0), 10);
        assert_eq!(remaining_secs(10_001, 0), 11);
        assert_eq!(remaining_secs(5, 10), 0);
    }
}
