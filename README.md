# Maatram Hard Lock for Windows

Hard Lock only. Pick a duration, start the lock, and for that time:

- **Apps are closed** the moment they open: WhatsApp, Instagram, TikTok, Discord, Telegram, Messenger, Steam, Epic, and a few games. You can add your own `.exe` names before starting.
- **Sites are blocked** system-wide through the Windows hosts file: Instagram, YouTube, TikTok, Snapchat, Facebook, X/Twitter, Reddit, WhatsApp Web, Telegram, Discord, Twitch. You can add your own sites before starting.
- **The lock survives**: closing the window hides it to the tray, a second watchdog process restarts the app if it is ended, and a sign-in task brings both back after a reboot.
- **It ends by itself** at the timer: sites and apps are unblocked automatically. Maximum lock is 90 minutes.
- **Linked devices**: enter the link code from maatram.co.in under **Link devices**. A Hard Lock started on your phone (Maatram Hard Lock app), the website or the Chrome extension then locks this PC too, checked about once a minute, and a lock started here is sent to them. While linked, Maatram starts with Windows and closing the window hides it to the tray (use **Quit** in the tray menu when no lock runs). A shared lock can only be extended, never shortened.

Backend is pure Rust (Tauri 2). The window is one plain HTML file in `ui/`.

## Get the .exe from GitHub

1. Create a new GitHub repo named `maatram-windows` and push this folder to it.
2. Make the build:
   - Tag a release: `git tag v0.1.0 && git push --tags`. The `.exe` appears under **Releases**.
   - Or without a tag: **Actions → Build Windows exe → Run workflow**, then download the `maatram-hardlock-windows` artifact.
3. The first build takes about 8 to 12 minutes. Later builds are faster.

## Install and test

Windows will show "Unknown publisher" (the file is not code-signed). Click **More info → Run anyway**. The app always asks for administrator rights, which it needs to edit the hosts file and close apps.

Run this checklist:

1. Open the app, pick **5 min**, press **Start Hard Lock**.
2. Open instagram.com in Edge or Chrome. It should fail to load. (A tab that was already open before the lock can keep working for a minute on its old connection; close the browser and reopen it.)
3. Open WhatsApp or Discord if installed. It should close within about 2 seconds, and **Blocked attempts** goes up.
4. Close the window with the X. It should go to the tray, not quit. Open it again from the tray icon, or by launching Maatram from the Start menu (it brings the running window back instead of opening a second copy).
5. Open Task Manager and end `maatram-hardlock.exe`. The watchdog should bring it back within about 10 seconds.
6. Restart Windows mid-lock. After you sign in, the lock should still be running.
7. Wait for the timer to end. Sites and apps should work again, and `C:\Windows\System32\drivers\etc\hosts` should have no `MAATRAM` lines.

## If something goes wrong

Right-click **Maatram-Restore.bat** → **Run as administrator**. It removes the lock, stops the app and watchdog, deletes the sign-in tasks, and cleans the hosts file.

Uninstalling Maatram (Settings → Apps) also ends any running lock and cleans the hosts file, so sites are never left blocked.

## Known limits (v0.1)

- Browsers using their own DNS-over-HTTPS (Firefox by default) can ignore the hosts file. The Chrome extension covers Chrome.
- A user with admin rights can still defeat the lock by killing both processes at the same moment. The watchdog only slows this down.
- The countdown ignores changes to the system clock. Time the PC is off, or Maatram is not running, does not count.
- Antivirus may flag an unsigned app that edits the hosts file and closes processes.

## Layout

```
ui/index.html            the window (HTML + CSS + JS, no libraries)
src-tauri/src/main.rs    lock state, watchdog, app killer, hosts blocker, tray
src-tauri/src/logic.rs   blocklists + hosts-file text logic, unit-tested
src-tauri/app.manifest   asks Windows for administrator rights
.github/workflows/       builds the installer on windows-latest
src-tauri/windows/hooks.nsh  uninstaller hook that ends a running lock
Maatram-Restore.bat      emergency cleanup
```

Run the logic tests anywhere:

```
cd src-tauri
rustc --edition 2021 --test src/logic.rs -o /tmp/logic_test && /tmp/logic_test
```
