# Linux desktop build

Maatram Hard Lock is being ported to Linux. The Linux backend is separate from the existing Windows backend; the HTML interface is shared.

## Build locally

On Ubuntu 24.04 or a compatible Debian-based desktop, install the Tauri prerequisites:

```sh
sudo apt update
sudo apt install build-essential curl wget file libssl-dev libwebkit2gtk-4.1-dev libayatana-appindicator3-dev librsvg2-dev patchelf
```

Then build the packages from the repository root:

```sh
python3 -m pip install --user pillow
python3 tools/make_icons.py
npx --yes @tauri-apps/cli@2 build --bundles deb,appimage
```

GitHub Actions builds the `.deb` and AppImage packages for pull requests and uploads them to GitHub Releases for version tags.

## Permissions and behavior

- The app itself runs as the logged-in user, not as root.
- Site blocking updates only Maatram's marked section in `/etc/hosts`. The app asks for authorization through `pkexec`; a working polkit authentication agent is required.
- App blocking matches Linux process names. The available built-in names are common examples, not universal package identifiers. Different distributions and Flatpak/Snap packages may use different process names.
- AppImage may require FUSE 2 compatibility on some distributions.
- Test the build on your target desktop environment before depending on a lock.

## Recovery

If you need to remove Maatram's site block manually, run the recovery script from this repository:

```sh
bash Maatram-Linux-Restore.sh
```

It asks for sudo authorization to restore `/etc/hosts` and preserves entries outside Maatram's markers. Do not delete the markers or edit the block while a lock is active.
