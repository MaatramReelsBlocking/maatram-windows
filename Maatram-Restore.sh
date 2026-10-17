#!/bin/sh
# Maatram emergency cleanup for Linux and macOS.
#   sudo sh Maatram-Restore.sh            end any lock and clean the hosts file
#   sudo sh Maatram-Restore.sh --remove   also remove the Maatram guard completely
[ "$(id -u)" = 0 ] || { echo "Run this with sudo."; exit 1; }
G=/usr/local/libexec/maatram/maatram-guard
[ -x "$G" ] || G=/Library/PrivilegedHelperTools/in.co.maatram.guard
if [ -x "$G" ]; then
  if [ "$1" = "--remove" ]; then "$G" --uninstall; else "$G" --restore; fi
fi
# Works even if the guard is already gone.
sed -i.bak '/# MAATRAM-BEGIN/,/# MAATRAM-END/d' /etc/hosts && rm -f /etc/hosts.bak
echo "Done. Sites are unblocked."
