; Uninstalling during a lock: end it first (restore hosts file, stop app + watchdog, delete sign-in tasks).
!macro NSIS_HOOK_PREUNINSTALL
  nsExec::Exec '"$INSTDIR\maatram-hardlock.exe" --cleanup'
  Pop $0
!macroend
