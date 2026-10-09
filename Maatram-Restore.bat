@echo off
rem Emergency cleanup for Maatram Hard Lock. Right-click -> Run as administrator.
net session >nul 2>&1
if errorlevel 1 (
  echo Right-click this file and choose "Run as administrator".
  pause
  exit /b 1
)
echo Ending the lock...
del /f /q "%ProgramData%\Maatram\lock.json" >nul 2>&1
rem give the watchdog a few seconds to notice there is no lock and stop
ping -n 5 127.0.0.1 >nul
taskkill /f /im maatram-hardlock.exe /t >nul 2>&1
schtasks /delete /tn MaatramHardLock /f >nul 2>&1
schtasks /delete /tn MaatramWatchdog /f >nul 2>&1
powershell -NoProfile -Command "$p=$env:SystemRoot+'\System32\drivers\etc\hosts'; $o=@(); $in=$false; foreach($x in (Get-Content $p)){ if($x.Trim() -eq '# MAATRAM-BEGIN'){$in=$true;continue}; if($in){ if($x.Trim() -eq '# MAATRAM-END'){$in=$false}; continue }; $o+=$x }; Set-Content -Path $p -Value $o"
ipconfig /flushdns >nul
echo Done. Sites and apps are unblocked.
pause
