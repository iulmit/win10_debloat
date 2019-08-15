@echo.
@echo [92m:: Updating Microsoft Windows...[0m
explorer ms-settings:windowsupdate-action

@echo.
@echo [92m:: Removing Windows Store Apps...[0m
powershell.exe -ExecutionPolicy Bypass "%~dp0tools\disable_store_apps.ps1"

@echo.
@echo [92m:: Scheduling Stage_2 for the next logon...[0m
schtasks /CREATE /TN "Stage_2" /TR "%~dp0Stage_2.bat" /SC ONLOGON /RL HIGHEST /F

:: Pause
@echo.
@echo off
echo [92m:: FINISH THE UPDATES, then press enter to reboot the system...[0m
set /p input=

:: Reboot
shutdown /r /f /t 0