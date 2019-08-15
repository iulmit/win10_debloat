@echo.
@echo [92m:: Installing wim_tweak...[0m
copy "%~dp0tools\install_wim_tweak.exe" C:\Windows\System32

@echo.
@echo [92m:: Removing Windows Defender...[0m
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v SmartScreenEnabled /t REG_SZ /d "Off" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\AppHost" /v "EnableWebContentEvaluation" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\PhishingFilter" /v "EnabledV9" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v SpyNetReporting /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v SubmitSamplesConsent /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v DontReportInfectionInformation /t REG_DWORD /d 1 /f
reg delete "HKLM\SYSTEM\CurrentControlSet\Services\Sense" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\MRT" /v "DontReportInfectionInformation" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\MRT" /v "DontOfferThroughWUAU" /t REG_DWORD /d 1 /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "SecurityHealth" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" /v "SecurityHealth" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\SecHealthUI.exe" /v Debugger /t REG_SZ /d "%windir%\System32\taskkill.exe" /f
install_wim_tweak /o /c Windows-Defender /r
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.SecurityAndMaintenance" /v "Enabled" /t REG_DWORD /d 0 /f
reg delete "HKLM\SYSTEM\CurrentControlSet\Services\SecurityHealthService" /f

@echo.
@echo [92m:: Removing Windows Store...[0m
powershell.exe -Command "Get-AppxPackage -AllUsers *store* | Remove-AppxPackage"
install_wim_tweak /o /c Microsoft-Windows-ContentDeliveryManager /r
install_wim_tweak /o /c Microsoft-Windows-Store /r
reg add "HKLM\Software\Policies\Microsoft\WindowsStore" /v RemoveWindowsStore /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\WindowsStore" /v DisableStoreApps /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\AppHost" /v "EnableWebContentEvaluation" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\PushToInstall" /v DisablePushToInstall /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SilentInstalledAppsEnabled /t REG_DWORD /d 0 /f
sc delete PushToInstall

@echo.
@echo [92m:: Removing Music and TV...[0m
powershell.exe -Command "Get-AppxPackage -AllUsers *zune* | Remove-AppxPackage"
powershell.exe -Command "Get-WindowsPackage -Online | Where PackageName -like *MediaPlayer* | Remove-WindowsPackage -Online -NoRestart"

@echo.
@echo [92m:: Removing Xbox and Game DVR...[0m
powershell.exe -Command "Get-AppxPackage -AllUsers *xbox* | Remove-AppxPackage"
sc delete XblAuthManager
sc delete XblGameSave
sc delete XboxNetApiSvc
sc delete XboxGipSvc
reg delete "HKLM\SYSTEM\CurrentControlSet\Services\xbgm" /f
schtasks /Change /TN "Microsoft\XblGameSave\XblGameSaveTask" /disable
schtasks /Change /TN "Microsoft\XblGameSave\XblGameSaveTaskLogon" /disable
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\GameDVR" /v AllowGameDVR /t REG_DWORD /d 0 /f

@echo.
@echo [92m:: Removing Sticky Notes...[0m
powershell.exe -Command "Get-AppxPackage -AllUsers *sticky* | Remove-AppxPackage"

@echo.
@echo [92m:: Removing Maps...[0m
powershell.exe -Command "Get-AppxPackage -AllUsers *maps* | Remove-AppxPackage"
sc delete MapsBroker
sc delete lfsvc
schtasks /Change /TN "\Microsoft\Windows\Maps\MapsUpdateTask" /disable
schtasks /Change /TN "\Microsoft\Windows\Maps\MapsToastTask" /disable

@echo.
@echo [92m:: Removing Alarms and Clock...[0m
powershell.exe -Command "Get-AppxPackage -AllUsers *alarms* | Remove-AppxPackage"
powershell.exe -Command "Get-AppxPackage -AllUsers *people* | Remove-AppxPackage"

@echo.
@echo [92m:: Removing Mail and Calendar...[0m
powershell.exe -Command "Get-AppxPackage -AllUsers *comm* | Remove-AppxPackage"
powershell.exe -Command "Get-AppxPackage -AllUsers *mess* | Remove-AppxPackage"

@echo.
@echo [92m:: Removing OneNote...[0m
powershell.exe -Command "Get-AppxPackage -AllUsers *onenote* | Remove-AppxPackage"

@echo.
@echo [92m:: Removing Photos...[0m
powershell.exe -Command "Get-AppxPackage -AllUsers *photo* | Remove-AppxPackage"

@echo.
@echo [92m:: Removing Camera...[0m
powershell.exe -Command "Get-AppxPackage -AllUsers *camera* | Remove-AppxPackage"

@echo.
@echo [92m:: Removing Weather and News...[0m
powershell.exe -Command "Get-AppxPackage -AllUsers *bing* | Remove-AppxPackage"

@echo.
@echo [92m:: Removing Calculator...[0m
powershell.exe -Command "Get-AppxPackage -AllUsers *calc* | Remove-AppxPackage"

@echo.
@echo [92m:: Removing Sound Recorder...[0m
powershell.exe -Command "Get-AppxPackage -AllUsers *soundrec* | Remove-AppxPackage"

@echo.
@echo [92m:: Removing Microsoft Edge...[0m
taskkill /F /IM browser_broker.exe
taskkill /F /IM RuntimeBroker.exe
taskkill /F /IM MicrosoftEdge.exe
taskkill /F /IM MicrosoftEdgeCP.exe
taskkill /F /IM MicrosoftEdgeSH.exe
mv C:\Windows\SystemApps\Microsoft.MicrosoftEdge_8wekyb3d8bbwe C:\Windows\SystemApps\Microsoft.MicrosoftEdge_8wekyb3d8bbwe_BAK
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\MicrosoftEdge.exe" /v Debugger /t REG_SZ /d "%windir%\System32\taskkill.exe" /f
powershell.exe -Command "Get-WindowsPackage -Online | Where PackageName -like *InternetExplorer* | Remove-WindowsPackage -Online -NoRestart"

@echo.
@echo [92m:: Removing Concact, Support and Get Help...[0m
install_wim_tweak /o /c Microsoft-Windows-ContactSupport /r
powershell.exe -Command "Get-AppxPackage -AllUsers *GetHelp* | Remove-AppxPackage"

@echo.
@echo [92m:: Removing Microsoft Quick Assist...[0m
powershell.exe -Command "Get-WindowsPackage -Online | Where PackageName -like *QuickAssist* | Remove-WindowsPackage -Online -NoRestart"

@echo.
@echo [92m:: Removing Connect...[0m
install_wim_tweak /o /c Microsoft-PPIProjection-Package /r

@echo.
@echo [92m:: Removing Your Phone...[0m
powershell.exe -Command "Get-AppxPackage -AllUsers *phone* | Remove-AppxPackage"

@echo.
@echo [92m:: Removing Hello Face...[0m
powershell.exe -Command "Get-WindowsPackage -Online | Where PackageName -like *Hello-Face* | Remove-WindowsPackage -Online -NoRestart"
schtasks /Change /TN "\Microsoft\Windows\HelloFace\FODCleanupTask" /Disable

@echo.
@echo [92m:: Removing Edit with 3D Paint / 3D Print...[0m
for /f "tokens=1* delims=" %%I in ('reg query "HKEY_CLASSES_ROOT\SystemFileAssociations" /s /k /f "3D Edit" ^| find /i "3D Edit"') do (reg delete "%%I" /f )
for /f "tokens=1* delims=" %%I in ('reg query "HKEY_CLASSES_ROOT\SystemFileAssociations" /s /k /f "3D Print" ^| find /i "3D Print"') do (reg delete "%%I" /f )

@echo.
@echo [92m:: Disabling System Restore...[0m
powershell.exe -Command "Disable-ComputerRestore -Drive 'C:\'"
vssadmin delete shadows /all /Quiet
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\SystemRestore" /v "DisableConfig" /t "REG_DWORD" /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\SystemRestore" /v "DisableSR " /t "REG_DWORD" /d "1" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" /v "DisableConfig" /t "REG_DWORD" /d "1" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" /v "DisableSR " /t "REG_DWORD" /d "1" /f
schtasks /Change /TN "\Microsoft\Windows\SystemRestore\SR" /disable

@echo.
@echo [92m:: Deleting scheduled task for Stage_2 and scheduling Stage_3 for the next logon...[0m
schtasks /DELETE /TN "Stage_2" /F
schtasks /CREATE /TN "Stage_3" /TR "%~dp0Stage_3.bat" /SC ONLOGON /RL HIGHEST /F

:: Pause
@echo.
@echo off
echo [92m:: Press enter to reboot the system...[0m
set /p input=

:: Reboot
shutdown /r /f /t 0