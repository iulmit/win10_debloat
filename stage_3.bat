@echo.
@echo [92m:: Disabling Cortana...[0m
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v AllowCortana /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"  /v "{2765E0F4-2918-4A46-B9C9-43CDD8FCBA2B}" /t REG_SZ /d  "BlockCortana|Action=Block|Active=TRUE|Dir=Out|App=C:\windows\systemapps\microsoft.windows.cortana_cw5n1h2txyewy\searchui.exe|Name=Search  and Cortana  application|AppPkgId=S-1-15-2-1861897761-1695161497-2927542615-642690995-327840285-2659745135-2630312742|" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v BingSearchEnabled /t REG_DWORD /d 0 /f

@echo.
@echo [92m:: Deleting scheduled task for Stage_3 and scheduling Stage_4 for the next logon...[0m
schtasks /DELETE /TN "Stage_3" /F
schtasks /CREATE /TN "Stage_4" /TR "%~dp0Stage_4.bat" /SC ONLOGON /RL HIGHEST /F

:: Pause
@echo.
@echo off
echo [92m:: Press enter to reboot the system...[0m
set /p input=

:: Reboot
shutdown /r /f /t 0