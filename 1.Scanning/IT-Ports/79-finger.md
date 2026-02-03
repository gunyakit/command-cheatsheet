# Port 79 - Finger

## Table of Contents
- [Enumeration](#enumeration)
  - [Basic Connection](#basic-connection)
  - [Nmap Scripts](#nmap-scripts)
  - [User Enumeration](#user-enumeration)
- [Tools](#tools)

---

## Enumeration

### Quick Check (One-liner)

```shell
finger @$rhost && finger root@$rhost && finger admin@$rhost
```

### Basic Connection

```shell
# Basic finger query
finger @$rhost

# Query specific user
finger root@$rhost
finger admin@$rhost

# Using netcat
nc -nv $rhost 79
# then type username or press enter for all users
```

### Nmap Scripts

```shell
# Service detection
nmap -p 79 -sV $rhost

# Finger enumeration
nmap -p 79 --script "finger" $rhost
```

### User Enumeration

```shell
# Enumerate users using Metasploit wordlist
./finger-user-enum.pl -U /usr/share/metasploit-framework/data/wordlists/unix_users.txt -t $rhost

# Common users to try
finger root@$rhost
finger admin@$rhost
finger user@$rhost
finger test@$rhost
finger guest@$rhost
```

---

## Tools

### finger-user-enum

> Download: http://pentestmonkey.net/tools/user-enumeration/finger-user-enum

```shell
# Basic usage
./finger-user-enum.pl -U userlist.txt -t $rhost

# With timeout
./finger-user-enum.pl -U userlist.txt -t $rhost -T 5
```

### Metasploit

```shell
use auxiliary/scanner/finger/finger_users
set RHOSTS $rhost
set USERS_FILE /usr/share/metasploit-framework/data/wordlists/unix_users.txt
run
```

---

## Information Disclosed

Finger service may reveal:
- Username
- Real name
- Home directory
- Login shell
- Last login time
- Mail status
- Idle time
