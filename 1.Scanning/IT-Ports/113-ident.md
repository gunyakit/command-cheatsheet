# Port 113 - Ident

## Table of Contents

- [Enumeration](#enumeration)
- [Exploitation](#exploitation)

---

## Enumeration

### Nmap

```shell
nmap -sV -sC -p 113 $rhost
nmap -p 113 --script auth-owners $rhost
```

### Manual Query

```shell
# Query ident for connection owner
# Format: <remote_port>, <local_port>

# Example: who owns connection from port 22
echo "22, 12345" | nc -nv $rhost 113

# Check SSH connection owner
nc -nv $rhost 113
22, 22

# Check HTTP connection owner  
nc -nv $rhost 113
80, 80
```

---

## Exploitation

### Username Enumeration

```shell
# Script to enumerate users via common ports
for port in 22 25 80 443 21 23; do
  echo "$port, $port" | nc -w 2 $rhost 113 2>/dev/null
done
```

### Nmap Auth-Owners Script

```shell
# Enumerate service owners
nmap -sV --script auth-owners -p 22,25,80,443 $rhost

# This will show which user owns each service
```

### Python Ident Client

```python
#!/usr/bin/env python3
import socket
import sys

def query_ident(host, remote_port, local_port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((host, 113))
        s.send(f"{remote_port}, {local_port}\r\n".encode())
        response = s.recv(1024).decode().strip()
        s.close()
        return response
    except:
        return None

if __name__ == "__main__":
    host = sys.argv[1]
    
    # Common ports to check
    ports = [21, 22, 23, 25, 80, 110, 143, 443, 993, 995]
    
    for port in ports:
        result = query_ident(host, port, port)
        if result:
            print(f"Port {port}: {result}")
```

---

## Information Gathered

The ident service reveals:

- Username running the service
- Process information
- Can help identify:
  - Services running as root
  - Custom service accounts
  - Potential privilege escalation targets

---

## Quick Reference

| Command | Description |
| :--- | :--- |
| `echo "22, 22" \| nc $rhost 113` | Query SSH service owner |
| `nmap -p 113 --script auth-owners $rhost` | Enumerate owners |
| `nmap --script auth-owners -p 22,80 $rhost` | Check specific ports |
