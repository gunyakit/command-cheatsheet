# Port Scanning

## Table of Contents

- [Quick Reference](#quick-reference)
- [Host Discovery](#host-discovery)
- [Nmap](#nmap)
  - [Basic Scans](#basic-scan-one-liner)
  - [UDP Scan](#udp-scan-one-liner)
  - [Stealth Scanning](#stealth-scanning)
  - [Vulnerability Scan](#vulnerability-scan-one-liner)
  - [Firewall Evasion](#firewall-evasion-one-liner)
- [Masscan](#masscan-one-liner)
- [Rustscan](#rustscan-one-liner)
- [NetExec](#netexec-one-liner)
- [Tips](#tips)
  - [Speed Optimization](#speed-optimization)
  - [Common Options](#common-options)
  - [Timing Templates](#timing-templates-explained)
- [Output Parsing](#output-parsing)
- [Common Port Lists](#common-port-lists)
- [IPv6 Scanning](#ipv6-scanning)
- [Firewall/IDS Evasion](#firewallids-evasion)
- [Troubleshooting](#troubleshooting)

---

## Quick Reference

> **เลือก command ตามสถานการณ์**

| สถานการณ์ | Command |
|-----------|---------|
| 🚀 **Quick scan** | `nmap -sC -sV -Pn $rhost` |
| 🔍 **Full port** | `nmap -p- --min-rate 10000 $rhost` |
| 📡 **UDP top 100** | `sudo nmap -sU --top-ports 100 $rhost` |
| 🕵️ **Stealth** | `sudo nmap -sS -T2 -f $rhost` |
| 💥 **Vuln scan** | `nmap --script vuln $rhost` |
| 🌐 **Network sweep** | `nmap -sn $cidr` |
| ⚡ **Fastest** | `rustscan -a $rhost -- -sC -sV` |
| 🔥 **Mass scan** | `sudo masscan -p1-65535 $rhost --rate=10000` |
| 🖥️ **Windows hosts** | `nxc smb $cidr` |

### OSCP Quick Workflow

```shell
# Step 1: Quick scan while full scan runs in background
nmap -sC -sV -Pn $rhost -oN quick.nmap &
nmap -p- --min-rate 10000 $rhost -oN allports.nmap

# Step 2: Extract open ports and detailed scan
ports=$(grep -oP '\d+(?=/open)' allports.nmap | tr '\n' ',' | sed 's/,$//')
nmap -sC -sV -p $ports $rhost -oN detail.nmap

# Step 3: UDP scan (background)
sudo nmap -sU --top-ports 50 $rhost -oN udp.nmap &
```

---

## Host Discovery

### Quick Check (One-liner)

```shell
# Quick network discovery + port scan
nmap -sn $cidr | grep "Up" | awk '{print $5}' | xargs -I{} nmap -sC -sV -Pn {} -oN nmap_{}.txt
```

### Ping Sweep

> ICMP ping sweep (find live hosts)

```shell
# Nmap ping sweep (one-liner)
nmap -sn $cidr -oG - | grep "Up" | awk '{print $2}' | tee live_hosts.txt

# Nmap ARP scan (local network only - most reliable)
sudo nmap -sn -PR $cidr -oG - | grep "Up" | awk '{print $2}' | tee live_hosts.txt

# fping (fast)
fping -a -g $cidr 2>/dev/null | tee live_hosts.txt

# Ping sweep with bash (ICMP)
for i in {1..254}; do (ping -c1 -W1 192.168.1.$i &>/dev/null && echo "192.168.1.$i" &); done | tee live_hosts.txt
```

### ARP Discovery (Layer 2)

```shell
# arp-scan (most reliable on local network)
sudo arp-scan -l | grep -v "^Interface\|^Starting\|packets" | awk '{print $1}' | tee live_hosts.txt

# arp-scan specific range
sudo arp-scan $cidr | awk '/([0-9a-f]{2}:){5}[0-9a-f]{2}/{print $1}' | tee live_hosts.txt

# Netdiscover
sudo netdiscover -r $cidr -P | awk '/[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/{print $1}' | tee live_hosts.txt
```

### TCP/UDP Discovery (When ICMP Blocked)

```shell
# TCP SYN discovery on common ports
nmap -sn -PS22,80,443,445 $cidr -oG - | grep "Up" | awk '{print $2}' | tee live_hosts.txt

# TCP ACK discovery
sudo nmap -sn -PA80,443 $cidr -oG - | grep "Up" | awk '{print $2}' | tee live_hosts.txt

# UDP discovery
sudo nmap -sn -PU53,161 $cidr -oG - | grep "Up" | awk '{print $2}' | tee live_hosts.txt

# Combined TCP + UDP + ICMP
sudo nmap -sn -PE -PS22,80,443 -PU53,161 $cidr -oG - | grep "Up" | awk '{print $2}' | tee live_hosts.txt
```

### NetExec Host Discovery

```shell
# SMB discovery (Windows hosts)
nxc smb $cidr --gen-relay-list live_smb.txt 2>/dev/null && cat live_smb.txt

# Multiple protocols one-liner
for proto in smb rdp winrm ssh; do nxc $proto $cidr 2>/dev/null | grep -E "^\d|SMB|RDP|WINRM|SSH" | awk '{print $2}' | sort -u; done | sort -u | tee live_hosts.txt
```

### Quick Reference - Host Discovery

| Method | Command | Best For |
|--------|---------|----------|
| ICMP Ping | `nmap -sn $cidr` | General discovery |
| ARP Scan | `sudo arp-scan -l` | Local network (most reliable) |
| TCP SYN | `nmap -sn -PS22,80,443 $cidr` | When ICMP blocked |
| TCP ACK | `nmap -sn -PA80 $cidr` | Bypass stateless firewall |
| UDP | `nmap -sn -PU53,161 $cidr` | Find DNS/SNMP hosts |
| NetExec | `nxc smb $cidr` | Windows/AD environments |

---

## Nmap

### Basic Scan (One-liner)

> Quick scan + version detection (one-liner)

```shell
sudo nmap -sV -sC -oN scan.nmap $rhost
```

> Full port scan then detailed scan (one-liner)

```shell
sudo nmap -p- --min-rate 10000 $rhost -oG - | grep '/open' | awk -F'/' '{print $1}' | awk '{print $NF}' | tr '\n' ',' | sed 's/,$//' | xargs -I{} sudo nmap -sV -sC -p {} -oN detail.nmap $rhost
```

> Full scan with auto port extraction (traditional)

```shell
port=$(sudo nmap -p- --min-rate 10000 $rhost | grep '^[0-9]' | cut -d'/' -f1 | tr '\n' ',' | sed 's/,$//') && sudo nmap -sV -sC -p $port -oN scan.nmap $rhost
```

### UDP Scan (One-liner)

> Top 100 UDP ports with version detection

```shell
sudo nmap -sU --top-ports 100 -sV -oN udp.nmap $rhost
```

> Quick UDP scan common ports

```shell
sudo nmap -sU -p 53,67,68,69,123,161,162,500,514,1900 -sV -oN udp_common.nmap $rhost
```

> Combined TCP + UDP scan

```shell
sudo nmap -sS -sU -p T:22,80,443,445,U:53,161,500 $rhost -oN tcp_udp.nmap
```

### Stealth Scanning

> SYN Stealth scan (default for root)

```shell
sudo nmap -sS -Pn -p- $rhost -oN stealth.nmap
```

> Slow and stealthy (IDS evasion)

```shell
sudo nmap -sS -T1 --max-retries 1 --max-rate 10 $rhost
```

> Fragment packets (bypass simple firewalls)

```shell
sudo nmap -sS -f -p 80,443,445 $rhost
```

> Decoy scan (hide among fake IPs)

```shell
sudo nmap -sS -D RND:10 -p 80,443,445 $rhost
```

> Idle/Zombie scan (completely stealthy)

```shell
# Find zombie host first
nmap -O -v $cidr | grep "IP ID Sequence"
# Use zombie for scan
sudo nmap -sI zombie_ip:80 $rhost
```

### CIDR Scan (One-liner)

> Find hosts with specific port open

```shell
nmap -p 445 --open $cidr -oG - | grep '/open' | awk '{print $2}' | tee smb_hosts.txt
```

> Scan multiple ports and extract live hosts

```shell
nmap -p 22,80,443,445,3389 --open $cidr -oG - | grep '/open' | awk '{print $2}' | sort -u | tee live_services.txt
```

### Vulnerability Scan (One-liner)

```shell
sudo nmap -sV --script "vuln" -oN vuln.nmap $rhost
```

> Safe enumeration scripts

```shell
sudo nmap -sV --script "safe and not brute" -oN safe.nmap $rhost
```

> Specific vulnerability checks

```shell
# EternalBlue (MS17-010)
nmap --script smb-vuln-ms17-010 -p 445 $rhost

# Heartbleed
nmap --script ssl-heartbleed -p 443 $rhost

# ShellShock
nmap --script http-shellshock --script-args uri=/cgi-bin/test.cgi -p 80 $rhost
```

### Firewall Evasion (One-liner)

> Skip host discovery + full scan

```shell
sudo nmap -Pn -p- --min-rate 10000 -oN pn_scan.nmap $rhost
```

> Fragment packets + decoys

```shell
sudo nmap -f -D RND:10 -p 80,443,445 $rhost
```

> Source port 53 (DNS - often allowed)

```shell
sudo nmap --source-port 53 -p- $rhost
```

## Masscan (One-liner)

> Full port scan + pipe to nmap

```shell
sudo masscan -p1-65535 $rhost --rate=1000 -oL - 2>/dev/null | grep 'open' | cut -d' ' -f3 | sort -n | uniq | tr '\n' ',' | sed 's/,$//' | xargs -I{} sudo nmap -sV -sC -p {} -oN mass_detail.nmap $rhost
```

> Quick common ports

```shell
sudo masscan -p21,22,23,25,53,80,110,139,443,445,3306,3389,5985,8080 $rhost --rate=1000 2>/dev/null | tee masscan.txt
```

> CIDR range scan (one-liner with output)

```shell
sudo masscan -p80,443,445 $cidr --rate=10000 2>/dev/null | awk '/open/{print $6}' | sort -u | tee mass_hosts.txt
```

## Rustscan (One-liner)

> Fast scan with nmap integration

```shell
rustscan -a $rhost --ulimit 5000 -- -sV -sC -oN rust_scan.nmap
```

> Greppable output for scripting

```shell
rustscan -a $rhost --ulimit 5000 -g 2>/dev/null | tr ',' '\n'
```

> Batch scan from file

```shell
rustscan -a $(cat live_hosts.txt | tr '\n' ',') --ulimit 5000 -- -sV -oN batch_scan.nmap
```

## NetExec (One-liner)

> Multi-protocol discovery

```shell
for p in smb ldap winrm mssql rdp ssh ftp; do echo "=== $p ===" && nxc $p $cidr 2>/dev/null | grep -v "^\[" | head -20; done | tee nxc_discovery.txt
```

> SMB signing check (for relay attacks)

```shell
nxc smb $cidr --gen-relay-list relay_targets.txt 2>/dev/null
```

> Quick Windows enumeration

```shell
nxc smb $rhost -u '' -p '' --shares --users --groups 2>/dev/null
```

## Tips

### Speed Optimization

| Option | Description |
| ------ | ----------- |
| `-T4` | Aggressive timing (faster) |
| `-T5` | Insane timing (fastest, may miss ports) |
| `--min-rate 10000` | Minimum packet rate |
| `--max-retries 1` | Reduce retries for speed |

### Common Options

| Option | Description |
| ------ | ----------- |
| `-sV` | Version detection |
| `-sC` | Default scripts |
| `-sS` | SYN stealth scan |
| `-sT` | TCP connect scan |
| `-sU` | UDP scan |
| `-Pn` | Skip host discovery |
| `-A` | Aggressive scan (OS, version, scripts, traceroute) |
| `-O` | OS detection |
| `-oN` | Normal output |
| `-oG` | Greppable output |
| `-oA` | All formats |

### Useful Script Categories

```shell
# List available scripts
ls /usr/share/nmap/scripts/*.nse | wc -l

# Search for specific scripts
ls /usr/share/nmap/scripts/*smb*.nse
ls /usr/share/nmap/scripts/*http*.nse
ls /usr/share/nmap/scripts/*vuln*.nse

# Use script category
sudo nmap --script "default,safe" -p $port $rhost
sudo nmap --script "vuln and safe" -p $port $rhost
```

### Timing Templates Explained

| Template | Name | Packets/sec | Use Case |
| -------- | ---- | ----------- | -------- |
| `-T0` | Paranoid | 1 every 5 min | IDS evasion (very slow) |
| `-T1` | Sneaky | 1 every 15 sec | IDS evasion |
| `-T2` | Polite | 1 every 0.4 sec | Reduce network load |
| `-T3` | Normal | Default | Standard scanning |
| `-T4` | Aggressive | Parallel, fast | CTF/Lab environment |
| `-T5` | Insane | Max speed | Fast but may miss ports |

---

## Output Parsing

### Extract Open Ports from Nmap

```shell
# From greppable output (-oG)
grep -oP '\d+/open' scan.gnmap | cut -d'/' -f1 | tr '\n' ',' | sed 's/,$//'

# From normal output (-oN)
grep "^[0-9]" scan.nmap | grep open | cut -d'/' -f1 | tr '\n' ',' | sed 's/,$//'

# One-liner: Scan and extract ports
ports=$(sudo nmap -p- --min-rate 10000 -Pn $rhost | grep "^[0-9]" | cut -d'/' -f1 | tr '\n' ',' | sed 's/,$//')
echo $ports
```

### Quick Port Extraction Script

```shell
# Save as extract_ports.sh
#!/bin/bash
if [ -z "$1" ]; then
    echo "Usage: $0 <nmap_output_file>"
    exit 1
fi
grep -oP '\d+(?=/open)' "$1" | sort -n | uniq | tr '\n' ',' | sed 's/,$/\n/'
```

### Convert Nmap XML to Other Formats

```shell
# XML to HTML report
xsltproc scan.xml -o scan.html

# Using nmap's built-in
nmap --webxml -oX - $rhost | xsltproc - -o scan.html
```

---

## Common Port Lists

### Top Ports by Category

```shell
# Top 20 TCP ports (most common)
ports_top20="21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080"

# Windows focused
ports_windows="53,88,135,139,389,445,464,593,636,3268,3269,3389,5985,5986,9389"

# Linux focused  
ports_linux="21,22,23,25,53,80,110,111,139,143,443,445,993,995,2049,3306,5432,6379"

# Web applications
ports_web="80,443,8000,8080,8443,8888,9000,9090,9443,10000"

# Databases
ports_db="1433,1521,3306,5432,6379,27017,9200,5984"

# Use with nmap
sudo nmap -sV -sC -p $ports_windows $rhost
```

### OSCP Essential Ports

```shell
# Most common in OSCP labs
ports_oscp="21,22,23,25,53,80,88,110,111,135,139,143,389,443,445,464,587,636,993,995,1433,1521,2049,3268,3269,3306,3389,5432,5900,5985,5986,6379,8000,8080,8443,9200,27017"

sudo nmap -sV -sC -p $ports_oscp $rhost -oA oscp_scan
```

---

## IPv6 Scanning

### Basic IPv6 Scan

```shell
# Scan IPv6 address
sudo nmap -6 -sV -sC $ipv6_target

# Discover IPv6 hosts on local network
sudo nmap -6 --script=targets-ipv6-multicast-* --script-args 'newtargets,interface=eth0'

# Scan link-local addresses
sudo nmap -6 fe80::1%eth0
```

### IPv6 Discovery

```shell
# Using ping6
ping6 -c 2 ff02::1%eth0

# IPv6 neighbor discovery
ip -6 neigh show

# Alive6 from THC-IPv6
alive6 eth0
```

---

## Firewall/IDS Evasion

### Fragmentation and MTU

```shell
# Fragment packets (8-byte fragments)
sudo nmap -f $rhost

# Custom MTU (must be multiple of 8)
sudo nmap --mtu 24 $rhost

# Combine with scan
sudo nmap -f -sS -Pn -p 445 $rhost
```

### Source Port Manipulation

```shell
# Use trusted source port (DNS)
sudo nmap --source-port 53 -sS $rhost

# FTP source port
sudo nmap --source-port 20 -sS $rhost

# Combine with Netcat for connection
nc -p 53 $rhost 445
```

### MAC Address Spoofing

```shell
# Random MAC
sudo nmap --spoof-mac 0 $rhost

# Specific vendor
sudo nmap --spoof-mac Dell $rhost

# Specific MAC
sudo nmap --spoof-mac 00:11:22:33:44:55 $rhost
```

### Badsum for Firewall Detection

```shell
# Send packets with bad checksums (firewalls may respond, real hosts won't)
sudo nmap --badsum $rhost
```

---

## Troubleshooting

### Common Issues

| Problem | Solution |
| ------- | -------- |
| "Host seems down" | Use `-Pn` to skip ping |
| Slow scanning | Use `-T4` or `--min-rate` |
| Missing ports | Scan all ports `-p-` |
| Permission denied | Use `sudo` for SYN scan |
| UDP scan slow | Limit ports `-p U:53,67,68,69,123,161` |
| No route to host | Check network/firewall |

### Verify Connectivity

```shell
# Basic connectivity
ping -c 1 $rhost

# TCP connectivity (without nmap)
nc -zv $rhost 80

# Multiple ports
for port in 21 22 80 443; do nc -zv -w2 $rhost $port 2>&1; done
```

### Debug Mode

```shell
# Packet trace
sudo nmap --packet-trace -p 80 $rhost

# Debug output
sudo nmap -d -p 80 $rhost

# Reason for port state
sudo nmap --reason -p 80 $rhost
```

---

## See Also

- **[IT-Ports/](IT-Ports/)** - Service-specific enumeration (SMB, SSH, HTTP, etc.)
- **[OT-Ports/](OT-Ports/)** - Industrial/SCADA protocol scanning
- **[AD Exploitation](../3.AD-Exploit/3.1.AD-Exploitation.md)** - Post-scan AD enumeration
- **[Web Application Analysis](../7.Web-Exploit/7.0.Web-Application-Analysis.md)** - Web service scanning

