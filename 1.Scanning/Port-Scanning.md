# Port Scanning

## Table of Contents
- [Nmap](#nmap)
- [Masscan](#masscan)
- [Rustscan](#rustscan)
- [NetExec](#netexec)
- [Tips](#tips)

## Nmap

### Basic Scan

> 1000 Port scan
```shell
sudo nmap -oN initial_scan.nmap $rhost
```

```shell
port=$(grep 'open' initial_scan.nmap | awk '{print $1}' | cut -d'/' -f1 | tr '\n' ',' | sed 's/,$//')
```

```shell
sudo nmap -sV -sC -oN detail_scan.nmap -p $port $rhost
```

> Full port scan step 65535 Port
```shell
sudo nmap -p- -T4 -oN initial_scan_full.nmap $rhost 
```

```shell
port=$(grep 'open' initial_scan_full.nmap | awk '{print $1}' | cut -d'/' -f1 | tr '\n' ',' | sed 's/,$//')
```

```shell
sudo nmap -sV -sC -oN detail_scan_full.nmap -p $port $rhost
```

> Fast full port scan with min-rate
```shell
sudo nmap -p- --min-rate 10000 -oN initial_scan_fast.nmap $rhost
```

### UDP Scan

> 100 UDP Port Scan
```shell
sudo nmap -sU --top-ports 100 -oN initial_scan_100udp.nmap $rhost
```

```shell
port=$(grep 'open' initial_scan_100udp.nmap | awk '{print $1}' | cut -d'/' -f1 | tr '\n' ',' | sed 's/,$//')
```

```shell
sudo nmap -sU -sV -sC -oN detail_scan_100udp.nmap -p $port $rhost
```

### CIDR Scan

> CIDR Port Scan
```shell
sudo nmap -p 445 -oN initial_port_cidr_scan.nmap $cidr
```

```shell
grep -A 3 'open' initial_port_cidr_scan.nmap | grep 'for' | awk  '{print$5}'
```

### Vulnerability Scan

> Nmap vulnerability scripts
```shell
sudo nmap -sV --script vuln -oN vuln_scan.nmap $rhost
```

> Safe scripts for enumeration
```shell
sudo nmap -sV -sC --script "safe and not intrusive" -oN safe_scan.nmap -p $port $rhost
```

### Firewall Evasion

> Skip host discovery (when ICMP is blocked)
```shell
sudo nmap -Pn -p- -oN initial_scan_pn.nmap $rhost
```

> Fragment packets
```shell
sudo nmap -f -p- -oN initial_scan_frag.nmap $rhost
```

> Use decoys
```shell
sudo nmap -D RND:10 -p 80,443 $rhost
```

> Source port manipulation
```shell
sudo nmap --source-port 53 -p- $rhost
```

## Masscan

> Fast port scan (entire port range)
```shell
sudo masscan -p1-65535 $rhost --rate=1000 -oL masscan_output.txt
```

> Common ports only
```shell
sudo masscan -p21,22,23,25,53,80,110,139,443,445,3306,3389,5985,8080 $rhost --rate=1000 -oL masscan_output.txt
```

> CIDR range scan
```shell
sudo masscan -p80,443 $cidr --rate=10000 -oL masscan_cidr.txt
```

> Parse masscan output for nmap
```shell
ports=$(grep 'open' masscan_output.txt | cut -d' ' -f3 | sort -n | uniq | tr '\n' ',' | sed 's/,$//')
sudo nmap -sV -sC -p $ports -oN detail_scan.nmap $rhost
```

## Rustscan

> Fast scan with nmap integration
```shell
rhost="192.168.1.1" && rustscan -a "$rhost" --ulimit 5000 -- -sV -sC -oN initial_scan.rust
```

> Scan specific ports
```shell
rustscan -a $rhost -p 22,80,443 -- -sV -sC
```

> Scan with greppable output
```shell
rustscan -a $rhost --ulimit 5000 -g
```

> Scan CIDR range
```shell
rustscan -a $cidr --ulimit 5000 -- -sV
```

## NetExec

> smb (445) , ldap (389) , winrm (5985) , mssql (1433) , ssh (22) , ftp (21) , rdp (3389) , wmi (5985)

```shell
for proto in smb ldap winrm mssql rdp ssh ftp; do
    if [[ "$proto" == "smb" || "$proto" == "mssql" || "$proto" == "winrm" ]]; then
        nxc $proto $cidr -u '' -p '' --local-auth --continue-on-success --no-bruteforce | tee -a nxc_$proto.txt
    else
        nxc $proto $cidr -u '' -p '' --continue-on-success --no-bruteforce | tee -a nxc_$proto.txt
    fi
done
```

## Tips

### Speed Optimization
| Option | Description |
|--------|-------------|
| `-T4` | Aggressive timing (faster) |
| `-T5` | Insane timing (fastest, may miss ports) |
| `--min-rate 10000` | Minimum packet rate |
| `--max-retries 1` | Reduce retries for speed |

### Common Options
| Option | Description |
|--------|-------------|
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

---

## See Also

- **[IT-Ports/](IT-Ports/)** - Service-specific enumeration (SMB, SSH, HTTP, etc.)
- **[OT-Ports/](OT-Ports/)** - Industrial/SCADA protocol scanning
- **[AD Exploitation](../3.AD-Exploit/3.1.AD-Exploitation.md)** - Post-scan AD enumeration
- **[Web Application Analysis](../7.Web-Exploit/7.0.Web-Application-Analysis.md)** - Web service scanning

