# Port 53 - DNS

## Table of Contents

- [Enumeration](#enumeration)
  - [Nmap Scripts](#nmap-scripts)
  - [DNS Lookup](#dns-lookup)
  - [Zone Transfer](#zone-transfer)
  - [Subdomain Enumeration](#subdomain-enumeration)
- [Tools](#tools)
  - [dig](#dig)
  - [nslookup](#nslookup)
  - [dnsrecon](#dnsrecon)
  - [dnsenum](#dnsenum)
  - [fierce](#fierce)
- [Post-Exploitation](#post-exploitation)

---

## Enumeration

### Nmap Scripts

```shell
# Service detection
nmap -p 53 -sV $rhost

# DNS enumeration
nmap -p 53 --script dns-brute $rhost
nmap -p 53 --script dns-zone-transfer --script-args dns-zone-transfer.domain=$domain $rhost
nmap -p 53 --script dns-srv-enum --script-args dns-srv-enum.domain=$domain $rhost
nmap -p 53 --script dns-nsid $rhost
```

### DNS Lookup

```shell
# Forward lookup
host www.$domain
host -t mx $domain
host -t txt $domain
host -t ns $domain

# Reverse lookup
host $rhost

# Query specific DNS server
host www.$domain $rhost
```

### Zone Transfer

```shell
# Using host
host -l $domain $rhost

# Using dig
dig axfr @$rhost $domain

# Using nslookup
nslookup
> server $rhost
> set type=any
> ls -d $domain
```

### Subdomain Enumeration

```shell
# Bash bruteforce
for sub in $(cat subdomains.txt); do host $sub.$domain | grep -v "not found"; done

# Using wfuzz
wfuzz -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -H "Host: FUZZ.$domain" -u http://$rhost --hc 400,404,403

# Using ffuf
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -H "Host: FUZZ.$domain" -u http://$rhost -ac

# Using gobuster
gobuster dns -d $domain -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
```

---

## Tools

### dig

```shell
# Basic query
dig $domain

# Query specific record type
dig $domain A
dig $domain MX
dig $domain NS
dig $domain TXT
dig $domain ANY

# Query specific DNS server
dig @$rhost $domain

# Zone transfer
dig axfr @$rhost $domain

# Reverse lookup
dig -x $rhost

# Short output
dig +short $domain
```

### nslookup

```shell
# Interactive mode
nslookup
> server $rhost
> $domain

# Query types
nslookup -type=A $domain
nslookup -type=MX $domain
nslookup -type=NS $domain
nslookup -type=TXT $domain
nslookup -type=PTR $rhost

# Query specific server
nslookup $domain $rhost
```

### dnsrecon

```shell
# Standard enumeration
dnsrecon -d $domain

# Zone transfer
dnsrecon -d $domain -t axfr

# Bruteforce
dnsrecon -d $domain -D /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -t brt

# Reverse lookup range
dnsrecon -r 192.168.1.0/24
```

### dnsenum

```shell
# Basic enumeration
dnsenum $domain

# With wordlist
dnsenum --enum $domain -f /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
```

### fierce

```shell
# Domain scan
fierce --domain $domain

# With DNS server
fierce --domain $domain --dns-servers $rhost
```

---

## Post-Exploitation

### DNS Cache Snooping

```shell
# Check if recursive queries are allowed
dig @$rhost $domain +recurse
```

### Common DNS Records

| Record | Description |
|--------|-------------|
| A | IPv4 address |
| AAAA | IPv6 address |
| MX | Mail exchange |
| NS | Nameserver |
| TXT | Text record (SPF, DKIM) |
| CNAME | Canonical name (alias) |
| PTR | Pointer (reverse DNS) |
| SOA | Start of authority |
| SRV | Service location |
