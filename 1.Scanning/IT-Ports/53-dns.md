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

### Quick Check (One-liner)

```shell
dig axfr @$rhost $domain && nmap -p 53 --script "dns-zone-transfer" $rhost
```

### Nmap Scripts (One-liner)

```shell
# All DNS scripts in one command
nmap -p 53 -sV --script "dns-*" --script-args dns-zone-transfer.domain=$domain $rhost
```

### Zone Transfer (One-liner)

```shell
# Quick zone transfer attempt
dig axfr @$rhost $domain && host -l $domain $rhost
```

### DNS Lookup (One-liner)

```shell
# All record types at once
for t in A AAAA MX NS TXT SOA CNAME; do echo "=== $t ==="; dig +short $domain $t; done

# Reverse lookup
dig -x $rhost +short
```

### Subdomain Enumeration (One-liner)

```shell
# ffuf subdomain brute (fastest)
ffuf -u http://$rhost -H "Host: FUZZ.$domain" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -mc 200,301,302 -c

# gobuster DNS
gobuster dns -d $domain -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -t 50

# Bash bruteforce
for sub in $(cat /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt); do host $sub.$domain | grep -v "not found"; done 2>/dev/null
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
