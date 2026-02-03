# Port 554, 8554 - RTSP (Real Time Streaming Protocol)

## Table of Contents
- [Enumeration](#enumeration)
- [Stream Access](#stream-access)
- [Exploitation](#exploitation)

---

## Enumeration

### Quick Check (One-liner)

```shell
nmap -p 554 --script "rtsp-methods,rtsp-url-brute" $rhost
```

### Nmap

```shell
nmap -sV -sC -p 554 $rhost
nmap -p 554 --script "rtsp-methods" $rhost
nmap -p 554 --script "rtsp-url-brute" $rhost
```

### Check RTSP Methods

```shell
# Using curl
curl -i -X OPTIONS rtsp://$rhost:554/

# Using nmap
nmap -p 554 --script "rtsp-methods" $rhost
```

### Manual RTSP Request

```shell
# DESCRIBE request
echo -e "DESCRIBE rtsp://$rhost:554/ RTSP/1.0\nCSeq: 1\n\n" | nc $rhost 554

# OPTIONS request
echo -e "OPTIONS rtsp://$rhost:554/ RTSP/1.0\nCSeq: 1\n\n" | nc $rhost 554
```

---

## Stream Access

### Common RTSP URLs

```
rtsp://$rhost:554/
rtsp://$rhost:554/live
rtsp://$rhost:554/media
rtsp://$rhost:554/video1
rtsp://$rhost:554/stream1
rtsp://$rhost:554/ch0
rtsp://$rhost:554/cam/realmonitor
rtsp://$rhost:554/h264
rtsp://$rhost:554/mpeg4
```

### View Stream

```shell
# Using VLC
vlc rtsp://$rhost:554/stream

# Using ffplay
ffplay rtsp://$rhost:554/stream

# Using mpv
mpv rtsp://$rhost:554/stream

# With credentials
vlc rtsp://user:password@$rhost:554/stream
```

### Save Stream

```shell
# Record stream with ffmpeg
ffmpeg -i rtsp://$rhost:554/stream -c copy output.mp4

# With credentials
ffmpeg -i rtsp://user:password@$rhost:554/stream -c copy output.mp4
```

---

## Exploitation

### URL Brute Force

```shell
# Nmap script
nmap -p 554 --script "rtsp-url-brute" $rhost

# Custom wordlist
nmap -p 554 --script "rtsp-url-brute" \
  --script-args rtsp-url-brute.urlfile=rtsp_urls.txt $rhost
```

### Credential Brute Force

```shell
# Common default credentials
# admin:admin
# admin:password
# admin:12345
# root:root
# user:user

# Hydra (if basic auth)
hydra -l admin -P /usr/share/wordlists/rockyou.txt rtsp://$rhost
```

### Camera-Specific URLs

| Vendor | URL Format |
| :--- | :--- |
| Hikvision | `rtsp://$rhost:554/Streaming/Channels/101` |
| Dahua | `rtsp://$rhost:554/cam/realmonitor?channel=1&subtype=0` |
| Axis | `rtsp://$rhost:554/axis-media/media.amp` |
| Foscam | `rtsp://$rhost:554/videoMain` |
| Generic | `rtsp://$rhost:554/live.sdp` |

### Information Gathering

```shell
# RTSP may reveal:
# - Camera model
# - Firmware version
# - Stream capabilities
# - Authentication type

# Get stream info
ffprobe rtsp://$rhost:554/stream
```

---

## RTSP Methods

| Method | Description |
| :--- | :--- |
| OPTIONS | Get supported methods |
| DESCRIBE | Get stream info (SDP) |
| SETUP | Configure transport |
| PLAY | Start streaming |
| PAUSE | Pause streaming |
| TEARDOWN | Stop streaming |

---

## Quick Reference

| Command | Description |
| :--- | :--- |
| `nmap -p 554 --script "rtsp-methods" $rhost` | Get RTSP methods |
| `nmap -p 554 --script "rtsp-url-brute" $rhost` | Find streams |
| `vlc rtsp://$rhost:554/stream` | View stream |
| `ffmpeg -i rtsp://$rhost:554/stream -c copy out.mp4` | Record stream |
