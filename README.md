<p align="center">
  <img src="assets/banner.png" alt="CobraSEC · Blue Arsenal · port-sentinel" width="100%">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/CobraSEC-Blue_Arsenal-22d3ee?style=for-the-badge&labelColor=0a0f1a">
  <img src="https://img.shields.io/badge/License-MIT-38bdf8?style=for-the-badge&labelColor=0a0f1a">
  <img src="https://img.shields.io/badge/Python-3.x-7dd3fc?style=for-the-badge&labelColor=0a0f1a">
  <img src="https://img.shields.io/badge/Status-Active-16a34a?style=for-the-badge&labelColor=0a0f1a">
</p>

<h1 align="center">port-sentinel</h1>
<p align="center"><b>Listening-port drift & anomaly monitor</b><br><sub><i>CobraSEC · Attack in order to Defend.</i></sub></p>

---


Features:
  - Stealth TCP/UDP port listener on configurable ports
  - Port scan detection via SYN flood analysis (iptables/nflog or pcap)
  - Honeypot traps: banner emulation for SSH, HTTP, FTP, MySQL, SMB
  - Connection logging with geolocation (via external lookup)
  - Alerting on repeated connection attempts
  - SYN proxy mode to fingerprint scanners (passive OS detection)
  - IP blacklisting after threshold
  - JSON/CSV export of intrusion attempts

Usage:
  port_sentinel.py --mode listener --ports 22,80,443,3306,6379,8080
  port_sentinel.py --mode scan-detect --interface eth0
  port_sentinel.py --mode honeypot --ports 22,80,445,3389,6379
  port_sentinel.py --mode all --ports 22,80,443,8080,3306

## Requirements

- Python 3.8+ (standard library only — no external dependencies)

## Usage

```
python3 port_sentinel.py --help
```

```
usage: port_sentinel.py [-h] [--mode {listener,scan-detect,honeypot,all}]
                        [--ports PORTS] [--interface INTERFACE]
                        [--alert ALERT] [--ban BAN]
                        [--ban-duration BAN_DURATION] [--output OUTPUT]
                        [--duration DURATION]

Port Sentinel — Stealth Listener, Scan Detector & Honeypot

options:
  -h, --help            show this help message and exit
  --mode {listener,scan-detect,honeypot,all}
                        Operation mode
  --ports PORTS         Comma-separated ports (default: 22,80,443,8080,3306)
  --interface INTERFACE
                        Network interface for scan detection
  --alert ALERT         Connections from same IP before alert (default: 5)
  --ban BAN             Connections before IP ban (default: 15)
  --ban-duration BAN_DURATION
                        Ban duration in seconds (default: 3600)
  --output OUTPUT       JSON report output path
  --duration DURATION   Run duration in seconds (0 = forever)

Examples:
  python3 port_sentinel.py --mode listener --ports 22,80,443,3306,8080
  python3 port_sentinel.py --mode scan-detect
  python3 port_sentinel.py --mode honeypot --ports 22,21,80,445,3306,6379
  python3 port_sentinel.py --mode all --ports 22,80,443,8080,6379 --alert 3
```

## Notes

- Defensive tooling: run only on systems you own or are authorized to assess.
- Read-only by design where possible; review flags before use on production hosts.
- Some checks (disk sectors, process memory, raw sockets) require root.
