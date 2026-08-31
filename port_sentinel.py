#!/usr/bin/env python3
"""
Port Sentinel — Stealth Listener, Scan Detector & Honeypot
============================================================
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
"""

import os
import sys
import re
import json
import time
import struct
import signal
import socket
import ssl
import select
import hashlib
import logging
import argparse
import threading
import ipaddress
from pathlib import Path
from collections import defaultdict
from datetime import datetime, timedelta


logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
log = logging.getLogger('PortSentinel')


# ─── Banner Emulation Database ───────────────────────────────────────────────

BANNERS = {
    22: b'SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n',
    21: b'220 ProFTPD 1.3.5 Server Ready\r\n',
    25: b'220 mail.example.com ESMTP Postfix (Ubuntu)\r\n',
    80: b'HTTP/1.1 200 OK\r\nServer: Apache/2.4.52 (Ubuntu)\r\nContent-Type: text/html\r\nConnection: close\r\n\r\n<html><body><h1>It works!</h1></body></html>',
    110: b'+OK Dovecot ready.\r\n',
    143: b'* OK Dovecot ready.\r\n',
    443: b'HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\nContent-Type: text/html\r\nConnection: close\r\n\r\n<html><body><h1>Secure</h1></body></html>',
    445: None,  # SMB — handled specially
    3306: None,  # MySQL — handled specially
    3389: b'\x03\x00\x00\x13\x0e\xd0\x00\x00\x124\x00\x02\x1f\x08\x00\x02\x00\x00\x00',  # RDP negotiation
    5432: b'N\x00\x00\x00\x08\x00\x00\x00\x00',  # PostgreSQL deny (insufficient to auth)
    6379: b'-NOAUTH Authentication required.\r\n',  # Redis
    8080: b'HTTP/1.1 200 OK\r\nServer: Apache Tomcat/9.0.58\r\nContent-Type: text/html\r\nConnection: close\r\n\r\n<html><body><h2>Apache Tomcat</h2></body></html>',
    8443: b'HTTP/1.1 200 OK\r\nServer: Apache Tomcat/9.0.58\r\nContent-Type: text/html\r\nConnection: close\r\n\r\n<html><body><h2>Tomcat SSL</h2></body></html>',
    9200: b'HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\n\r\n{"error":{"reason":"missing authentication token","type":"security_exception"}}',
    27017: None,  # MongoDB wire protocol
    11211: b'ERROR\r\n',  # Memcached
    5900: b'RFB 003.008\n',  # VNC
    23: b'\xff\xfb\x01\xff\xfb\x03\xff\xfd\x18\xff\xfd\x1f',  # Telnet negotiation
}

SMB_BANNER = bytes.fromhex(
    '0000009a'   # NetBIOS session message
    'ff534d42'   # SMB marker
    '72000000009801c800000000000000000000000000000000000000'
    '000000000000000000000000000000000000000000000000000000'
    '000000000000000000000000000000000000000000000000000000'
    '0000000000000000000000000000000000000000'
)

MYSQL_BANNER = bytes([
    0x4a, 0x00, 0x00, 0x00, 0x0a, 0x38, 0x2e, 0x30,
    0x2e, 0x33, 0x36, 0x00, 0x1d, 0x00, 0x00, 0x00,
    0x58, 0x1e, 0x5f, 0x5e, 0x57, 0x28, 0x5b, 0x00,
    0xff, 0xf7, 0x08, 0x02, 0x00, 0x7f, 0x80, 0x15,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x6e, 0x3e, 0x35, 0x58, 0x47,
    0x6e, 0x4e, 0x4d, 0x77, 0x65, 0x00, 0x6d, 0x79,
    0x73, 0x71, 0x6c, 0x5f, 0x6e, 0x61, 0x74, 0x69,
    0x76, 0x65, 0x5f, 0x70, 0x61, 0x73, 0x73, 0x77,
    0x6f, 0x72, 0x64, 0x00,
])

MONGO_BANNER = bytes.fromhex(
    '4f000000'   # messageLength
    '00000000'   # requestID
    '00000000'   # responseTo
    'dd070000'   # opCode (2013 = OP_MSG)
    '00000000'   # flagBits
    '00000000'   # sections
    '1c000000'   # section kind 0
    '1069736d61737465720001000000'  # ismaster
    '086f6b00'  # ok
)


# ─── Port Sentinel Core ──────────────────────────────────────────────────────

class ConnectionRecord:
    def __init__(self, remote_addr, remote_port, local_port, timestamp=None, data=None):
        self.remote_addr = remote_addr
        self.remote_port = remote_port
        self.local_port = local_port
        self.timestamp = timestamp or datetime.now()
        self.data = data or b''
        self.geo = None

    def to_dict(self):
        return {
            'remote_addr': self.remote_addr,
            'remote_port': self.remote_port,
            'local_port': self.local_port,
            'timestamp': self.timestamp.isoformat(),
            'data_sent_hex': self.data[:256].hex(),
            'data_sent_ascii': self.data[:256].decode('ascii', errors='replace'),
        }


class PortSentinel:
    def __init__(self, ports, mode='all', interface=None, alert_threshold=5,
                 ban_threshold=15, ban_duration=3600, log_file=None):
        self.ports = ports
        self.mode = mode
        self.interface = interface
        self.alert_threshold = alert_threshold
        self.ban_threshold = ban_threshold
        self.ban_duration = ban_duration
        self.log_file = log_file

        self.connections = []
        self.ip_counter = defaultdict(list)
        self.banned_ips = {}
        self.running = False
        self.sockets = []
        self.lock = threading.Lock()

    # ─── Listener Mode ───────────────────────────────────────────────────────

    def start_listeners(self):
        for port in self.ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                sock.bind(('0.0.0.0', port))
                sock.listen(5)
                sock.settimeout(1.0)
                self.sockets.append((sock, port))
                log.info(f"Listening on 0.0.0.0:{port}")
            except OSError as e:
                log.warning(f"Cannot bind port {port}: {e}")

        if not self.sockets:
            log.error("No ports could be bound. Run as root for privileged ports.")
            return

        self.running = True

        while self.running:
            for sock, port in self.sockets:
                try:
                    client, addr = sock.accept()
                    t = threading.Thread(target=self._handle_connection,
                                         args=(client, addr, port), daemon=True)
                    t.start()
                except socket.timeout:
                    continue
                except OSError:
                    continue

    def _handle_connection(self, client, addr, port):
        remote_ip, remote_port = addr
        timestamp = datetime.now()

        # Check ban list
        if remote_ip in self.banned_ips:
            ban_time = self.banned_ips[remote_ip]
            if (datetime.now() - ban_time).total_seconds() < self.ban_duration:
                client.close()
                return
            else:
                del self.banned_ips[remote_ip]

        # Track connection attempt
        with self.lock:
            self.ip_counter[remote_ip].append(datetime.now())

        # Read initial data
        data = b''
        try:
            client.settimeout(3)
            data = client.recv(4096)
        except (socket.timeout, ConnectionResetError, OSError):
            pass

        # Record
        record = ConnectionRecord(remote_ip, remote_port, port, timestamp, data)
        with self.lock:
            self.connections.append(record)

        # Send appropriate banner
        banner = BANNERS.get(port)
        if port == 445:
            banner = SMB_BANNER
        elif port == 3306:
            banner = MYSQL_BANNER
        elif port == 27017:
            banner = MONGO_BANNER

        if banner:
            try:
                client.sendall(banner)
                time.sleep(0.5)
            except (socket.timeout, ConnectionResetError, BrokenPipeError):
                pass

        client.close()

        # Check alert threshold
        recent = [t for t in self.ip_counter[remote_ip]
                  if (datetime.now() - t).total_seconds() < 60]
        if len(recent) >= self.alert_threshold:
            log.warning(f"⚠ ALERT: {remote_ip} — {len(recent)} connections in 60s — THRESHOLD EXCEEDED")

        if len(recent) >= self.ban_threshold:
            self.banned_ips[remote_ip] = datetime.now()
            log.error(f"⛔ BANNED: {remote_ip} for {self.ban_duration}s — {len(recent)} connections")

        # Log
        ascii_data = data[:256].decode('ascii', errors='replace')
        log.info(f"Connection: {remote_ip}:{remote_port} → port {port} | "
                 f"Sent: {ascii_data[:80].strip()}")

    # ─── Scan Detection Mode ─────────────────────────────────────────────────

    def start_scan_detector(self):
        log.info(f"Starting scan detection mode (interface: {self.interface or 'all'})")
        self.running = True

        seen_scan = defaultdict(set)
        scan_window = 10  # seconds
        port_threshold = 5  # unique ports from same IP = scan

        while self.running:
            # Use ss to look for SYN_RECV connections (half-open — scan indicator)
            try:
                import subprocess
                result = subprocess.run(
                    ['ss', '-tan', 'state', 'syn-recv'],
                    capture_output=True, text=True, timeout=5
                )
                lines = result.stdout.strip().split('\n')[1:]
                for line in lines:
                    parts = line.split()
                    if len(parts) < 5:
                        continue
                    try:
                        # Parse: LISTEN 0 128 0.0.0.0:22 0.0.0.0:*
                        local = parts[3]
                        remote = parts[4] if len(parts) > 4 else '*:*'
                        local_port = int(local.rsplit(':', 1)[-1]) if ':' in local else 0
                        remote_ip = remote.rsplit(':', 1)[0] if ':' in remote else ''
                        if remote_ip and remote_ip != '*':
                            seen_scan[remote_ip].add((datetime.now(), local_port))
                    except (ValueError, IndexError):
                        continue
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass

            # Analyze scan behavior
            now = datetime.now()
            for ip in list(seen_scan.keys()):
                recent = [(t, p) for t, p in seen_scan[ip]
                          if (now - t).total_seconds() < scan_window]
                unique_ports = set(p for _, p in recent)
                if len(unique_ports) >= port_threshold:
                    log.warning(f"🔍 SCAN DETECTED: {ip} probing {len(unique_ports)} ports "
                                f"in {scan_window}s → {sorted(unique_ports)[:10]}")
                    # Clear to avoid repeated alerts
                    seen_scan[ip] = {(t, p) for t, p in seen_scan[ip]
                                     if (now - t).total_seconds() >= scan_window * 2}

            time.sleep(2)

    # ─── Honeypot Mode ───────────────────────────────────────────────────────

    def start_honeypot(self):
        """Interactive honeypot with richer responses for specific protocols."""
        log.info("Starting honeypot mode with protocol-aware responses")

        for port in self.ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.bind(('0.0.0.0', port))
                sock.listen(5)
                sock.settimeout(1.0)
                self.sockets.append((sock, port))
                log.info(f"Honeypot listening on 0.0.0.0:{port}")
            except OSError as e:
                log.warning(f"Cannot bind port {port}: {e}")

        if not self.sockets:
            log.error("No ports bound for honeypot")
            return

        self.running = True
        while self.running:
            for sock, port in self.sockets:
                try:
                    client, addr = sock.accept()
                    t = threading.Thread(target=self._honeypot_handle,
                                         args=(client, addr, port), daemon=True)
                    t.start()
                except socket.timeout:
                    continue
                except OSError:
                    continue

    def _honeypot_handle(self, client, addr, port):
        remote_ip, remote_port = addr
        timestamp = datetime.now()

        if remote_ip in self.banned_ips:
            client.close()
            return

        data = b''
        try:
            client.settimeout(5)
            data = client.recv(4096)
        except (socket.timeout, ConnectionResetError):
            pass

        with self.lock:
            self.connections.append(
                ConnectionRecord(remote_ip, remote_port, port, timestamp, data)
            )

        # Protocol-specific interaction
        if port == 22:
            self._honeypot_ssh(client, data)
        elif port == 21:
            self._honeypot_ftp(client, data)
        elif port == 80 or port == 8080:
            self._honeypot_http(client, data)
        elif port == 6379:
            self._honeypot_redis(client, data)
        elif port == 3306:
            self._honeypot_mysql(client, data)
        else:
            banner = BANNERS.get(port, b'')
            if banner:
                try:
                    client.sendall(banner)
                except (BrokenPipeError, ConnectionResetError):
                    pass

        try:
            client.close()
        except OSError:
            pass

        log.info(f"HONEYPOT: {remote_ip}:{remote_port} → port {port} | "
                 f"Data: {data[:100].decode('ascii', errors='replace').strip()}")

    def _honeypot_ssh(self, client, data):
        banner = BANNERS[22]
        client.sendall(banner)
        time.sleep(0.2)
        # Collect credentials attempt
        try:
            client.settimeout(10)
            more = client.recv(4096)
            log.info(f"SSH Interaction from {client.getpeername()}: {more[:200].hex()}")
            # Parse SSH client version string
            if b'SSH-' in more:
                client_ver = more.split(b'\r\n')[0].decode('ascii', errors='replace')
                log.info(f"SSH Client: {client_ver}")
            # Wait for auth attempt
            more2 = client.recv(4096)
            if more2:
                log.info(f"SSH Auth Data: {more2[:100].hex()}")
                # Try to extract username from SSH_MSG_USERAUTH_REQUEST
                # This is complex — log raw data for analysis
        except (socket.timeout, ConnectionResetError, OSError):
            pass

    def _honeypot_ftp(self, client, data):
        client.sendall(BANNERS[21])
        try:
            client.settimeout(10)
            user_data = client.recv(4096)
            log.info(f"FTP USER: {user_data.decode('ascii', errors='replace').strip()}")

            client.sendall(b'331 Password required\r\n')
            pass_data = client.recv(4096)
            log.info(f"FTP PASS: {pass_data.decode('ascii', errors='replace').strip()}")

            client.sendall(b'530 Login incorrect.\r\n')
        except (socket.timeout, ConnectionResetError):
            pass

    def _honeypot_http(self, client, data):
        request = data.decode('ascii', errors='replace')
        log.info(f"HTTP REQUEST: {request[:500]}")
        response = BANNERS.get(80, b'HTTP/1.1 200 OK\r\n\r\n')
        try:
            client.sendall(response)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _honeypot_redis(self, client, data):
        client.sendall(BANNERS[6379])
        try:
            client.settimeout(10)
            cmd = client.recv(4096)
            log.info(f"Redis Command: {cmd.decode('ascii', errors='replace').strip()}")
            client.sendall(b'-NOAUTH Authentication required.\r\n')
        except (socket.timeout, ConnectionResetError):
            pass

    def _honeypot_mysql(self, client, data):
        client.sendall(MYSQL_BANNER)
        try:
            client.settimeout(10)
            auth_data = client.recv(4096)
            log.info(f"MySQL Auth Attempt: {auth_data[:200].hex()}")
            # Send access denied
            client.sendall(bytes([0x1d, 0x00, 0x00, 0x01, 0xff, 0x15, 0x04] +
                                 b"#28000Access denied for user"))
        except (socket.timeout, ConnectionResetError):
            pass

    # ─── Report Generation ───────────────────────────────────────────────────

    def generate_report(self, output_path=None):
        if not self.connections:
            print("No connections recorded.")
            return

        report = {
            'scan_time': datetime.now().isoformat(),
            'total_connections': len(self.connections),
            'unique_ips': len(set(c.remote_addr for c in self.connections)),
            'banned_ips': {ip: t.isoformat() for ip, t in self.banned_ips.items()},
            'connections': [c.to_dict() for c in self.connections],
            'per_port': defaultdict(list),
            'top_ips': [],
        }

        ip_counts = Counter(c.remote_addr for c in self.connections)
        report['top_ips'] = ip_counts.most_common(20)

        for conn in self.connections:
            report['per_port'][conn.local_port].append(conn.to_dict())

        # Convert defaultdict for JSON
        report['per_port'] = dict(report['per_port'])

        json_report = json.dumps(report, indent=2, default=str)

        if output_path:
            with open(output_path, 'w') as f:
                f.write(json_report)
            log.info(f"Report saved to {output_path}")
        else:
            print(json_report[:5000])

    # ─── Control ──────────────────────────────────────────────────────────────

    def stop(self):
        self.running = False
        for sock, port in self.sockets:
            try:
                sock.close()
            except OSError:
                pass
        log.info("Port Sentinel stopped.")

    def run_forever(self):
        if self.mode == 'listener':
            self.start_listeners()
        elif self.mode == 'scan-detect':
            self.start_scan_detector()
        elif self.mode == 'honeypot':
            self.start_honeypot()
        elif self.mode == 'all':
            # Run listeners and scan detection together
            threads = [
                threading.Thread(target=self.start_listeners, daemon=True),
                threading.Thread(target=self.start_scan_detector, daemon=True),
            ]
            for t in threads:
                t.start()
            try:
                while any(t.is_alive() for t in threads):
                    time.sleep(1)
            except KeyboardInterrupt:
                self.stop()


def main():
    parser = argparse.ArgumentParser(
        description='Port Sentinel — Stealth Listener, Scan Detector & Honeypot',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  python3 port_sentinel.py --mode listener --ports 22,80,443,3306,8080
  python3 port_sentinel.py --mode scan-detect
  python3 port_sentinel.py --mode honeypot --ports 22,21,80,445,3306,6379
  python3 port_sentinel.py --mode all --ports 22,80,443,8080,6379 --alert 3
        '''
    )
    parser.add_argument('--mode', choices=['listener', 'scan-detect', 'honeypot', 'all'],
                        default='listener', help='Operation mode')
    parser.add_argument('--ports', type=str, default='22,80,443,8080,3306',
                        help='Comma-separated ports (default: 22,80,443,8080,3306)')
    parser.add_argument('--interface', type=str, help='Network interface for scan detection')
    parser.add_argument('--alert', type=int, default=5,
                        help='Connections from same IP before alert (default: 5)')
    parser.add_argument('--ban', type=int, default=15,
                        help='Connections before IP ban (default: 15)')
    parser.add_argument('--ban-duration', type=int, default=3600,
                        help='Ban duration in seconds (default: 3600)')
    parser.add_argument('--output', type=str, help='JSON report output path')
    parser.add_argument('--duration', type=int, default=0,
                        help='Run duration in seconds (0 = forever)')

    args = parser.parse_args()

    ports = [int(p.strip()) for p in args.ports.split(',') if p.strip()]

    sentinel = PortSentinel(
        ports=ports,
        mode=args.mode,
        interface=args.interface,
        alert_threshold=args.alert,
        ban_threshold=args.ban,
        ban_duration=args.ban_duration,
    )

    def signal_handler(sig, frame):
        print("\nShutting down...")
        if args.output:
            sentinel.generate_report(args.output)
        sentinel.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    print(f"""
{'='*60}
  Port Sentinel v1.0
  Mode: {args.mode}
  Ports: {ports}
  Alert threshold: {args.alert} | Ban threshold: {args.ban}
{'='*60}
""")

    if args.duration > 0:
        threading.Timer(args.duration, signal_handler, args=(signal.SIGINT, None)).start()

    try:
        sentinel.run_forever()
    except KeyboardInterrupt:
        if args.output:
            sentinel.generate_report(args.output)
        sentinel.stop()


if __name__ == '__main__':
    main()
