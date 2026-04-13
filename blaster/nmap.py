import socket
import ssl
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import Fore, Style

# ============================================================
#                    PORT SCANNER MODULE
#
#   PRESERVED:
#     - Class name: PortScanner
#     - Method name: scan()
#     - Return structure: list of dicts with 'port' and 'banner'
#     - Core socket-based scanning logic
#
#   ADDITIONS:
#     - Expanded port list (13 → 65 ports)
#       covering web, mail, databases, remote access,
#       cloud, devops, monitoring, and known risky ports
#     - Service name labels per port
#       (port 443 now shows 'HTTPS' not just the number)
#     - Threaded scanning — all ports scanned in parallel
#       instead of one by one (much faster)
#     - Protocol-aware banner grabbing
#       HTTP, HTTPS, FTP, SMTP, SSH each get the right probe
#     - Risk tagging — flags ports known to be dangerous
#       when exposed (e.g. MongoDB, Redis, Elasticsearch)
# ============================================================

class PortScanner:
    def __init__(self, domain):
        self.domain = domain

        # ----------------------------------------------------
        #   PORT LIST — EXPANDED (13 → 65 ports)
        #   Format: port → (service_name, risk_flag)
        #   risk_flag: True = dangerous if publicly exposed
        # ----------------------------------------------------
        self.ports = {

            # --- Web ---
            80:    ('HTTP',               False),
            443:   ('HTTPS',              False),
            8080:  ('HTTP-Alt',           False),
            8443:  ('HTTPS-Alt',          False),
            8888:  ('HTTP-Dev',           False),
            8000:  ('HTTP-Dev',           False),
            8008:  ('HTTP-Alt',           False),
            3000:  ('Node/Dev Server',    False),
            4000:  ('Dev Server',         False),
            5000:  ('Dev/Flask Server',   False),
            7000:  ('Dev Server',         False),
            9000:  ('Dev/SonarQube',      False),

            # --- Mail ---
            25:    ('SMTP',               False),
            465:   ('SMTPS',              False),
            587:   ('SMTP Submission',    False),
            110:   ('POP3',               False),
            995:   ('POP3S',              False),
            143:   ('IMAP',               False),
            993:   ('IMAPS',              False),

            # --- Remote Access ---
            22:    ('SSH',                False),
            23:    ('Telnet',             True),   # Unencrypted — risky
            3389:  ('RDP',                True),   # Remote Desktop — risky
            5900:  ('VNC',                True),   # VNC — risky if exposed
            5901:  ('VNC-1',              True),
            2222:  ('SSH-Alt',            False),

            # --- FTP ---
            21:    ('FTP',                True),   # Unencrypted — risky
            20:    ('FTP-Data',           True),
            990:   ('FTPS',               False),
            989:   ('FTPS-Data',          False),

            # --- DNS ---
            53:    ('DNS',                False),

            # --- Databases — risky if publicly exposed ---
            3306:  ('MySQL',              True),
            5432:  ('PostgreSQL',         True),
            1433:  ('MSSQL',              True),
            1521:  ('Oracle DB',          True),
            27017: ('MongoDB',            True),
            27018: ('MongoDB-Shard',      True),
            6379:  ('Redis',              True),
            6380:  ('Redis-TLS',          True),
            5984:  ('CouchDB',            True),
            9200:  ('Elasticsearch',      True),
            9300:  ('Elasticsearch',      True),
            7474:  ('Neo4j',              True),
            8086:  ('InfluxDB',           True),
            9042:  ('Cassandra',          True),
            2181:  ('Zookeeper',          True),

            # --- Message Queues ---
            5672:  ('RabbitMQ',           True),
            15672: ('RabbitMQ Mgmt',      True),
            9092:  ('Kafka',              True),

            # --- DevOps & CI/CD ---
            2375:  ('Docker (Unencrypted)', True),  # Critical risk
            2376:  ('Docker TLS',         False),
            6443:  ('Kubernetes API',     True),
            8001:  ('Kubernetes Proxy',   True),
            10250: ('Kubelet API',        True),
            2379:  ('etcd',               True),
            50000: ('Jenkins',            True),

            # --- Monitoring ---
            3000:  ('Grafana',            False),
            5601:  ('Kibana',             False),
            9090:  ('Prometheus',         False),
            9100:  ('Node Exporter',      False),

            # --- VPN & Proxy ---
            1194:  ('OpenVPN',            False),
            1723:  ('PPTP VPN',           False),
            500:   ('IPSec VPN',          False),
            8118:  ('Privoxy Proxy',      False),
            3128:  ('Squid Proxy',        False),

            # --- Other Common ---
            389:   ('LDAP',               True),
            636:   ('LDAPS',              False),
            161:   ('SNMP',               True),
            162:   ('SNMP Trap',          True),
            111:   ('RPC',                True),
            2049:  ('NFS',                True),
            445:   ('SMB',                True),   # Critical — ransomware target
            139:   ('NetBIOS',            True),
        }

    # --------------------------------------------------------
    #   PROTOCOL-AWARE BANNER GRABBING — ADDED
    #   Different services need different probes to respond
    #   Previously only sent HTTP HEAD — now sends the right
    #   probe per protocol for accurate banner retrieval
    # --------------------------------------------------------
    def _grab_banner(self, sock, port):
        try:
            # ------------------------------------------------
            #   HTTP ports — full header capture
            #   Same approach as HTTPS — read until \r\n\r\n
            #   to get status line + Server header
            # ------------------------------------------------
            if port in (80, 8080, 8000, 8008, 8888, 3000, 4000, 5000, 7000, 9000):
                sock.sendall(
                    b'HEAD / HTTP/1.1\r\nHost: ' + self.domain.encode() +
                    b'\r\nConnection: close\r\n\r\n'
                )
                raw = b''
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    raw += chunk
                    if b'\r\n\r\n' in raw:
                        break
                return raw.decode(errors='ignore').strip()

            # ------------------------------------------------
            #   HTTPS ports — TLS handshake + full headers
            # ------------------------------------------------
            elif port in (443, 8443):
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode    = ssl.CERT_NONE
                with context.wrap_socket(sock, server_hostname=self.domain) as ssock:
                    ssock.sendall(
                        b'HEAD / HTTP/1.1\r\nHost: ' + self.domain.encode() +
                        b'\r\nConnection: close\r\n\r\n'
                    )
                    raw = b''
                    while True:
                        chunk = ssock.recv(4096)
                        if not chunk:
                            break
                        raw += chunk
                        if b'\r\n\r\n' in raw:
                            break
                return raw.decode(errors='ignore').strip()

            # ------------------------------------------------
            #   SMTP — server sends greeting automatically
            # ------------------------------------------------
            elif port in (25, 465, 587):
                return sock.recv(1024).decode(errors='ignore').strip()

            # ------------------------------------------------
            #   FTP — server sends greeting automatically
            # ------------------------------------------------
            elif port in (21, 990):
                return sock.recv(1024).decode(errors='ignore').strip()

            # ------------------------------------------------
            #   SSH — server sends banner automatically
            # ------------------------------------------------
            elif port == 22:
                return sock.recv(1024).decode(errors='ignore').strip()

            # ------------------------------------------------
            #   Database & generic ports
            #   Many DB servers send a greeting on connect
            # ------------------------------------------------
            else:
                try:
                    # Try reading greeting first (MySQL, Redis etc. send one)
                    sock.settimeout(1)
                    return sock.recv(1024).decode(errors='ignore').strip()
                except Exception:
                    # No greeting — send generic probe
                    sock.sendall(b'\r\n')
                    return sock.recv(1024).decode(errors='ignore').strip()

        except Exception:
            return ''

    # --------------------------------------------------------
    #   VERSION EXTRACTION
    #   Returns: "STATUS | Software/version" combined
    #   e.g. "HTTP/1.1 200 OK | nginx/1.18.0"
    #        "HTTP/1.1 301 Moved | Apache/2.4.52"
    #        "OpenSSH 8.9p1"
    #        "Postfix ESMTP"
    # --------------------------------------------------------
    def _extract_version(self, banner, service):
        if not banner:
            return ''

        import re

        # ------------------------------------------------
        #   SSH — extract software name + version
        # ------------------------------------------------
        ssh_match = re.search(r'ssh-[\d.]+-(\S+)', banner, re.IGNORECASE)
        if ssh_match:
            version = ssh_match.group(1).replace('_', ' ')
            if re.match(r'^[a-z]', version, re.IGNORECASE) and len(version) > 4:
                return version
            else:
                return 'SSH (custom implementation)'

        # ------------------------------------------------
        #   HTTP/HTTPS — combine status line + server software
        #   Output: "HTTP/1.1 200 OK | nginx/1.18.0"
        #   If no software detected: "HTTP/1.1 200 OK"
        # ------------------------------------------------
        http_status = re.search(r'(HTTP/[\d.]+\s+\d+[^\r\n]*)', banner, re.IGNORECASE)
        if http_status:
            status_line = http_status.group(1).strip()

            # Try to extract server software from Server: header
            server_match = re.search(r'server:\s*([^\r\n]+)', banner, re.IGNORECASE)
            if server_match:
                server_val  = server_match.group(1).strip()
                is_generic  = server_val.lower() in ('server', '', '-', 'unknown')
                is_domain   = bool(re.match(r'^[\w.-]+\.[a-z]{2,}$', server_val, re.IGNORECASE))
                if not is_generic and not is_domain:
                    return f"{status_line} | {server_val}"

            # No useful server header — return status line only
            return status_line

        # ------------------------------------------------
        #   SMTP — extract software from greeting
        #   Format: "220 mail.example.com ESMTP Postfix"
        # ------------------------------------------------
        smtp_match = re.search(r'220\s+\S+\s+(.+)', banner, re.IGNORECASE)
        if smtp_match:
            return smtp_match.group(1).strip()[:60]

        # ------------------------------------------------
        #   FTP — extract software from greeting
        #   Format: "220 ProFTPD 1.3.5 Server"
        #           "220 FileZilla FTP Server"
        # ------------------------------------------------
        ftp_match = re.search(r'220[\s-]+(.+)', banner, re.IGNORECASE)
        if ftp_match:
            return ftp_match.group(1).strip()[:60]

        # ------------------------------------------------
        #   MySQL — greeting contains version
        #   Format: binary header with version string
        # ------------------------------------------------
        mysql_match = re.search(r'(\d+\.\d+\.\d+[\w-]*)', banner)
        if mysql_match and 'mysql' in service.lower():
            return f"MySQL {mysql_match.group(1)}"

        # ------------------------------------------------
        #   Redis — inline banner
        #   Format: "-ERR" or "+PONG" or version info
        # ------------------------------------------------
        if 'redis' in service.lower() and banner:
            return f"Redis ({banner[:30]})"

        # Fallback
        return banner[:60].strip()

    # --------------------------------------------------------
    #   SCAN SINGLE PORT — internal helper
    # --------------------------------------------------------
    def _scan_port(self, port):
        service_name, is_risky = self.ports.get(port, ('Unknown', False))
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1.5)
                result = s.connect_ex((self.domain, port))
                if result == 0:
                    banner  = self._grab_banner(s, port)
                    version = self._extract_version(banner, service_name)
                    return {
                        'port':    port,
                        'service': service_name,
                        'banner':  banner,
                        'version': version,
                        'risk':    is_risky
                    }
        except Exception:
            pass
        return None

    # --------------------------------------------------------
    #   SCAN — MAIN METHOD (THREADED) — ADDED THREADING
    #   Previously sequential — scanned one port at a time
    #   Now uses ThreadPoolExecutor for parallel scanning
    #   Same return contract: list of dicts with port/banner
    #   + added 'service' and 'risk' fields per entry
    # --------------------------------------------------------
    def scan(self):
        open_ports = []

        with ThreadPoolExecutor(max_workers=100) as executor:
            futures = {
                executor.submit(self._scan_port, port): port
                for port in self.ports
            }
            for future in as_completed(futures):
                result = future.result()
                if result:
                    open_ports.append(result)

        # Sort by port number for clean output
        open_ports.sort(key=lambda x: x['port'])
        return open_ports