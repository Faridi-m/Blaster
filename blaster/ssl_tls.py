import ssl
import socket
from datetime import datetime
from colorama import Fore, Style

# ============================================================
#                   SSL/TLS ANALYSIS MODULE
#
#   Checks:
#     - Certificate details (issuer, subject, serial)
#     - Valid from / Valid to dates
#     - Days until expiry + expiry warning (< 30 days)
#     - Self-signed detection
#     - Subject Alternative Names (SANs)
#     - TLS version negotiated
#     - Cipher suite negotiated
#     - Weak protocol detection (SSLv2, SSLv3, TLS 1.0, TLS 1.1)
#
#   No external packages — uses built-in ssl + socket only
# ============================================================

class SSLAnalyzer:
    def __init__(self, domain, port=443):
        self.domain = domain
        self.port   = port

        # ----------------------------------------------------
        #   WEAK PROTOCOLS — flagged as insecure if supported
        #   TLS 1.0 and 1.1 are deprecated (RFC 8996)
        #   SSLv2 and SSLv3 are critically broken
        # ----------------------------------------------------
        self.weak_protocols = ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']


    # --------------------------------------------------------
    #   FETCH CERTIFICATE
    #   Connects to domain:port and pulls the raw cert dict
    # --------------------------------------------------------
    def _fetch_cert(self):
        # First attempt — try with verification to get full parsed cert dict
        # This works for valid, trusted certificates (most cases)
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode    = ssl.CERT_OPTIONAL

            with socket.create_connection((self.domain, self.port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=self.domain) as ssock:
                    cert        = ssock.getpeercert()
                    cipher      = ssock.cipher()
                    tls_version = ssock.version()

                    # If cert dict is populated, we're done
                    if cert:
                        return cert, cipher, tls_version

        except Exception:
            pass

        # Fallback — CERT_NONE + binary decode
        # Used when cert is self-signed, expired, or untrusted
        # getpeercert(binary_form=True) always returns data regardless
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode    = ssl.CERT_NONE

        with socket.create_connection((self.domain, self.port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=self.domain) as ssock:
                # Get binary DER cert and decode it with ssl itself
                der_cert    = ssock.getpeercert(binary_form=True)
                cert        = ssl.DER_cert_to_PEM_cert(der_cert)
                cipher      = ssock.cipher()
                tls_version = ssock.version()

                # Decode PEM back to dict using a temporary context
                try:
                    decoded = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                    decoded.check_hostname = False
                    decoded.verify_mode    = ssl.CERT_NONE
                    import tempfile, os
                    with tempfile.NamedTemporaryFile(
                        mode='w', suffix='.pem',
                        delete=False
                    ) as f:
                        f.write(cert)
                        tmp_path = f.name

                    parsed = ssl._ssl._test_decode_cert(tmp_path)
                    os.unlink(tmp_path)
                    return parsed, cipher, tls_version
                except Exception:
                    # If decode still fails, return empty dict
                    # analyze() will report the connection details at minimum
                    return {}, cipher, tls_version


    # --------------------------------------------------------
    #   PARSE CERTIFICATE FIELDS
    #   Extracts clean structured data from raw cert dict
    # --------------------------------------------------------
    def _parse_cert(self, cert, cipher, tls_version):
        result = {}

        # --- Subject (who the cert is issued TO) ---
        subject = dict(x[0] for x in cert.get('subject', []))
        result['subject_cn'] = subject.get('commonName', 'N/A')
        result['subject_org'] = subject.get('organizationName', 'N/A')

        # --- Issuer (who issued the cert) ---
        issuer = dict(x[0] for x in cert.get('issuer', []))
        result['issuer_cn']  = issuer.get('commonName', 'N/A')
        result['issuer_org'] = issuer.get('organizationName', 'N/A')

        # --- Validity Dates ---
        not_before_str = cert.get('notBefore', '')
        not_after_str  = cert.get('notAfter', '')

        try:
            not_before = datetime.strptime(not_before_str, '%b %d %H:%M:%S %Y %Z')
            not_after  = datetime.strptime(not_after_str,  '%b %d %H:%M:%S %Y %Z')
            days_left  = (not_after - datetime.utcnow()).days

            result['valid_from']  = not_before.strftime('%Y-%m-%d')
            result['valid_to']    = not_after.strftime('%Y-%m-%d')
            result['days_left']   = days_left
            result['is_expired']  = days_left < 0
            result['expiry_warn'] = 0 < days_left < 30  # Warning if < 30 days
        except Exception:
            result['valid_from']  = not_before_str
            result['valid_to']    = not_after_str
            result['days_left']   = None
            result['is_expired']  = False
            result['expiry_warn'] = False

        # --- Serial Number ---
        result['serial'] = cert.get('serialNumber', 'N/A')

        # --- Self-Signed Detection ---
        # A cert is self-signed when issuer == subject
        # Only flag if we actually have real values (not N/A)
        has_real_data = (
            result['subject_cn'] != 'N/A' or
            result['issuer_cn']  != 'N/A'
        )
        result['self_signed'] = (
            has_real_data and (
                result['issuer_cn']  == result['subject_cn'] or
                result['issuer_org'] == result['subject_org']
            ) and result['issuer_cn'] != 'N/A'
        )

        # --- Subject Alternative Names (SANs) ---
        # SANs reveal all domains this cert is valid for
        # Often reveals subdomains and related domains
        sans = []
        for san_type, san_value in cert.get('subjectAltName', []):
            if san_type == 'DNS':
                sans.append(san_value)
        result['sans'] = sans

        # --- TLS Version & Cipher ---
        result['tls_version']  = tls_version or 'Unknown'
        result['cipher_name']  = cipher[0] if cipher else 'Unknown'
        result['cipher_bits']  = cipher[2] if cipher else 'Unknown'

        # --- Weak Protocol Flag ---
        result['weak_protocol'] = tls_version in self.weak_protocols

        return result


    # --------------------------------------------------------
    #   ANALYZE — MAIN METHOD
    #   Returns structured dict or error dict
    # --------------------------------------------------------
    def analyze(self):
        try:
            cert, cipher, tls_version = self._fetch_cert()
            parsed = self._parse_cert(cert, cipher, tls_version)
            return {
                'domain':  self.domain,
                'port':    self.port,
                'success': True,
                'data':    parsed
            }

        except ssl.SSLError as e:
            return {
                'success': False,
                'error':   f"SSL Error: {str(e)}"
            }
        except socket.timeout:
            return {
                'success': False,
                'error':   f"Connection timed out on port {self.port}"
            }
        except ConnectionRefusedError:
            return {
                'success': False,
                'error':   f"Port {self.port} is closed or not accepting SSL"
            }
        except Exception as e:
            return {
                'success': False,
                'error':   f"Unexpected error: {str(e)}"
            }