import socket

class PortScanner:
    def __init__(self, domain):
        self.domain = domain
        self.ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 587, 993, 995, 3306]

    def scan(self):
        open_ports = []
        for port in self.ports:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(1)
                    result = s.connect_ex((self.domain, port))
                    if result == 0:
                        try:
                            s.sendall(b'HEAD / HTTP/1.0\r\n\r\n')
                            banner = s.recv(1024).decode(errors='ignore').strip()
                        except:
                            banner = ''
                        open_ports.append({'port': port, 'banner': banner})
            except Exception:
                pass
        return open_ports
