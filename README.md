# Blaster - Domain Recon Made Brutal

> **Developed by Usman Faridi**
> A powerful domain reconnaissance tool built for speed, clarity, and brutal simplicity.

---

## 🚀 Features

* DNS Lookup (A, MX, TXT, NS records)
* WHOIS Lookup (raw socket query to WHOIS servers)
* Subdomain Enumeration (via [crt.sh](https://crt.sh))
* Port Scanning + Banner Grabbing (common ports)
* Clean, Colorful CLI Output (via `colorama`)
* Output to report file via command line redirection

---

## 📦 Installation

```bash
git clone https://github.com/Faridi-m/blaster.git
cd blaster
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

---

## ⚙️ Requirements

Add the following in your `requirements.txt` file:

```
colorama
requests
dnspython
pythonwhois-alt
```

---

## 🧠 Usage

```bash
python blaster.py example.com [--dns] [--whois] [--subdomains] [--ports] [-v]
```

### Flags:

* `--dns` — Perform DNS lookup
* `--whois` — Perform WHOIS lookup
* `--subdomains` — Discover subdomains
* `--ports` — Perform port scan and banner grabbing
* `-v`, `--verbose` — Enable verbose mode

### Example:

```bash
python blaster.py example.com --dns --subdomains --ports -v
```

---

### 📄 Saving Scan Results to a Report

You can save all scan output to a file (a report) by appending `> [filename]` to your command.

#### **Example:**

```bash
python blaster.py example.com --dns --whois --subdomains --ports -v > example_report.txt
```

✅ This will save the results into a file called `example_report.txt` in the current directory.

> 💡 Tip: You can also use `>>` to **append** results to an existing report file.

---

## 🔍 Output Example

```
[*] Running DNS lookup for example.com
[*] Searching subdomains for example.com
[+] Subdomains found:
  • www.example.com
  • mail.example.com

DNS Records:
A records:
  • 93.184.216.34
MX records:
  • mail.example.com

[+] Open Ports:
  • Port 80
    Banner: HTTP/1.1 200 OK
  • Port 443
```

---

## 🛡 Disclaimer

This tool is intended for educational and authorized security testing purposes only. Unauthorized use is prohibited.

---

## ✨ Credits

Built with ❤️ by Usman Faridi.
