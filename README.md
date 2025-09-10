**Running the Script**

From Terminal, Command Prompt or PowerShell, navigate to where you saved the script and run:

Scan a single host (IPv4):
```bash
python network_scanner.py --target 192.168.1.10
```

Scan IPv6 host:
```bash
python network_scanner.py --target 2001:db8::1 --ipv6
```

Scan subnet:
```bash
python network_scanner.py --target 192.168.1.0/24
```

Scan multiple hosts from a file:
```bash
python network_scanner.py --file targets.txt
```

Enable vulnerability scan:
```bash
python network_scanner.py --target 192.168.1.20 --vuln
```