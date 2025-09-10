Running the Script on Windows

From Command Prompt or PowerShell, navigate to where you saved the script and run:

Scan a single host (IPv4):

python network_scanner.py --target 192.168.1.10


Scan IPv6 host:

python network_scanner.py --target 2001:db8::1 --ipv6


Scan subnet:

python network_scanner.py --target 192.168.1.0/24


Scan multiple hosts from a file:

python network_scanner.py --file targets.txt


Enable vulnerability scan:

python network_scanner.py --target 192.168.1.20 --vuln