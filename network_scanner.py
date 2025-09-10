#!/usr/bin/env python3
import nmap
import argparse
import json
import os
import sys
import csv
from tabulate import tabulate


def load_targets(file_path=None, target=None):
    """Load targets from file or direct input"""
    targets = []
    if file_path and os.path.exists(file_path):
        with open(file_path, "r") as f:
            targets = [line.strip() for line in f if line.strip()]
    elif target:
        targets = [target.strip()]
    else:
        print("❌ No targets provided. Use --target or --file")
        sys.exit(1)
    return targets


def discover_hosts(targets, use_ipv6=False):
    """Ping sweep to find live hosts before scanning"""
    nm = nmap.PortScanner()
    live_hosts = []

    for target in targets:
        print(f"\n🌐 Discovering live hosts in: {target} (IPv6: {use_ipv6})...")
        args = "-sn"
        if use_ipv6:
            args += " -6"

        try:
            nm.scan(hosts=target, arguments=args)
            for host in nm.all_hosts():
                if nm[host].state() == "up":
                    print(f"   ✅ Host up: {host}")
                    live_hosts.append(host)
                else:
                    print(f"   ❌ Host down: {host}")
        except Exception as e:
            print(f"❌ Error discovering {target}: {e}")

    return live_hosts


def scan_targets(targets, use_ipv6=False, vuln_scan=False, txt_output=None):
    """Full port/service/vuln scan for live hosts, also logs to TXT"""
    nm = nmap.PortScanner()
    results = {}

    def log(msg):
        """Helper to print and write to TXT file simultaneously"""
        print(msg)
        if txt_output:
            txt_output.write(msg + "\n")

    for target in targets:
        log(f"\n🔍 Scanning target: {target} (IPv6: {use_ipv6})...")
        args = "-Pn -sV -O"  # -sS -sU -sV -O -T4 --top-ports 50" --->>> TCP + UDP with speed optimization
        if vuln_scan:
            args += " --script vuln"
        if use_ipv6:
            args += " -6"

        try:
            nm.scan(hosts=target, arguments=args)

            for host in nm.all_hosts():
                host_data = {
                    "state": nm[host].state(),
                    "protocols": {},
                    "os": nm[host]["osmatch"] if "osmatch" in nm[host] else [],
                }

                # Gather port/service info
                for proto in nm[host].all_protocols():
                    ports = nm[host][proto].keys()
                    port_data = {}
                    for port in ports:
                        service = nm[host][proto][port]
                        entry = {
                            "state": service.get("state", ""),
                            "name": service.get("name", ""),
                            "product": service.get("product", ""),
                            "version": service.get("version", ""),
                            "extrainfo": service.get("extrainfo", ""),
                            "cpe": service.get("cpe", ""),
                            "vulns": []
                        }
                        if vuln_scan and "script" in service:
                            for script_name, output in service["script"].items():
                                entry["vulns"].append(f"{script_name}: {output}")
                        port_data[port] = entry
                    host_data["protocols"][proto] = port_data

                results[host] = host_data

                # --- Print and log output identically ---
                log(f"\n📊 Results for {host} (State: {host_data['state']})")

                for proto, ports in host_data["protocols"].items():
                    table = []
                    for port, info in ports.items():
                        table.append([
                            proto,
                            port,
                            info["state"],
                            info["name"],
                            f"{info['product']} {info['version']}".strip(),
                            info["cpe"]
                        ])
                    if table:
                        table_str = tabulate(
                            table,
                            headers=["Proto", "Port", "State", "Service", "Version", "CPE"],
                            tablefmt="grid"
                        )
                        log(table_str)

                    for port, info in ports.items():
                        if info["vulns"]:
                            log(f"\n   ⚠️  Vulnerabilities on {proto}/{port}:")
                            for vuln in info["vulns"]:
                                log(f"      - {vuln}")

                if host_data["os"]:
                    log("\n🖥️  OS Matches:")
                    for osmatch in host_data["os"]:
                        log(f"   - {osmatch['name']} ({osmatch['accuracy']}% confidence)")

        except Exception as e:
            log(f"❌ Error scanning {target}: {e}")

    return results



def save_json(results, filename):
    with open(filename, "w") as f:
        json.dump(results, f, indent=4)


def save_csv(results, filename):
    with open(filename, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["Host", "Proto", "Port", "State", "Service", "Version", "CPE", "Vulnerabilities"])
        for host, data in results.items():
            for proto, ports in data["protocols"].items():
                for port, info in ports.items():
                    writer.writerow([
                        host,
                        proto,
                        port,
                        info["state"],
                        info["name"],
                        f"{info['product']} {info['version']}".strip(),
                        info["cpe"],
                        "; ".join(info["vulns"]) if info["vulns"] else ""
                    ])


def save_txt(results, filename):
    with open(filename, "w", encoding="utf-8") as f:
        for host, data in results.items():
            f.write(f"Host: {host} (State: {data['state']})\n")
            for proto, ports in data["protocols"].items():
                for port, info in ports.items():
                    f.write(f"  {proto}/{port} {info['state']} {info['name']} {info['product']} {info['version']}\n")
                    if info["vulns"]:
                        f.write("    Vulnerabilities:\n")
                        for vuln in info["vulns"]:
                            f.write(f"      - {vuln}\n")
            if data["os"]:
                f.write("  OS Matches:\n")
                for osmatch in data["os"]:
                    f.write(f"    - {osmatch['name']} ({osmatch['accuracy']}% confidence)\n")
            f.write("\n")


def main():
    parser = argparse.ArgumentParser(description="Python-based Nmap Network Scanner")
    parser.add_argument("--file", help="File with list of targets (IP, subnet, or hostname)")
    parser.add_argument("--target", help="Single target (IP, subnet, or hostname)")
    parser.add_argument("--ipv6", action="store_true", help="Use IPv6 scanning")
    parser.add_argument("--vuln", action="store_true", help="Enable vulnerability scanning (Nmap NSE)")
    parser.add_argument("--output", help="Base name for output files", default="scan_results")
    args = parser.parse_args()

    # Load targets
    targets = load_targets(args.file, args.target)

    # Open TXT file for logging
    with open(f"{args.output}.txt", "w", encoding="utf-8") as txt_output:
        live_hosts = discover_hosts(targets, args.ipv6)
        if not live_hosts:
            txt_output.write("\n⚠️ No live hosts found. Exiting.\n")
            print("\n⚠️ No live hosts found. Exiting.")
            sys.exit(0)

        # Perform scan
        results = scan_targets(live_hosts, args.ipv6, args.vuln, txt_output)

    # Save JSON and CSV
    save_json(results, f"{args.output}.json")
    save_csv(results, f"{args.output}.csv")

    print(f"\n✅ Scan complete. Results saved as:")
    print(f"   - {args.output}.json (structured data)")
    print(f"   - {args.output}.csv (Excel-friendly)")
    print(f"   - {args.output}.txt (exact console output)")


if __name__ == "__main__":
    main()
