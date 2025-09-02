#!/usr/bin/env python3
import nmap
import argparse
import json
import os
import sys

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


def scan_targets(targets, use_ipv6=False, vuln_scan=False):
    nm = nmap.PortScanner()
    results = {}

    for target in targets:
        print(f"\n🔍 Scanning target: {target} (IPv6: {use_ipv6})...")
        args = "-sV -O -Pn"  # Service + OS detection, skip ping
        if vuln_scan:
            args += " --script vuln"  # run vulnerability NSE scripts
        if use_ipv6:
            args += " -6"

        try:
            nm.scan(hosts=target, arguments=args)

            for host in nm.all_hosts():
                host_data = {
                    "state": nm[host].state(),
                    "protocols": {},
                    "os": nm[host]["osmatch"] if "osmatch" in nm[host] else []
                }

                for proto in nm[host].all_protocols():
                    ports = nm[host][proto].keys()
                    port_data = {}
                    for port in ports:
                        service = nm[host][proto][port]
                        port_data[port] = {
                            "state": service.get("state", ""),
                            "name": service.get("name", ""),
                            "product": service.get("product", ""),
                            "version": service.get("version", ""),
                            "extrainfo": service.get("extrainfo", ""),
                            "cpe": service.get("cpe", "")
                        }
                    host_data["protocols"][proto] = port_data

                results[host] = host_data

        except Exception as e:
            print(f"❌ Error scanning {target}: {e}")

    return results


def main():
    parser = argparse.ArgumentParser(description="Python-based Nmap Network Scanner")
    parser.add_argument("--file", help="File with list of targets (IP, subnet, or hostname)")
    parser.add_argument("--target", help="Single target (IP, subnet, or hostname)")
    parser.add_argument("--ipv6", action="store_true", help="Use IPv6 scanning")
    parser.add_argument("--vuln", action="store_true", help="Enable vulnerability scanning (Nmap NSE)")
    parser.add_argument("--output", help="Save results to JSON file", default="scan_results.json")
    args = parser.parse_args()

    targets = load_targets(args.file, args.target)
    results = scan_targets(targets, args.ipv6, args.vuln)

    # Save results
    with open(args.output, "w") as f:
        json.dump(results, f, indent=4)

    print(f"\n✅ Scan complete. Results saved to {args.output}")


if __name__ == "__main__":
    main()
