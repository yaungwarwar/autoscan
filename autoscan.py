#!/usr/bin/env python3
# autoscan - automatic fingerprint of visited networks
# 2013, Laurent Ghigonis at P1 Security <laurent@p1sec.com>
# 2024, Modernized for Python 3.12
"""
Original Author: Laurent Ghigonis (P1 Security, 2013)
Maintained by: [Your Name] (2024)
GitHub: github.com/yaungwarwar/autoscan
"""
import sys
import os
import time
import subprocess
import traceback
import re
import argparse
import shutil
import logging
import signal
from typing import List, Optional, Tuple

VERSION = "2.6"
DEFAULT_PUBIP = "8.8.8.8"

class Autoscan_iface:
    def __init__(self, iface: str, outdir: str = ".", logfile: Optional[str] = None,
                 loglevel: int = logging.INFO, target_pubip: str = DEFAULT_PUBIP,
                 noexplore: bool = False):
        """Initialize network interface scanner."""
        self.logger = logging.getLogger(f"Autoscan_{iface}")
        self.logger.setLevel(loglevel)
        
        # Remove any existing handlers
        for handler in self.logger.handlers[:]:
            self.logger.removeHandler(handler)
            
        # Configure handler
        if logfile:
            handler = logging.FileHandler(logfile)
        else:
            handler = logging.StreamHandler(sys.stdout)
            
        handler.setFormatter(logging.Formatter(
            '%(asctime)s %(message)s',
            datefmt="%Y%m%d-%H%M%S"
        ))
        self.logger.addHandler(handler)
        
        self.iface = iface
        self.outdir = os.path.abspath(outdir)
        self.target_pubip = target_pubip
        self.noexplore = noexplore
        self.date = None
        
        # Handle permissions
        if 'SUDO_UID' in os.environ and 'SUDO_GID' in os.environ:
            self.perm_uid = int(os.environ['SUDO_UID'])
            self.perm_gid = int(os.environ['SUDO_GID'])
        else:
            self.perm_uid = os.getuid()
            self.perm_gid = os.getgid()
        
        self.found_ip4 = None
        self.found_ip6 = None
        self.found_pubip = None
        self.found_dns = []
        self.found_essid = None

    def log(self, level: int, message: str) -> None:
        """Log a message at specified level."""
        self.logger.log(level, message)

    def run_now(self) -> None:
        """Run tests once and exit."""
        self._do_tests()

    def monitor(self) -> None:
        """Monitor interface and run tests when state changes."""
        while True:
            self._wait_up()
            self._do_tests()
            self._wait_down()

    def _wait_up(self) -> None:
        """Wait for interface to come up."""
        self.log(logging.INFO, "[>] _wait_up")
        while True:
            out, _, _ = self._exec(['ip', 'addr', 'show', self.iface])
            if 'UP' in out and re.search(r'inet (\d+\.\d+\.\d+\.\d+)', out):
                break
            time.sleep(0.5)
        time.sleep(3)

    def _wait_down(self) -> None:
        """Wait for interface to go down."""
        self.log(logging.INFO, "[>] _wait_down")
        last_ip = None
        while True:
            out, _, _ = self._exec(['ip', 'addr', 'show', self.iface])
            if 'UP' not in out:
                break
            ip_match = re.search(r'inet (\d+\.\d+\.\d+\.\d+)', out)
            current_ip = ip_match.group(1) if ip_match else None
            if current_ip and last_ip and current_ip != last_ip:
                break
            last_ip = current_ip
            time.sleep(0.5)

    def _do_tests(self) -> None:
        """Run all configured tests."""
        self.log(logging.INFO, "[>] _do_tests")
        self.date = time.strftime("%Y%m%d_%H%M%S", time.gmtime())
        
        tests = [
            self._test_pcap,
            self._test_ifconfig,
            self._test_iwconfig,
            self._test_route,
            self._test_resolv,
            self._test_pubip_get,
            self._test_pubip_ping,
            self._test_pubip_traceroute,
            self._test_resolv_traceroute
        ]
        
        if not self.noexplore:
            tests.extend([
                self._test_explor_traceroute,
                self._test_explor_scan
            ])
        
        for test in tests:
            self._do_tests_run(test)
        
        self._storepath_rename()

    def _do_tests_run(self, func) -> None:
        """Run a test with error handling."""
        try:
            self.log(logging.INFO, f"[-] {func.__name__}")
            func()
        except Exception as e:
            self.log(logging.ERROR, f"[!] {func.__name__} failed: {e}")

    def _test_pcap(self) -> None:
        """Capture network traffic."""
        pid = os.fork()
        if pid == 0:  # Child
            try:
                pcap_file = self._storepath_get("pcap/tcpdump.pcap")
                os.makedirs(os.path.dirname(pcap_file), exist_ok=True)
                subprocess.run([
                    "tcpdump",
                    "-ni", self.iface,
                    "-w", pcap_file,
                    "-G", "15",
                    "-W", "1"
                ], check=True)
            finally:
                sys.exit(0)

    def _test_ifconfig(self) -> None:
        """Collect interface configuration."""
        out, _, _ = self._exec(['ip', 'addr', 'show', self.iface])
        self._store("ifconfig/out", out)
        
        if 'UP' in out:
            self._store("ifconfig/up", "")
            
        ip4 = re.search(r'inet (\d+\.\d+\.\d+\.\d+)', out)
        if ip4:
            self._store("ifconfig/ip4", ip4.group(1))
            self.found_ip4 = ip4.group(1)
            
        ip6 = re.search(r'inet6 ([a-f0-9:]+)', out, re.I)
        if ip6:
            self._store("ifconfig/ip6", ip6.group(1))
            self.found_ip6 = ip6.group(1)

    def _test_iwconfig(self) -> None:
        """Collect wireless interface information."""
        self.found_essid = None
        out, _, _ = self._exec(['iwconfig', self.iface])
        
        if not out:
            return  # Not a wireless interface
            
        self._store("iwconfig/out", out)
        
        essid = re.search(r'ESSID:"([^"]+)"', out)
        if essid:
            self.found_essid = essid.group(1)
            self._store("iwconfig/essid", self.found_essid)
            
        ap = re.search(r'Access Point: ([0-9A-Fa-f:]{17})', out)
        if ap:
            self._store("iwconfig/ap", ap.group(1))

    def _test_route(self) -> None:
        """Collect routing information."""
        out, _, _ = self._exec(['ip', 'route'])
        self._store("route/out", out)
        
        default_route = next((line for line in out.splitlines() if 'default via' in line), None)
        if default_route:
            gw = default_route.split()[2]
            self._store("route/gw", gw)

    def _test_resolv(self) -> None:
        """Collect DNS resolver information."""
        try:
            resolv_path = self._storepath_get("resolv/resolv.conf")
            os.makedirs(os.path.dirname(resolv_path), exist_ok=True)
            shutil.copy("/etc/resolv.conf", resolv_path)
            with open("/etc/resolv.conf") as f:
                for i, line in enumerate(f):
                    match = re.search(r'nameserver\s+(\S+)', line)
                    if match:
                        dns = match.group(1)
                        self._store(f"resolv/dns{i}", dns)
                        self.found_dns.append(dns)
        except Exception as e:
            self.log(logging.WARNING, f"Failed to read resolv.conf: {e}")

    def _test_pubip_get(self) -> None:
        """Determine public IP address."""
        out, _, _ = self._exec(['curl', '--silent', '--max-time', '5', 'ifconfig.me'])
        
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', out.strip()):
            self._store("pubip_get/ip", out.strip())
            self.found_pubip = out.strip()
        else:
            self._store("pubip_get/out", out)
            self.found_pubip = None

    def _test_pubip_ping(self) -> None:
        """Test connectivity to public IP."""
        out, _, code = self._exec(['ping', '-c', '3', '-W', '2', self.target_pubip])
        self._store("pubip_ping/code", str(code))
        self._store("pubip_ping/out", out)

    def _test_pubip_traceroute(self) -> None:
        """Trace route to public IP."""
        out, _, _ = self._exec(['traceroute', '-w', '1', '-q', '1', '-n', self.target_pubip])
        self._store("pubip_traceroute/out", out)

    def _test_resolv_traceroute(self) -> None:
        """Trace route to DNS servers."""
        for dns in self.found_dns:
            out, _, _ = self._exec(['traceroute', '-w', '1', '-q', '1', '-n', dns])
            self._store(f"resolv_traceroute/out_{dns}", out)

    def _test_explor_traceroute(self) -> None:
        """Exploratory traceroute to common private ranges."""
        targets = ["192.168.0.1", "192.168.1.1", "10.0.0.1", "172.16.0.1"]
        for target in targets:
            out, _, _ = self._exec(['traceroute', '-w', '1', '-q', '1', '-n', target])
            self._store(f"explor_traceroute/out_{target}", out)

    def _test_explor_scan(self) -> None:
        """Exploratory network scan."""
        if not self.found_ip4:
            self.log(logging.ERROR, "No IP address found")
            return
            
        network = re.sub(r'\.\d+$', '.0/24', self.found_ip4)
        scan_dir = self._storepath_get("explor_scan")
        os.makedirs(scan_dir, exist_ok=True)
        
        try:
            out, err, _ = self._exec([
                'nmap',
                '-oA', os.path.join(scan_dir, 'localnet'),
                '-p', '21,22,23,80,443,445,8080-8083',
                '--max-retries', '1',
                '--host-timeout', '2m',
                network
            ])
            self._store("explor_scan/out", out)
            if err:
                self._store("explor_scan/err", err)
        except Exception as e:
            self.log(logging.ERROR, f"Nmap scan failed: {e}")

    def _exec(self, cmd: List[str]) -> Tuple[str, str, int]:
        """Execute a command and return output."""
        try:
            result = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False
            )
            return result.stdout, result.stderr, result.returncode
        except Exception as e:
            return "", str(e), -1

    def _store(self, suffix: str, txt: str = '') -> None:
        """Store data in output directory."""
        path = self._storepath_get(suffix)
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, 'w') as f:
                f.write(str(txt))
            os.chown(path, self.perm_uid, self.perm_gid)
        except Exception as e:
            self.log(logging.ERROR, f"Failed to store {suffix}: {e}")

    def _storepath_get(self, suffix: str = None) -> str:
        """Get path for storing results."""
        path = os.path.join(self.outdir, f"{self.date}_{self.iface}")
        if suffix:
            path = os.path.join(path, suffix)
        return path

    def _storepath_rename(self) -> None:
        """Rename output directory with network info."""
        if not (self.found_pubip or self.found_ip4):
            return
            
        suffix = self.found_pubip if self.found_pubip else self.found_ip4
        if self.found_essid:
            suffix += f"_{self.found_essid}"
            
        old_path = self._storepath_get()
        new_path = f"{old_path}_{suffix}"
        
        if not os.path.exists(old_path):
            return
            
        try:
            os.rename(old_path, new_path)
            self.log(logging.INFO, f"[*] {new_path}")
        except OSError as e:
            self.log(logging.ERROR, f"Rename failed: {e}")

def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Automatic network fingerprinting tool",
        epilog=f"Example: sudo {sys.argv[0]} wlan0 -r -o ./scan_results"
    )
    parser.add_argument("interfaces", nargs='+', help="Network interfaces")
    parser.add_argument("-m", "--monitor", action="store_true", help="Continuous monitoring")
    parser.add_argument("-r", "--runnow", action="store_true", help="Run once and exit")
    parser.add_argument("-b", "--background", action="store_true", help="Run in background")
    parser.add_argument("-o", "--outdir", default=".", help="Output directory")
    parser.add_argument("-x", "--noexplore", action="store_true", help="Skip exploratory scans")
    parser.add_argument("-p", "--pubip", default=DEFAULT_PUBIP, help="Target IP for tests")
    parser.add_argument("-q", "--quiet", action="store_true", help="Quiet mode")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    
    args = parser.parse_args()
    
    # Validate arguments
    if args.runnow and args.monitor:
        parser.error("Cannot specify both monitor and runnow modes")
    if args.runnow and args.background:
        parser.error("Cannot run in background with runnow mode")
    if args.verbose and args.quiet:
        parser.error("Cannot specify both verbose and quiet modes")
        
    # Set defaults
    if not args.runnow and not args.monitor:
        args.runnow = True
        
    # Configure logging
    loglevel = logging.DEBUG if args.verbose else (
        logging.WARNING if args.quiet else logging.INFO
    )
    
    # Verify root
    if not os.geteuid() == 0:
        parser.error("must be run as root")
    
    # Main execution
    for iface in args.interfaces:
        pid = os.fork()
        if pid == 0:  # Child
            scanner = Autoscan_iface(
                iface,
                args.outdir,
                logfile=f"autoscan_{iface}.log" if args.background else None,
                loglevel=loglevel,
                target_pubip=args.pubip,
                noexplore=args.noexplore
            )
            
            if args.runnow:
                scanner.run_now()
            else:
                scanner.monitor()
            
            sys.exit(0)
    
    if not args.background:
        while True:
            try:
                os.wait()
            except ChildProcessError:
                break

if __name__ == "__main__":
    main()

