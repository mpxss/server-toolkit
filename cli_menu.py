#!/usr/bin/env python3
"""
Server-Toolkit – Interactive CLI for Ubuntu 20.04 +
MIT © 2025 | https://github.com/mpxss
"""

from __future__ import annotations
import os, sys, subprocess, re
from datetime import datetime
from textwrap import dedent
from typing import List, Dict

# ── ANSI colors ────────────────────────────────────────────
OK, ERR, END = "\033[1;92m", "\033[1;31m", "\033[0m"

clear   = lambda: os.system("clear" if os.name == "posix" else "cls")
pause   = lambda: input("\nPress <Enter> to continue...")

def run(cmd: List[str], desc: str, interactive: bool = False) -> None:
    """Run shell command and print ✅ / ❌."""
    print(f"→ {desc}...", end=" ")
    try:
        if interactive:
            subprocess.check_call(cmd)
        else:
            subprocess.check_call(cmd,
                                  stdout=subprocess.DEVNULL,
                                  stderr=subprocess.DEVNULL)
        print(f"{OK}✅{END}")
    except subprocess.CalledProcessError as e:
        print(f"{ERR}❌{END}")
        if not interactive:
            print("   ", e)

# ── Public IP banner (ifconfig.co) ─────────────────────────
def ip_info() -> Dict[str, str]:
    try:
        import requests
        data = requests.get("https://ifconfig.co/json", timeout=4).json()
        return {
            "ip":  data.get("ip", "-"),
            "isp": data.get("asn_org", "-"),
            "cty": data.get("country_iso", "-")
        }
    except Exception:
        return {"ip": "-", "isp": "-", "cty": "-"}

# ═════════════════════════ NETWORK ═════════════════════════
def apply_dns(servers: List[str]) -> None:
    run(["sudo", "systemctl", "stop", "systemd-resolved"],
        "Stop systemd-resolved")
    run(["sudo", "systemctl", "disable", "systemd-resolved"],
        "Disable systemd-resolved")
    run(["sudo", "rm", "-f", "/etc/resolv.conf"], "Remove resolv.conf")
    lines = "\n".join(f"nameserver {s}" for s in servers) + "\n"
    run(["sudo", "bash", "-c",
         f"echo -e '{lines}' > /etc/resolv.conf"],
        "Write resolv.conf")
    run(["sudo", "chattr", "+i", "/etc/resolv.conf"], "Lock file")
    pause()

def dns_menu() -> None:
    while True:
        clear()
        print("DNS PROVIDERS")
        print("1) Google        8.8.8.8 / 8.8.4.4")
        print("2) Cloudflare    1.1.1.1 / 1.0.0.1")
        print("3) Shecan        185.51.200.2 / 178.22.122.100")
        print("4) Dynx          10.70.95.150 / 10.70.95.162")
        print("0) Back")
        choice = input("\nSelect #: ").strip()
        if   choice == "1": apply_dns(["8.8.8.8", "8.8.4.4"])
        elif choice == "2": apply_dns(["1.1.1.1", "1.0.0.1"])
        elif choice == "3": apply_dns(["185.51.200.2", "178.22.122.100"])
        elif choice == "4": apply_dns(["10.70.95.150", "10.70.95.162"])
        elif choice == "0": return
        else: pause()

UNBOUND_CFG = dedent("""
server:
  interface: 127.0.0.1
  interface: ::1
  port: 53

forward-zone:
  name: "."
  forward-addr: 8.8.8.8
  forward-addr: 1.1.1.1
""")

def install_unbound() -> None:
    clear()
    run(["sudo", "apt", "install", "unbound", "-y"], "Install Unbound")
    run(["sudo", "bash", "-c",
         f"echo '{UNBOUND_CFG}' > /etc/unbound/unbound.conf"],
        "Write configuration")
    run(["sudo", "unbound-checkconf"], "Validate config", True)
    run(["sudo", "systemctl", "restart", "unbound"], "Restart Unbound")
    apply_dns(["127.0.0.1", "::1"])

def speed_test() -> None:
    clear()
    run(["bash", "-c", "wget -qO- bench.sh | bash"], "Run speed test", True)
    pause()

def network_menu() -> None:
    while True:
        clear()
        print("NETWORK MENU")
        print("1) DNS switcher")
        print("2) Install & configure Unbound")
        print("3) Network speed-test")
        print("0) Back")
        c = input("\nSelect #: ").strip()
        if   c == "1": dns_menu()
        elif c == "2": install_unbound()
        elif c == "3": speed_test()
        elif c == "0": return
        else: pause()

# ═════════════════════ SYSTEM SETTINGS ═════════════════════
def sync_time() -> None:
    clear()
    run(["sudo", "timedatectl", "set-ntp", "true"], "Enable NTP")
    run(["sudo", "apt", "install", "ntpdate", "-y"], "Install ntpdate")
    run(["sudo", "ntpdate", "-u", "pool.ntp.org"], "Sync time")
    print("Current time:", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    pause()

def distro_info() -> None:
    clear()
    run(["lsb_release", "-a"], "Distribution info", True)
    pause()

def htop_live() -> None:
    clear()
    run(["sudo", "apt", "install", "htop", "-y"], "Install htop")
    run(["htop"], "Launch htop", True)
    pause()

def system_menu() -> None:
    while True:
        clear()
        print("SYSTEM SETTINGS")
        print("1) Sync time/date")
        print("2) Distribution info")
        print("3) Live status (htop)")
        print("0) Back")
        c = input("\nSelect #: ").strip()
        if   c == "1": sync_time()
        elif c == "2": distro_info()
        elif c == "3": htop_live()
        elif c == "0": return
        else: pause()

# ═════════════════════ SECURITY ════════════════════════════
def change_ssh_port() -> None:
    clear()
    p = input("New SSH port (1-65535): ").strip()
    if not p.isdigit() or not 1 <= int(p) <= 65535:
        pause(); return
    run(["sudo", "sed", "-i",
         rf"s/^#?Port .*/Port {p}/", "/etc/ssh/sshd_config"],
        "Set new port")
    run(["sudo", "ufw", "allow", f"{p}/tcp"], "Allow port in UFW")
    run(["sudo", "systemctl", "restart", "ssh"], "Restart SSH")
    pause()

def toggle_ping(enable: bool) -> None:
    val = "0" if enable else "1"
    run(["sudo", "bash", "-c",
         f"echo {val} > /proc/sys/net/ipv4/icmp_echo_ignore_all"],
        "Apply runtime change")
    run(["sudo", "sysctl", "-w",
         f"net.ipv4.icmp_echo_ignore_all={val}"], "Persist setting")
    pause()

def self_ssl() -> None:
    clear()
    run(["sudo", "apt", "install", "openssl", "-y"], "Install OpenSSL")
    run(["openssl", "req", "-x509", "-nodes", "-days", "365",
         "-newkey", "rsa:2048", "-keyout", "server.key",
         "-out", "server.crt"], "Generate self-signed certificate", True)
    pause()

def ufw_status() -> None:
    clear()
    run(["sudo", "ufw", "status"], "UFW status", True)
    pause()

def security_menu() -> None:
    while True:
        clear()
        print("SECURITY MENU")
        print("1) Change SSH port")
        print("2) Enable ICMP (ping)")
        print("3) Disable ICMP (ping)")
        print("4) Generate self-signed SSL")
        print("5) UFW status")
        print("0) Back")
        c = input("\nSelect #: ").strip()
        if   c == "1": change_ssh_port()
        elif c == "2": toggle_ping(True)
        elif c == "3": toggle_ping(False)
        elif c == "4": self_ssl()
        elif c == "5": ufw_status()
        elif c == "0": return
        else: pause()

# ═════════════════════ WEBSERVER ═══════════════════════════
apt = lambda pkg: run(["sudo", "apt", "install", pkg, "-y"],
                      f"Install {pkg}")
svc = lambda s, a: run(["sudo", "systemctl", a, s],
                       f"{a.capitalize()} {s}")

def nginx_vhost() -> None:
    clear()
    domain = input("Domain name: ").strip()
    if not re.match(r"^[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$", domain):
        pause(); return
    root = f"/var/www/{domain}"
    conf = f"/etc/nginx/sites-available/{domain}.conf"
    run(["sudo", "mkdir", "-p", root], "Create docroot")
    block = f"""
server {{
    listen 80;
    server_name {domain};
    root {root};
    index index.html index.htm;
    location / {{
        try_files $uri $uri/ =404;
    }}
}}
"""
    run(["sudo", "bash", "-c", f"echo '{block}' > {conf}"], "Write vhost")
    run(["sudo", "ln", "-s", conf,
         f"/etc/nginx/sites-enabled/{domain}.conf"], "Enable site")
    run(["sudo", "nginx", "-t"], "Test config", True)
    svc("nginx", "reload")
    pause()

def apache_vhost() -> None:
    clear()
    domain = input("Domain name: ").strip()
    if not re.match(r"^[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$", domain):
        pause(); return
    root = f"/var/www/{domain}"
    conf = f"/etc/apache2/sites-available/{domain}.conf"
    run(["sudo", "mkdir", "-p", root], "Create docroot")
    vhost = f"""
<VirtualHost *:80>
    ServerName {domain}
    DocumentRoot {root}
    <Directory {root}>
        AllowOverride All
        Require all granted
    </Directory>
</VirtualHost>
"""
    run(["sudo", "bash", "-c", f"echo '{vhost}' > {conf}"], "Write vhost")
    run(["sudo", "a2ensite", f"{domain}.conf"], "Enable site")
    run(["sudo", "apache2ctl", "configtest"], "Test config", True)
    svc("apache2", "reload")
    pause()

def web_menu() -> None:
    while True:
        clear()
        print("WEBSERVER MENU")
        print("1) Install Nginx    2) Nginx status    3) Nginx restart   4) Nginx stop")
        print("5) Install Apache   6) Apache status   7) Apache restart  8) Apache stop")
        print("9) Nginx v-host    10) Apache v-host   0) Back")
        c = input("\nSelect #: ").strip()
        if   c == "1": apt("nginx"); pause()
        elif c == "2": svc("nginx", "status"); pause()
        elif c == "3": svc("nginx", "restart"); pause()
        elif c == "4": svc("nginx", "stop"); pause()
        elif c == "5": apt("apache2"); pause()
        elif c == "6": svc("apache2", "status"); pause()
        elif c == "7": svc("apache2", "restart"); pause()
        elif c == "8": svc("apache2", "stop"); pause()
        elif c == "9": nginx_vhost()
        elif c == "10": apache_vhost()
        elif c == "0": return
        else: pause()

# ═════════════════════ MAIN LOOP ═══════════════════════════
def main() -> None:
    banner = ip_info()
    while True:
        clear()
        print("############################################")
        print(f" IP: {banner['ip']} | ISP: {banner['isp']} | {banner['cty']}")
        print("############################################")
        print("1) Network 🌐  2) System ⚙️  3) Security 🔒  4) Webserver 🕸️  0) Exit")
        c = input("\nSelect #: ").strip()
        if   c == "1": network_menu()
        elif c == "2": system_menu()
        elif c == "3": security_menu()
        elif c == "4": web_menu()
        elif c == "0": sys.exit(0)
        else: pause()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nInterrupted.")
