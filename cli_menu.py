#!/usr/bin/env python3
"""
Server Admin Toolkit
© 2025 – MIT License
Tested on Ubuntu 20.04 → 24.04

Main modules
============
1) Network          – DNS switcher, Unbound installer, speed-test
2) System Settings  – NTP sync, distro info, htop, backup wizard
3) Security         – SSH-port changer, ICMP toggle, SSL, status
4) Webserver        – Nginx & Apache install / restart / v-host

"""

from __future__ import annotations
import os, sys, platform, subprocess, re
from datetime import datetime
from textwrap import dedent
from pathlib import Path
from typing import Dict, List

# ────────────────────────── colours / helpers ──────────────────────────
OK, ERR, RESET = "\033[1;92m", "\033[1;31m", "\033[0m"

def clear() -> None:
    os.system("clear" if os.name == "posix" else "cls")

def pause() -> None:
    input("\nPress Enter to continue…")

def run(cmd: List[str], desc: str, interactive: bool = False) -> None:
    print(f"→ {desc}…", end=" ")
    try:
        if interactive:
            subprocess.check_call(cmd)
        else:
            subprocess.check_call(cmd,
                                  stdout=subprocess.DEVNULL,
                                  stderr=subprocess.DEVNULL)
        print(f"{OK}✅{RESET}")
    except subprocess.CalledProcessError as e:
        print(f"{ERR}❌{RESET}\n   {e}")

# ───────────────────── banner (public IP / ISP) ────────────────────────
try:
    import requests       # optional
except ModuleNotFoundError:
    requests = None

def ip_info() -> Dict[str, str]:
    default = {"ip": "Unknown", "isp": "Unknown", "country": "Unknown"}
    if requests is None:
        return default
    try:
        j = requests.get("https://ipinfo.io/json", timeout=4).json()
        return {"ip": j.get("ip", "N/A"),
                "isp": j.get("org", "N/A"),
                "country": j.get("country", "N/A")}
    except Exception:
        return default

# ══════════════════════════ NETWORK ════════════════════════════════════
def apply_dns(ns: List[str]) -> None:
    run(["sudo", "systemctl", "stop", "systemd-resolved"], "Stop systemd-resolved")
    run(["sudo", "systemctl", "disable", "systemd-resolved"], "Disable systemd-resolved")
    run(["sudo", "rm", "-f", "/etc/resolv.conf"], "Remove old resolv.conf")
    lines = "\n".join(f"nameserver {x}" for x in ns) + "\n"
    run(["sudo", "bash", "-c", f"echo '{lines}' > /etc/resolv.conf"], "Write resolv.conf")
    run(["sudo", "chattr", "+i", "/etc/resolv.conf"], "Lock resolv.conf")
    pause()

def dns_menu() -> None:
    while True:
        clear()
        print("DNS PROVIDERS")
        print("1) Google           8.8.8.8 / 8.8.4.4")
        print("2) Cloudflare       1.1.1.1 / 1.0.0.1")
        print("3) Shecan           185.51.200.2 / 178.22.122.100")
        print("4) Dynx             10.70.95.150 / 10.70.95.162")
        print("0) Back")
        ch = input("\nSelect #: ").strip()
        if ch == "1": apply_dns(["8.8.8.8", "8.8.4.4"])
        elif ch == "2": apply_dns(["1.1.1.1", "1.0.0.1"])
        elif ch == "3": apply_dns(["185.51.200.2", "178.22.122.100"])
        elif ch == "4": apply_dns(["10.70.95.150", "10.70.95.162"])
        elif ch == "0": return
        else: pause()

UNBOUND_CONF = dedent("""
server:
    cache-max-ttl: 86400
    cache-min-ttl: 3600
    prefetch: yes
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
    run(["sudo", "apt", "install", "unbound", "-y"], "Install unbound")
    run(["sudo", "bash", "-c", f"echo '{UNBOUND_CONF}' > /etc/unbound/unbound.conf"],
        "Write unbound.conf")
    run(["sudo", "unbound-checkconf"], "Check config", True)
    run(["sudo", "systemctl", "restart", "unbound"], "Restart unbound")
    apply_dns(["127.0.0.1", "::1"])
    pause()

def speedtest() -> None:
    clear()
    run(["bash", "-c", "wget -qO- bench.sh | bash"], "Run bench.sh", True)
    pause()

def network_menu() -> None:
    while True:
        clear()
        print("NETWORK MENU")
        print("1) DNS switcher")
        print("2) Install & configure Unbound")
        print("3) Speed-test (bench.sh)")
        print("0) Back")
        ch = input("\nSelect #: ").strip()
        if ch == "1": dns_menu()
        elif ch == "2": install_unbound()
        elif ch == "3": speedtest()
        elif ch == "0": return
        else: pause()

# ═══════════════════════ SYSTEM SETTINGS ═══════════════════════════════
def time_sync() -> None:
    clear()
    run(["sudo", "timedatectl", "set-ntp", "true"], "Enable NTP")
    run(["sudo", "apt", "install", "ntpdate", "-y"], "Install ntpdate")
    run(["sudo", "ntpdate", "-u", "pool.ntp.org"], "Immediate sync")
    pause()

def distro_info() -> None:
    clear()
    run(["lsb_release", "-a"], "Distro info", True)
    pause()

def htop_live() -> None:
    clear()
    run(["sudo", "apt", "install", "htop", "-y"], "Install htop")
    run(["htop"], "Launch htop", True)
    pause()

# Backup launcher – uses external script in repo
BASE_DIR = Path(__file__).resolve().parent
BACKUPER = BASE_DIR / "backuper_menu.sh"

def backup_menu() -> None:
    clear()
    if not BACKUPER.exists():
        print(f"{ERR}backuper_menu.sh not found!{RESET}")
        pause()
        return
    run(["sudo", "chmod", "+x", str(BACKUPER)], "Ensure executable")
    run(["sudo", str(BACKUPER)], "Run backup wizard", True)
    pause()

def system_menu() -> None:
    while True:
        clear()
        print("SYSTEM SETTINGS")
        print("1) Sync Time/Date")
        print("2) Distro info")
        print("3) Live status (htop)")
        print("4) Backup wizard")
        print("0) Back")
        ch = input("\nSelect #: ").strip()
        if ch == "1": time_sync()
        elif ch == "2": distro_info()
        elif ch == "3": htop_live()
        elif ch == "4": backup_menu()
        elif ch == "0": return
        else: pause()

# ════════════════════════ SECURITY ═════════════════════════════════════
def change_ssh_port() -> None:
    clear()
    new_port = input("New SSH port (1-65535): ").strip()
    if not new_port.isdigit() or not 1 <= int(new_port) <= 65535:
        pause(); return
    run(["sudo", "sed", "-i",
         rf"s/^#?Port .*/Port {new_port}/", "/etc/ssh/sshd_config"],
        f"Set Port {new_port}")
    run(["sudo", "ufw", "allow", f"{new_port}/tcp"], "Open port in UFW")
    run(["sudo", "systemctl", "restart", "ssh"], "Restart SSH")
    pause()

def icmp_toggle(active: bool) -> None:
    val = "0" if active else "1"
    run(["sudo", "bash", "-c", f"echo {val} > /proc/sys/net/ipv4/icmp_echo_ignore_all"],
        "Runtime ICMP toggle")
    run(["sudo", "bash", "-c",
         f"grep -q '^net.ipv4.icmp_echo_ignore_all' /etc/sysctl.conf && "
         f"sudo sed -i 's/^net.ipv4.icmp_echo_ignore_all.*/net.ipv4.icmp_echo_ignore_all = {val}/' /etc/sysctl.conf || "
         f"echo 'net.ipv4.icmp_echo_ignore_all = {val}' | sudo tee -a /etc/sysctl.conf"],
        "Persist in sysctl")
    run(["sudo", "sysctl", "-p"], "Reload sysctl")
    pause()

def icmp_menu() -> None:
    while True:
        clear()
        print("ICMP (Ping)")
        print("1) Enable ping")
        print("2) Disable ping")
        print("0) Back")
        ch = input("\nSelect #: ").strip()
        if ch == "1": icmp_toggle(True)
        elif ch == "2": icmp_toggle(False)
        elif ch == "0": return
        else: pause()

def self_ssl() -> None:
    clear()
    run(["sudo", "apt", "install", "openssl", "-y"], "Install openssl")
    run(["openssl", "genpkey", "-algorithm", "RSA", "-out", "server.key",
         "-pkeyopt", "rsa_keygen_bits:2048"], "Generate key")
    run(["openssl", "req", "-new", "-key", "server.key", "-out", "server.csr"],
        "Generate CSR", True)
    run(["openssl", "x509", "-req", "-in", "server.csr", "-signkey", "server.key",
         "-out", "server.crt", "-days", "365"], "Sign certificate")
    pause()

def certbot_ssl() -> None:
    clear()
    email = input("Email: ").strip()
    domain = input("Domain: ").strip()
    if not re.match(r"^[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$", domain):
        pause(); return
    run(["sudo", "apt", "install", "certbot", "-y"], "Install certbot")
    run(["sudo", "certbot", "certonly", "--standalone",
         "--preferred-challenges", "http", "-d", domain,
         "--email", email, "--agree-tos", "--noninteractive"],
        "Obtain certificate", True)
    pause()

def ssl_menu() -> None:
    while True:
        clear()
        print("SSL CERTIFICATES")
        print("1) Self-signed (OpenSSL)")
        print("2) Certbot (Let's Encrypt)")
        print("0) Back")
        ch = input("\nSelect #: ").strip()
        if ch == "1": self_ssl()
        elif ch == "2": certbot_ssl()
        elif ch == "0": return
        else: pause()

def ufw_fail2ban() -> None:
    clear()
    run(["sudo", "ufw", "status"], "UFW status", True)
    run(["sudo", "fail2ban-client", "status"], "Fail2Ban status", True)
    pause()

def security_menu() -> None:
    while True:
        clear()
        print("SECURITY MENU")
        print("1) Change SSH port")
        print("2) ICMP toggle")
        print("3) SSL certificates")
        print("4) Show UFW & Fail2Ban")
        print("0) Back")
        ch = input("\nSelect #: ").strip()
        if ch == "1": change_ssh_port()
        elif ch == "2": icmp_menu()
        elif ch == "3": ssl_menu()
        elif ch == "4": ufw_fail2ban()
        elif ch == "0": return
        else: pause()

# ═══════════════════════ WEBSERVER ══════════════════════════════════════
def install_pkg(pkg: str) -> None:
    run(["sudo", "apt", "update", "-y"], "apt update")
    run(["sudo", "apt", "install", pkg, "-y"], f"Install {pkg}")

def svc(service: str, action: str) -> None:
    run(["sudo", "systemctl", action, service], f"{action.capitalize()} {service}")

def nginx_vhost() -> None:
    clear()
    domain = input("Domain: ").strip()
    if not re.match(r"^[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$", domain):
        pause(); return
    root = input(f"Document root [/var/www/{domain}]: ").strip() or f"/var/www/{domain}"
    conf = f"/etc/nginx/sites-available/{domain}.conf"
    if os.path.exists(conf):
        print("Config already exists"); pause(); return
    run(["sudo", "mkdir", "-p", root], "Create root")
    server_block = f\"\"\"\nserver {{\n    listen 80;\n    server_name {domain};\n    root {root};\n    index index.html index.htm;\n    location / {{ try_files $uri $uri/ =404; }}\n}}\"\"\"\n    run(["sudo", "bash", "-c", f"echo '{server_block}' > {conf}"], "Write v-host")
    run(["sudo", "ln", "-s", conf, f"/etc/nginx/sites-enabled/{domain}.conf"], "Enable site")
    run(["sudo", "nginx", "-t"], "Nginx test", True)
    svc("nginx", "reload")
    pause()

def apache_vhost() -> None:
    clear()
    domain = input("Domain: ").strip()
    if not re.match(r"^[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$", domain):
        pause(); return
    root = input(f"Document root [/var/www/{domain}]: ").strip() or f"/var/www/{domain}"
    conf = f"/etc/apache2/sites-available/{domain}.conf"
    if os.path.exists(conf):
        print("Config already exists"); pause(); return
    run(["sudo", "mkdir", "-p", root], "Create root")
    vhost = f\"\"\"\n<VirtualHost *:80>\n    ServerName {domain}\n    DocumentRoot {root}\n    <Directory {root}>\n        Options Indexes FollowSymLinks\n        AllowOverride All\n        Require all granted\n    </Directory>\n    ErrorLog ${APACHE_LOG_DIR}/{domain}_error.log\n    CustomLog ${APACHE_LOG_DIR}/{domain}_access.log combined\n</VirtualHost>\"\"\"\n    run(["sudo", "bash", "-c", f"echo '{vhost}' > {conf}"], "Write v-host")
    run(["sudo", "a2ensite", f"{domain}.conf"], "Enable site")
    run(["sudo", "apache2ctl", "configtest"], "Apache test", True)
    svc("apache2", "reload")
    pause()

def web_menu() -> None:
    while True:
        clear()
        print("WEBSERVER MENU")
        print("1) Install Nginx          2) Nginx status")
        print("3) Nginx restart          4) Nginx stop")
        print("5) Install Apache         6) Apache status")
        print("7) Apache restart         8) Apache stop")
        print("9) Setup Nginx v-host     10) Setup Apache v-host")
        print("0) Back")
        ch = input("\nSelect #: ").strip()
        if ch == "1": install_pkg("nginx"); pause()
        elif ch == "2": svc("nginx", "status"); pause()
        elif ch == "3": svc("nginx", "restart"); pause()
        elif ch == "4": svc("nginx", "stop"); pause()
        elif ch == "5": install_pkg("apache2"); pause()
        elif ch == "6": svc("apache2", "status"); pause()
        elif ch == "7": svc("apache2", "restart"); pause()
        elif ch == "8": svc("apache2", "stop"); pause()
        elif ch == "9": nginx_vhost()
        elif ch == "10": apache_vhost()
        elif ch == "0": return
        else: pause()

# ═════════════════════════ MAIN MENU ════════════════════════════════════
def main() -> None:
    info = ip_info()
    while True:
        clear()
        print("############################################")
        print("               SERVER INFO")
        print(f"IP      : {info['ip']}")
        print(f"ISP     : {info['isp']}")
        print(f"Country : {info['country']}")
        print("############################################")
        print("MAIN MENU")
        print("1) Network")
        print("2) System Settings")
        print("3) Security")
        print("4) Webserver")
        print("0) Exit")
        ch = input("\nSelect #: ").strip()
        if ch == "1": network_menu()
        elif ch == "2": system_menu()
        elif ch == "3": security_menu()
        elif ch == "4": web_menu()
        elif ch == "0": sys.exit(0)
        else: pause()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nInterrupted")
