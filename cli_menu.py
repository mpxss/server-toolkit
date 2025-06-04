#!/usr/bin/env python3
"""
Server-Toolkit  –  Interactive CLI for Ubuntu 20.04+
MIT © 2025 | https://github.com/mpxss/server-toolkit
"""

from __future__ import annotations
import os, sys, subprocess, re
from datetime import datetime
from textwrap import dedent
from pathlib import Path
from typing import List, Dict

# ──────────────── ANSI colors ────────────────
OK, ERR, END = "\033[1;92m", "\033[1;31m", "\033[0m"

# ──────────────── helpers ────────────────────
cls   = lambda: os.system("clear" if os.name == "posix" else "cls")
pause = lambda: input("\nEnter ↵ برای ادامه…")

def run(cmd: List[str], desc: str, interactive: bool=False) -> None:
    """Run shell command and show ✅/❌."""
    print(f"→ {desc}…", end=" ")
    try:
        if interactive:
            subprocess.check_call(cmd)
        else:
            subprocess.check_call(cmd, stdout=subprocess.DEVNULL,
                                  stderr=subprocess.DEVNULL)
        print(f"{OK}✅{END}")
    except subprocess.CalledProcessError as e:
        print(f"{ERR}❌{END}")
        if interactive is False:
            print("   ", e)

# ──────────────── IP banner (ifconfig.co) ────────────────
def ip_info() -> Dict[str, str]:
    """
    Returns dict like {"ip": "...", "isp": "...", "cty": "..."}.
    Falls back to "-" on any error (no crash).
    """
    try:
        import requests
        j = requests.get("https://ifconfig.co/json", timeout=4).json()
        return {
            "ip":  j.get("ip", "-"),
            "isp": j.get("asn_org", "-"),
            "cty": j.get("country_iso", "-")
        }
    except Exception:
        return {"ip": "-", "isp": "-", "cty": "-"}

# ════════════════ NETWORK MODULE ════════════════
def apply_dns(ns: List[str]) -> None:
    run(["sudo","systemctl","stop","systemd-resolved"],   "Stop systemd-resolved")
    run(["sudo","systemctl","disable","systemd-resolved"],"Disable systemd-resolved")
    run(["sudo","rm","-f","/etc/resolv.conf"],            "Remove resolv.conf")
    run(["sudo","bash","-c",
         "printf '%s\\n' " + " ".join([f\"nameserver {x}\" for x in ns]) +
         " > /etc/resolv.conf"], "Write resolv.conf")
    run(["sudo","chattr","+i","/etc/resolv.conf"],        "Lock file")
    pause()

def dns_menu() -> None:
    while True:
        cls()
        print("DNS PROVIDERS")
        print("1) Google       8.8.8.8 / 8.8.4.4")
        print("2) Cloudflare   1.1.1.1 / 1.0.0.1")
        print("3) Shecan       185.51.200.2 / 178.22.122.100")
        print("4) Dynx         10.70.95.150 / 10.70.95.162")
        print("0) Back")
        c=input("\nSelect #: ").strip()
        if   c=="1": apply_dns(["8.8.8.8","8.8.4.4"])
        elif c=="2": apply_dns(["1.1.1.1","1.0.0.1"])
        elif c=="3": apply_dns(["185.51.200.2","178.22.122.100"])
        elif c=="4": apply_dns(["10.70.95.150","10.70.95.162"])
        elif c=="0": return
        else: pause()

UNBOUND_CONF = dedent("""
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
    cls()
    run(["sudo","apt","install","unbound","-y"], "Install unbound")
    run(["sudo","bash","-c",f"echo '{UNBOUND_CONF}' > /etc/unbound/unbound.conf"],
        "Write config")
    run(["sudo","unbound-checkconf"], "Check config", True)
    run(["sudo","systemctl","restart","unbound"], "Restart unbound")
    apply_dns(["127.0.0.1","::1"])

def speedtest() -> None:
    cls()
    run(["bash","-c","wget -qO- bench.sh | bash"], "Run bench.sh", True)
    pause()

def network_menu() -> None:
    while True:
        cls()
        print("NETWORK MENU")
        print("1) DNS switcher")
        print("2) Install & configure Unbound")
        print("3) Speed-test")
        print("0) Back")
        c=input("\nSelect #: ").strip()
        if   c=="1": dns_menu()
        elif c=="2": install_unbound()
        elif c=="3": speedtest()
        elif c=="0": return
        else: pause()

# ════════════════ SYSTEM SETTINGS ════════════════
def time_sync():
    cls()
    run(["sudo","timedatectl","set-ntp","true"], "Enable NTP")
    run(["sudo","apt","install","ntpdate","-y"], "Install ntpdate")
    run(["sudo","ntpdate","-u","pool.ntp.org"],   "Sync time")
    print("⏰", datetime.now().strftime("%Y-%m-%d %H:%M:%S")); pause()

def distro_info():
    cls(); run(["lsb_release","-a"], "Distro info", True); pause()

def htop_live():
    cls(); run(["sudo","apt","install","htop","-y"], "Install htop")
    run(["htop"], "Launch htop", True); pause()

BASE_DIR = Path(__file__).resolve().parent
BACKUPER = BASE_DIR / "backuper_menu.sh"
def backup_wizard():
    cls()
    if not BACKUPER.exists():
        print(f"{ERR}backuper_menu.sh not found{END}"); pause(); return
    run(["sudo","chmod","+x",str(BACKUPER)], "Ensure executable")
    run(["sudo",str(BACKUPER)], "Run wizard", True); pause()

def system_menu():
    while True:
        cls()
        print("SYSTEM SETTINGS")
        print("1) Sync Time/Date")
        print("2) Distro info")
        print("3) Live status (htop)")
        print("4) Backup wizard")
        print("0) Back")
        c=input("\nSelect #: ").strip()
        if   c=="1": time_sync()
        elif c=="2": distro_info()
        elif c=="3": htop_live()
        elif c=="4": backup_wizard()
        elif c=="0": return
        else: pause()

# ════════════════ SECURITY ════════════════
def change_ssh_port():
    cls(); p=input("New SSH port: ").strip()
    if not p.isdigit() or not 1<=int(p)<=65535: pause(); return
    run(["sudo","sed","-i",rf"s/^#?Port .*/Port {p}/","/etc/ssh/sshd_config"],
        "Set port")
    run(["sudo","ufw","allow",f"{p}/tcp"], "Open UFW")
    run(["sudo","systemctl","restart","ssh"], "Restart SSH"); pause()

def icmp_toggle(enable:bool):
    val="0" if enable else "1"
    run(["sudo","bash","-c",f"echo {val} > /proc/sys/net/ipv4/icmp_echo_ignore_all"],
        "Toggle ping")
    run(["sudo","sysctl","-w",f"net.ipv4.icmp_echo_ignore_all={val}"],
        "Persist"); pause()

def ssl_self():
    cls()
    run(["sudo","apt","install","openssl","-y"], "Install openssl")
    run(["openssl","req","-x509","-nodes","-days","365","-newkey","rsa:2048",
         "-keyout","server.key","-out","server.crt"],
        "Generate self-signed cert", True); pause()

def firewall_status():
    cls(); run(["sudo","ufw","status"], "UFW", True); pause()

def security_menu():
    while True:
        cls()
        print("SECURITY MENU")
        print("1) Change SSH port")
        print("2) Enable ping")
        print("3) Disable ping")
        print("4) Self-signed SSL")
        print("5) UFW status")
        print("0) Back")
        c=input("\nSelect #: ").strip()
        if   c=="1": change_ssh_port()
        elif c=="2": icmp_toggle(True)
        elif c=="3": icmp_toggle(False)
        elif c=="4": ssl_self()
        elif c=="5": firewall_status()
        elif c=="0": return
        else: pause()

# ════════════════ WEBSERVER ════════════════
apt = lambda pkg: run(["sudo","apt","install",pkg,"-y"],f"Install {pkg}")
svc = lambda s,a: run(["sudo","systemctl",a,s],f"{a} {s}")

def nginx_vhost():
    cls(); d=input("Domain: ").strip()
    if not re.match(r"^[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$", d): pause(); return
    root=f"/var/www/{d}"; conf=f"/etc/nginx/sites-available/{d}.conf"
    run(["sudo","mkdir","-p",root],"Create root")
    server_block=f"""
server {{
    listen 80;
    server_name {d};
    root {root};
    index index.html index.htm;
    location / {{ try_files $uri $uri/ =404; }}
}}"""
    run(["sudo","bash","-c",f"echo '{server_block}' > {conf}"],"Write vhost")
    run(["sudo","ln","-s",conf,f"/etc/nginx/sites-enabled/{d}.conf"],"Enable site")
    run(["sudo","nginx","-t"],"Test",True); svc("nginx","reload"); pause()

def apache_vhost():
    cls(); d=input("Domain: ").strip()
    if not re.match(r"^[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$", d): pause(); return
    root=f"/var/www/{d}"; conf=f"/etc/apache2/sites-available/{d}.conf"
    run(["sudo","mkdir","-p",root],"Create root")
    vhost=f"""
<VirtualHost *:80>
    ServerName {d}
    DocumentRoot {root}
    <Directory {root}>
        AllowOverride All
        Require all granted
    </Directory>
</VirtualHost>"""
    run(["sudo","bash","-c",f"echo '{vhost}' > {conf}"],"Write vhost")
    run(["sudo","a2ensite",f"{d}.conf"],"Enable")
    run(["sudo","apache2ctl","configtest"],"Test",True)
    svc("apache2","reload"); pause()

def web_menu():
    while True:
        cls()
        print("WEBSERVER MENU")
        print("1) Install Nginx   2) Nginx status   3) Nginx restart   4) Nginx stop")
        print("5) Install Apache  6) Apache status  7) Apache restart  8) Apache stop")
        print("9) Nginx vhost     10) Apache vhost   0) Back")
        c=input("\nSelect #: ").strip()
        if   c=="1": apt("nginx"); pause()
        elif c=="2": svc("nginx","status"); pause()
        elif c=="3": svc("nginx","restart"); pause()
        elif c=="4": svc("nginx","stop"); pause()
        elif c=="5": apt("apache2"); pause()
        elif c=="6": svc("apache2","status"); pause()
        elif c=="7": svc("apache2","restart"); pause()
        elif c=="8": svc("apache2","stop"); pause()
        elif c=="9": nginx_vhost()
        elif c=="10": apache_vhost()
        elif c=="0": return
        else: pause()

# ════════════════ MAIN LOOP ════════════════
def main():
    info=ip_info()
    while True:
        cls()
        print("############################################")
        print(f" IP: {info['ip']} | ISP: {info['isp']} | {info['cty']}")
        print("############################################")
        print("1) Network 🌐  2) System ⚙️  3) Security 🔒  4) Webserver 🕸️  0) Exit")
        c=input("\nSelect #: ").strip()
        if   c=="1": network_menu()
        elif c=="2": system_menu()
        elif c=="3": security_menu()
        elif c=="4": web_menu()
        elif c=="0": sys.exit(0)
        else: pause()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nInterrupted.")
