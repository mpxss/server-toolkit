#!/usr/bin/env python3
# ===============================================================
#  Server-Toolkit – Interactive CLI for Ubuntu 20.04+ (MIT)
#  Version : 2025-06  |  Author : mpxss (OpenAI assisted)
# ===============================================================

from __future__ import annotations
import os, sys, subprocess, re
from datetime import datetime
from pathlib import Path
from textwrap import dedent
from typing import List, Dict

# ────────────────────── ANSI colors ────────────────────────────
COK, CERR, CEND = "\033[1;92m", "\033[1;31m", "\033[0m"

# ────────────────────── utils ──────────────────────────────────
def cls()  -> None: os.system("clear" if os.name == "posix" else "cls")
def pause() -> None: input("\nEnter ↵ برای ادامه…")

def run(cmd: List[str], desc: str, interactive: bool=False) -> None:
    """Run shell command and show ✅/❌."""
    print(f"→ {desc}…", end=" ")
    try:
        if interactive:
            subprocess.check_call(cmd)
        else:
            subprocess.check_call(cmd,
                                  stdout=subprocess.DEVNULL,
                                  stderr=subprocess.DEVNULL)
        print(f"{COK}✅{CEND}")
    except subprocess.CalledProcessError as e:
        print(f"{CERR}❌{CEND}")
        if interactive is False:
            print("  ", e)

# ────────────────────── public IP banner ───────────────────────
try:
    import requests
except ModuleNotFoundError:
    requests = None

def ip_info() -> Dict[str, str]:
    default = {"ip": "Unknown", "isp": "Unknown", "country": "Unknown"}
    if requests is None:
        return default
    try:
        j = requests.get("https://ipinfo.io/json", timeout=4).json()
        return {"ip": j.get("ip","?"),
                "isp": j.get("org","?"),
                "country": j.get("country","?")}
    except Exception:
        return default

# ══════════════════════ NETWORK MODULE ═════════════════════════
def apply_dns(nameservers: List[str]) -> None:
    run(["sudo","systemctl","stop","systemd-resolved"], "Stop systemd-resolved")
    run(["sudo","systemctl","disable","systemd-resolved"], "Disable systemd-resolved")
    run(["sudo","rm","-f","/etc/resolv.conf"], "Remove resolv.conf")
    lines = "\n".join(f"nameserver {ns}" for ns in nameservers) + "\n"
    run(["sudo","bash","-c",f"echo '{lines}' > /etc/resolv.conf"], "Write resolv.conf")
    run(["sudo","chattr","+i","/etc/resolv.conf"], "Lock resolv.conf")
    pause()

def dns_menu():
    while True:
        cls()
        print("DNS PROVIDERS")
        print("1) Google            8.8.8.8 / 8.8.4.4")
        print("2) Cloudflare        1.1.1.1 / 1.0.0.1")
        print("3) Shecan (anti-sanction)")
        print("4) Dynx  (anti-sanction)")
        print("0) Back")
        ch=input("\nSelect #: ").strip()
        if   ch=="1": apply_dns(["8.8.8.8","8.8.4.4"])
        elif ch=="2": apply_dns(["1.1.1.1","1.0.0.1"])
        elif ch=="3": apply_dns(["185.51.200.2","178.22.122.100"])
        elif ch=="4": apply_dns(["10.70.95.150","10.70.95.162"])
        elif ch=="0": return
        else: pause()

UNBOUND_CONF = dedent("""
server:
    interface: 127.0.0.1
    interface: ::1
    port: 53
    cache-max-ttl: 86400
    cache-min-ttl: 3600
forward-zone:
    name: "."
    forward-addr: 8.8.8.8
    forward-addr: 1.1.1.1
""")

def install_unbound():
    cls()
    run(["sudo","apt","install","unbound","-y"], "Install unbound")
    run(["sudo","bash","-c",f"echo '{UNBOUND_CONF}' > /etc/unbound/unbound.conf"],
        "Write unbound.conf")
    run(["sudo","unbound-checkconf"], "Check config", True)
    run(["sudo","systemctl","restart","unbound"], "Restart unbound")
    apply_dns(["127.0.0.1","::1"])

def speedtest():
    cls()
    run(["bash","-c","wget -qO- bench.sh | bash"], "Run bench.sh", True)
    pause()

def network_menu():
    while True:
        cls()
        print("NETWORK MENU")
        print("1) DNS switcher")
        print("2) Install & configure Unbound")
        print("3) Network speed-test")
        print("0) Back")
        ch=input("\nSelect #: ").strip()
        if   ch=="1": dns_menu()
        elif ch=="2": install_unbound()
        elif ch=="3": speedtest()
        elif ch=="0": return
        else: pause()

# ═════════════════════ SYSTEM SETTINGS ═════════════════════════
def time_sync():
    cls()
    run(["sudo","timedatectl","set-ntp","true"], "Enable NTP")
    run(["sudo","apt","install","ntpdate","-y"], "Install ntpdate")
    run(["sudo","ntpdate","-u","pool.ntp.org"], "Sync time")
    print("⏰", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    pause()

def distro_info():
    cls()
    run(["lsb_release","-a"], "Distro info", True)
    pause()

def htop_live():
    cls()
    run(["sudo","apt","install","htop","-y"], "Install htop")
    run(["htop"], "Launch htop", True)
    pause()

BASE_DIR = Path(__file__).resolve().parent
BACKUPER = BASE_DIR / "backuper_menu.sh"
def backup_wizard():
    cls()
    if not BACKUPER.exists():
        print(f"{CERR}backuper_menu.sh not found!{CEND}")
        pause(); return
    run(["sudo","chmod","+x",str(BACKUPER)], "Ensure executable")
    run(["sudo",str(BACKUPER)], "Run backup wizard", True)
    pause()

def system_menu():
    while True:
        cls()
        print("SYSTEM SETTINGS")
        print("1) Sync Time/Date")
        print("2) Distro info")
        print("3) Live status (htop)")
        print("4) Backup wizard")
        print("0) Back")
        ch=input("\nSelect #: ").strip()
        if   ch=="1": time_sync()
        elif ch=="2": distro_info()
        elif ch=="3": htop_live()
        elif ch=="4": backup_wizard()
        elif ch=="0": return
        else: pause()

# ═══════════════════════ SECURITY ═══════════════════════════════
def change_ssh_port():
    cls()
    new=input("New SSH port: ").strip()
    if not new.isdigit() or not (1<=int(new)<=65535): pause(); return
    run(["sudo","sed","-i",rf"s/^#?Port .*/Port {new}/","/etc/ssh/sshd_config"],
        f"Set Port {new}")
    run(["sudo","ufw","allow",f"{new}/tcp"], "Open port in UFW")
    run(["sudo","systemctl","restart","ssh"], "Restart SSH")
    pause()

def icmp_toggle(enable: bool):
    val="0" if enable else "1"
    run(["sudo","bash","-c",f"echo {val} > /proc/sys/net/ipv4/icmp_echo_ignore_all"],
        "Runtime ICMP toggle")
    run(["sudo","bash","-c",
         f"grep -q icmp_echo /etc/sysctl.conf && "
         f"sudo sed -i 's/^net.ipv4.icmp_echo_ignore_all.*/net.ipv4.icmp_echo_ignore_all = {val}/' /etc/sysctl.conf || "
         f"echo 'net.ipv4.icmp_echo_ignore_all = {val}' | sudo tee -a /etc/sysctl.conf"],
        "Persist sysctl")
    run(["sudo","sysctl","-p"], "Reload sysctl")
    pause()

def icmp_menu():
    while True:
        cls()
        print("ICMP (Ping)")
        print("1) Enable ping")
        print("2) Disable ping")
        print("0) Back")
        ch=input("\nSelect #: ").strip()
        if   ch=="1": icmp_toggle(True)
        elif ch=="2": icmp_toggle(False)
        elif ch=="0": return
        else: pause()

def self_ssl():
    cls()
    run(["sudo","apt","install","openssl","-y"], "Install openssl")
    run(["openssl","genpkey","-algorithm","RSA","-out","server.key",
         "-pkeyopt","rsa_keygen_bits:2048"], "Generate key")
    run(["openssl","req","-new","-key","server.key","-out","server.csr"],
        "Generate CSR", True)
    run(["openssl","x509","-req","-in","server.csr","-signkey","server.key",
         "-out","server.crt","-days","365"], "Self-sign")
    pause()

def certbot_ssl():
    cls()
    email=input("Email: ").strip(); domain=input("Domain: ").strip()
    if not re.match(r"^[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$", domain): pause(); return
    run(["sudo","apt","install","certbot","-y"], "Install certbot")
    run(["sudo","certbot","certonly","--standalone",
         "--preferred-challenges","http","-d",domain,
         "--email",email,"--agree-tos","--noninteractive"],
        "Obtain cert", True)
    pause()

def ssl_menu():
    while True:
        cls()
        print("SSL Certificates")
        print("1) Self-signed")
        print("2) Certbot (Let’s Encrypt)")
        print("0) Back")
        ch=input("\nSelect #: ").strip()
        if   ch=="1": self_ssl()
        elif ch=="2": certbot_ssl()
        elif ch=="0": return
        else: pause()

def ufw_fail2ban():
    cls()
    run(["sudo","ufw","status"], "UFW status", True)
    run(["sudo","fail2ban-client","status"], "Fail2Ban", True)
    pause()

def security_menu():
    while True:
        cls()
        print("SECURITY MENU")
        print("1) Change SSH port")
        print("2) ICMP toggle")
        print("3) SSL certificates")
        print("4) Show UFW & Fail2Ban")
        print("0) Back")
        ch=input("\nSelect #: ").strip()
        if   ch=="1": change_ssh_port()
        elif ch=="2": icmp_menu()
        elif ch=="3": ssl_menu()
        elif ch=="4": ufw_fail2ban()
        elif ch=="0": return
        else: pause()

# ═══════════════════════ WEBSERVER ═══════════════════════════════
def apt_install(pkg:str):
    run(["sudo","apt","update","-y"], "apt update")
    run(["sudo","apt","install",pkg,"-y"], f"Install {pkg}")

def svc(svc:str, action:str): run(["sudo","systemctl",action,svc], f"{action} {svc}")

def nginx_vhost():
    cls(); dom=input("Domain: ").strip()
    if not re.match(r"^[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$", dom): pause(); return
    root=input(f"DocRoot [/var/www/{dom}]: ").strip() or f"/var/www/{dom}"
    conf=f"/etc/nginx/sites-available/{dom}.conf"
    if os.path.exists(conf): print("Exists"); pause(); return
    run(["sudo","mkdir","-p",root],"Create root")
    block=f\"\"\"\nserver {{\n    listen 80;\n    server_name {dom};\n    root {root};\n    index index.html index.htm;\n    location / {{ try_files $uri $uri/ =404; }}\n}}\"\"\"\n    run(["sudo","bash","-c",f"echo '{block}' > {conf}"],"Write vhost")
    run(["sudo","ln","-s",conf,f"/etc/nginx/sites-enabled/{dom}.conf"],"Enable site")
    run(["sudo","nginx","-t"],"Test",True); svc("nginx","reload"); pause()

def apache_vhost():
    cls(); dom=input("Domain: ").strip()
    if not re.match(r"^[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$", dom): pause(); return
    root=input(f"DocRoot [/var/www/{dom}]: ").strip() or f"/var/www/{dom}"
    conf=f"/etc/apache2/sites-available/{dom}.conf"
    if os.path.exists(conf): print("Exists"); pause(); return
    run(["sudo","mkdir","-p",root],"Create root")
    vhost=f\"\"\"\n<VirtualHost *:80>\n  ServerName {dom}\n  DocumentRoot {root}\n  <Directory {root}>\n    Options Indexes FollowSymLinks\n    AllowOverride All\n    Require all granted\n  </Directory>\n  ErrorLog ${APACHE_LOG_DIR}/{dom}_error.log\n  CustomLog ${APACHE_LOG_DIR}/{dom}_access.log combined\n</VirtualHost>\"\"\"\n    run(["sudo","bash","-c",f"echo '{vhost}' > {conf}"],"Write vhost")
    run(["sudo","a2ensite",f"{dom}.conf"],"Enable"); run(["sudo","apache2ctl","configtest"],"Test",True)
    svc("apache2","reload"); pause()

def web_menu():
    while True:
        cls()
        print("WEBSERVER MENU")
        print("1) Install Nginx      2) Nginx status")
        print("3) Nginx restart      4) Nginx stop")
        print("5) Install Apache     6) Apache status")
        print("7) Apache restart     8) Apache stop")
        print("9) Setup Nginx vhost  10) Setup Apache vhost")
        print("0) Back")
        ch=input("\nSelect #: ").strip()
        if   ch=="1": apt_install("nginx"); pause()
        elif ch=="2": svc("nginx","status"); pause()
        elif ch=="3": svc("nginx","restart"); pause()
        elif ch=="4": svc("nginx","stop"); pause()
        elif ch=="5": apt_install("apache2"); pause()
        elif ch=="6": svc("apache2","status"); pause()
        elif ch=="7": svc("apache2","restart"); pause()
        elif ch=="8": svc("apache2","stop"); pause()
        elif ch=="9": nginx_vhost()
        elif ch=="10": apache_vhost()
        elif ch=="0": return
        else: pause()

# ═══════════════════════ MAIN LOOP ══════════════════════════════
def main():
    info=ip_info()
    while True:
        cls()
        print("############################################")
        print("               SERVER INFO")
        print(f"IP      : {info['ip']}")
        print(f"ISP     : {info['isp']}")
        print(f"Country : {info['country']}")
        print("############################################")
        print("MAIN MENU")
        print("1) Network 🌐")
        print("2) System Settings ⚙️")
        print("3) Security 🔒")
        print("4) Webserver 🕸️")
        print("0) Exit")
        ch=input("\nSelect #: ").strip()
        if   ch=="1": network_menu()
        elif ch=="2": system_menu()
        elif ch=="3": security_menu()
        elif ch=="4": web_menu()
        elif ch=="0": sys.exit(0)
        else: pause()

if __name__ == "__main__":
    try: main()
    except KeyboardInterrupt: print("\nInterrupted.")
