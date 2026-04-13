import time
import re
import sqlite3
import ipaddress
from ipwhois import IPWhois
from datetime import datetime

LOG_FILE = "/var/log/ufw.log"
DB_FILE = "threats.db"
FIREHOL_FILE = "firehol_level1.txt"
THRESHOLD = 5

def load_blacklist(path):
    blacklist = []
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    try:
                        blacklist.append(ipaddress.ip_network(line, strict=False))
                    except ValueError:
                        pass
    except FileNotFoundError:
        print(f"Blacklist file not found: {path}")
    return blacklist

def is_blacklisted(ip, blacklist):
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in network for network in blacklist)
    except ValueError:
        return False

def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS threats (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip TEXT UNIQUE,
        count INTEGER,
        blacklisted INTEGER,
        country TEXT,
        isp TEXT,
        detected_at TEXT
    )''')
    conn.commit()
    return conn

def whois_lookup(ip):
    try:
        result = IPWhois(ip).lookup_rdap()
        country = result.get("asn_country_code", "Unknown")
        isp = result.get("asn_description", "Unknown")
        return country, isp
    except Exception:
        return "Unknown", "Unknown"

def process_line(line, ip_counts, blacklist, conn):
    pattern = re.compile(r'SRC=(\d+\.\d+\.\d+\.\d+)')
    match = pattern.search(line)
    if not match:
        return
    ip = match.group(1)
    ip_counts[ip] = ip_counts.get(ip, 0) + 1
    count = ip_counts[ip]
    if count >= THRESHOLD or is_blacklisted(ip, blacklist):
        c = conn.cursor()
        c.execute("SELECT id FROM threats WHERE ip = ?", (ip,))
        existing = c.fetchone()
        if existing:
            c.execute("UPDATE threats SET count = ? WHERE ip = ?", (count, ip))
        else:
            blacklisted = 1 if is_blacklisted(ip, blacklist) else 0
            country, isp = whois_lookup(ip)
            detected_at = datetime.now().isoformat()
            c.execute("INSERT INTO threats (ip, count, blacklisted, country, isp, detected_at) VALUES (?,?,?,?,?,?)",
                      (ip, count, blacklisted, country, isp, detected_at))
            flag = "YES" if blacklisted else "NO"
            print(f"[THREAT] {ip:<20} count={count:<5} blacklisted={flag:<4} country={country} isp={isp}")
        conn.commit()

def tail_log(log_file, blacklist, conn):
    print(f"Monitoring {log_file}... Press Ctrl+C to stop.")
    ip_counts = {}
    with open(log_file, 'r') as f:
        f.seek(0, 2)
        while True:
            line = f.readline()
            if line:
                process_line(line, ip_counts, blacklist, conn)
            else:
                time.sleep(0.5)

if __name__ == "__main__":
    print("Loading blacklist...")
    blacklist = load_blacklist(FIREHOL_FILE)
    print(f"Loaded {len(blacklist)} blacklisted networks")
    conn = init_db()
    print("Starting real-time monitoring...")
    try:
        tail_log(LOG_FILE, blacklist, conn)
    except KeyboardInterrupt:
        print("\nMonitoring stopped.")
        conn.close()