import re
import sqlite3
import ipaddress
from ipwhois import IPWhois
from datetime import datetime

LOG_FILE = "sample_ufw.log" # later change to "/var/log/ufw.log"
DB_FILE = "threats.db"
FIREHOL_FILE = "firehol_level1.txt"
THRESHOLD = 5 # flag the IP which shows up 5+ times

def load_blacklist(path):
    blacklist = []
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"): # skips comments
                    try:
                        blacklist.append(ipaddress.ip_network(line, strict=False)) # loads subnet ranges, not exact IPs
                    except ValueError:
                        pass
    except FileNotFoundError:
        print(f"Blacklist file not found: {path}")
    return blacklist

def is_blacklisted(ip, blacklist):
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in network for network in blacklist) # checks if IP falls within any blacklisted subnet
    except ValueError:
        return False

def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS threats (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip TEXT,
        count INTEGER,
        blacklisted INTEGER,
        country TEXT,
        isp TEXT,
        detected_at TEXT
    )''') # makes db if it doesnt exist, makes threats table
    conn.commit()
    return conn

def parse_ips(log_file):
    ip_counts = {}
    pattern = re.compile(r'SRC=(\d+\.\d+\.\d+\.\d+)') # searches for pattern that will give the source IP address
    try:
        with open(log_file) as f:
            for line in f:
                match = pattern.search(line)
                if match:
                    ip = match.group(1)
                    ip_counts[ip] = ip_counts.get(ip, 0) + 1 # counts how many times each IP appears
    except FileNotFoundError:
        print(f"Log file not found: {log_file}")
    return ip_counts

def whois_lookup(ip):
    try:
        result = IPWhois(ip).lookup_rdap() # asks the internet 'who's address is this?', returns country and ISP
        country = result.get("asn_country_code", "Unknown")
        isp = result.get("asn_description", "Unknown")
        return country, isp
    except Exception:
        return "Unknown", "Unknown"

def analyze(ip_counts, blacklist, conn): # goes through each IP address and flags those that are blacklisted and/or appear 5+ times
    c = conn.cursor()
    print(f"\n{'='*65}")
    print(f"{'IP':<20} {'COUNT':<8} {'BLACKLISTED':<13} {'COUNTRY':<10} ISP")
    print(f"{'='*65}")
    for ip, count in ip_counts.items():
        if count >= THRESHOLD or is_blacklisted(ip, blacklist):
            blacklisted = 1 if is_blacklisted(ip, blacklist) else 0
            country, isp = whois_lookup(ip)
            detected_at = datetime.now().isoformat()
            c.execute("INSERT INTO threats (ip, count, blacklisted, country, isp, detected_at) VALUES (?,?,?,?,?,?)", # saves them into db
                      (ip, count, blacklisted, country, isp, detected_at))
            conn.commit()
            flag = "YES" if blacklisted else "NO"
            print(f"{ip:<20} {count:<8} {flag:<13} {country:<10} {isp}")
    print(f"{'='*65}\n")

if __name__ == "__main__": # only runs when executed directly, not when imported
    print("Loading blacklist...")
    blacklist = load_blacklist(FIREHOL_FILE)
    print(f"Loaded {len(blacklist)} blacklisted networks")
    print("Parsing UFW logs...")
    ip_counts = parse_ips(LOG_FILE)
    print(f"Found {len(ip_counts)} unique IPs")
    conn = init_db()
    print("Analyzing threats...")
    analyze(ip_counts, blacklist, conn)
    conn.close()
