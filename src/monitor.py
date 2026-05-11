#!/usr/bin/env python3
import time
import re
import sqlite3
import ipaddress
import argparse
import os
import json
import smtplib
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

import pandas as pd
import joblib
from ipwhois import IPWhois


LOG_FILE = "/var/log/ufw.log"
DB_FILE = "threats.db"
FIREHOL_FILE = "firehol_level1.txt"
MODEL_FILE = "model/model.pkl"
CONFIG_FILE = "config.json"

THRESHOLD_COUNT = 5
THRESHOLD_ML = 0.7

blacklist = []
ip_counts = {}
model = None
config = {}


def load_config():
    global config
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, "r") as f:
            config = json.load(f)
    else:
        config = {"email": {"enabled": False}}
        print("⚠️  config.json not found — email alerts disabled")


def load_blacklist(path):
    global blacklist
    blacklist = []
    try:
        with open(path, "r") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    try:
                        blacklist.append(ipaddress.ip_network(line, strict=False))
                    except ValueError:
                        pass
        print(f"  ✅  Loaded {len(blacklist):,} blacklisted networks")
    except FileNotFoundError:
        print(f"⚠️  Blacklist file not found: {path}")


def is_blacklisted(ip):
    try:
        addr = ipaddress.ip_address(ip)
        if (
            addr.is_private
            or addr.is_loopback
            or addr.is_reserved
            or addr.is_multicast
            or addr.is_link_local
        ):
            return False
        return any(addr in network for network in blacklist)
    except ValueError:
        return False


def ml_score(src_port, dst_port):
    try:
        features = pd.DataFrame([{
            "Source Port": src_port,
            "Destination Port": dst_port
        }])
        return model.predict_proba(features)[0][1]
    except Exception:
        return 0.0


def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS threats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT UNIQUE,
            src_port INTEGER,
            dst_port INTEGER,
            count INTEGER,
            blacklisted INTEGER,
            ml_prob REAL,
            threat_score REAL,
            country TEXT,
            isp TEXT,
            detected_at TEXT
        )
    """)
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


def send_email_alert(threat_data):
    email_cfg = config.get("email", {})
    if not email_cfg.get("enabled", False):
        return

    try:
        msg = MIMEMultipart()
        msg["From"] = email_cfg["sender_email"]
        msg["To"] = email_cfg["recipient_email"]
        msg["Subject"] = f"Firewall Threat Detected: {threat_data['ip']}"

        body = f"""
New firewall threat detected.

IP Address:    {threat_data['ip']}
Source Port:   {threat_data['src_port']}
Destination:   {threat_data['dst_port']}
Occurrences:   {threat_data['count']}
Blacklisted:   {"YES" if threat_data['blacklisted'] else "NO"}
ML Probability:{threat_data['ml_prob']:.2f}
Threat Score:  {threat_data['threat_score']:.2f}
Country:       {threat_data['country']}
ISP:           {threat_data['isp']}
Detected At:   {threat_data['detected_at']}
"""

        msg.attach(MIMEText(body, "plain"))

        server = smtplib.SMTP(email_cfg["smtp_server"], email_cfg["smtp_port"])
        server.starttls()
        server.login(email_cfg["sender_email"], email_cfg["sender_password"])
        server.sendmail(
            email_cfg["sender_email"],
            email_cfg["recipient_email"],
            msg.as_string()
        )
        server.quit()
        print(f"  📧  Email alert sent for {threat_data['ip']}")
    except Exception as e:
        print(f"❌  Email alert failed: {e}")


def process_line(line, conn):
    global ip_counts

    src_match = re.search(r"SRC=(\d+\.\d+\.\d+\.\d+)", line)
    spt_match = re.search(r"SPT=(\d+)", line)
    dpt_match = re.search(r"DPT=(\d+)", line)

    if not all([src_match, spt_match, dpt_match]):
        return

    ip = src_match.group(1)
    src_port = int(spt_match.group(1))
    dst_port = int(dpt_match.group(1))

    ip_counts[ip] = ip_counts.get(ip, 0) + 1
    count = ip_counts[ip]

    ml_prob = ml_score(src_port, dst_port)
    blacklisted = 1 if is_blacklisted(ip) else 0
    threat_score = (0.4 * ml_prob) + (0.6 * blacklisted)

    if threat_score >= THRESHOLD_ML or count >= THRESHOLD_COUNT:
        c = conn.cursor()
        c.execute("SELECT id FROM threats WHERE ip = ?", (ip,))
        existing = c.fetchone()

        if existing:
            c.execute("""
                UPDATE threats
                SET count = ?, src_port = ?, dst_port = ?, blacklisted = ?,
                    ml_prob = ?, threat_score = ?
                WHERE ip = ?
            """, (count, src_port, dst_port, blacklisted, ml_prob, threat_score, ip))
        else:
            country, isp = whois_lookup(ip)
            detected_at = datetime.now().isoformat()

            c.execute("""
                INSERT INTO threats
                (ip, src_port, dst_port, count, blacklisted, ml_prob, threat_score, country, isp, detected_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (ip, src_port, dst_port, count, blacklisted, ml_prob, threat_score, country, isp, detected_at))

            bl_label = "YES" if blacklisted else "NO "
            print(
                f"  🚨  {ip:<15}  │  "
                f"#{count:<2}  │  "
                f"ML: {ml_prob:.2f}  │  "
                f"BL: {bl_label}  │  "
                f"Score: {threat_score:.2f}  │  "
                f"{country} / {isp}"
            )

            threat_data = {
                "ip": ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "count": count,
                "blacklisted": blacklisted,
                "ml_prob": ml_prob,
                "threat_score": threat_score,
                "country": country,
                "isp": isp,
                "detected_at": detected_at
            }
            send_email_alert(threat_data)

        conn.commit()


def tail_log(log_file, conn, test_mode=False):
    if test_mode:
        print()
        print("  🧪  Test mode — processing sample_ufw.log")
        print("  " + "─" * 60)
        if os.path.exists("sample_ufw.log"):
            with open("sample_ufw.log", "r") as sample_f:
                for line in sample_f:
                    process_line(line, conn)
                    time.sleep(0.2)
            print("  " + "─" * 60)
            print("  ✅  Test completed!")
        else:
            print("  ❌  sample_ufw.log not found!")
        return

    print()
    print(f"  🔍  Monitoring {log_file}")
    print("  " + "─" * 60)
    print("       Press Ctrl+C to stop")
    print("  " + "─" * 60)

    with open(log_file, "r") as f:
        f.seek(0, 2)
        while True:
            line = f.readline()
            if line:
                process_line(line, conn)
            else:
                time.sleep(0.1)


def cli_status():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM threats")
    total = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM threats WHERE blacklisted = 1")
    bl_count = c.fetchone()[0]
    c.execute("SELECT MAX(detected_at) FROM threats")
    last = c.fetchone()[0] or "—"
    conn.close()

    print()
    print("  📊  System Status")
    print("  " + "─" * 40)
    print(f"  Total threats detected:   {total}")
    print(f"  Blacklisted IPs:          {bl_count}")
    print(f"  Last detected:            {last[:19]}")
    print("  " + "─" * 40)
    print()


def cli_threats(limit=10):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("""
        SELECT ip, src_port, dst_port, count, blacklisted, ml_prob, threat_score, detected_at
        FROM threats
        ORDER BY detected_at DESC
        LIMIT ?
    """, (limit,))
    rows = c.fetchall()
    conn.close()

    COL_W = 118
    print()
    print(f"  🚨  Last {limit} detected threats")
    print("  " + "─" * COL_W)
    print(
        f"  {'IP Address':<16}  │  {'SPT':<6}  │  {'DPT':<6}  │  "
        f"{'Count':<6}  │  {'BL':<4}  │  {'ML Prob':<8}  │  {'Score':<7}  │  {'Detected At'}"
    )
    print("  " + "─" * COL_W)

    if not rows:
        print("  No threats recorded yet.")
    else:
        for ip, src_port, dst_port, count, blacklisted, ml_prob, threat_score, detected_at in rows:
            bl = "YES" if blacklisted else "NO "
            print(
                f"  {ip:<16}  │  {src_port:<6}  │  {dst_port:<6}  │  "
                f"{count:<6}  │  {bl:<4}  │  {ml_prob:<8.2f}  │  {threat_score:<7.2f}  │  {detected_at}"
            )

    print("  " + "─" * COL_W)
    print()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog="monitor.py",
        description=(
            "Firewall Threat Detection — real-time UFW log analyser.\n\n"
            "Monitors /var/log/ufw.log, scores suspicious IPs using a Random Forest\n"
            "ML model and the FireHOL blacklist, and stores confirmed threats in a\n"
            "local SQLite database with optional email alerts."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python3 src/monitor.py                # start real-time monitoring\n"
            "  python3 src/monitor.py --test          # run with sample log file\n"
            "  python3 src/monitor.py --threats 20   # show last 20 threats\n"
            "  python3 src/monitor.py --status        # show threat summary\n"
        )
    )

    parser.add_argument(
        "--test",
        action="store_true",
        help="run in test mode using sample_ufw.log instead of the live log"
    )
    parser.add_argument(
        "--status",
        action="store_true",
        help="show a summary of total threats detected and exit"
    )
    parser.add_argument(
        "--threats",
        type=int,
        metavar="N",
        help="show the last N detected threats from the database and exit"
    )

    args = parser.parse_args()

    if args.status:
        cli_status()
        raise SystemExit

    if args.threats is not None:
        cli_threats(args.threats)
        raise SystemExit

    load_config()

    print()
    print("  ╔══════════════════════════════════════════╗")
    print("  ║     Firewall Threat Detection System     ║")
    print("  ╚══════════════════════════════════════════╝")
    print()
    print("  Loading ML model...")
    model = joblib.load(MODEL_FILE)
    print("  ✅  ML model loaded")

    load_blacklist(FIREHOL_FILE)
    conn = init_db()

    try:
        tail_log(LOG_FILE, conn, test_mode=args.test)
    except KeyboardInterrupt:
        print()
        print("  👋  Monitoring stopped.")
        print()
    finally:
        conn.close()
