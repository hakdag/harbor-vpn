#!/usr/bin/env python3
"""Read-only VPN forwarded traffic accounting for the HVPOC_FWD chain."""
import argparse
import datetime as dt
import json
import os
import sqlite3
import subprocess
import sys
from pathlib import Path

DEFAULT_DB = '/var/lib/vpn-usage/usage.sqlite3'
CHAIN = 'HVPOC_FWD'


def current_counters():
    result = subprocess.run(['iptables', '-w', '-nvxL', CHAIN], capture_output=True, text=True, check=True)
    counters = {}
    for line in result.stdout.splitlines():
        parts = line.split()
        if len(parts) < 10 or not parts[0].isdigit() or not parts[1].isdigit():
            continue
        # pkts bytes target prot opt in out source destination ...
        pkts, byte_count, target, _, _, incoming, outgoing, source, destination = parts[:9]
        suffix = ' '.join(parts[9:])
        if target != 'ACCEPT' or 'policy match dir ' not in suffix or 'pol ipsec' not in suffix:
            continue
        if 'dir in' in suffix and source == '10.77.0.0/24' and outgoing == 'eth0' and incoming == '*':
            counters['upload'] = int(byte_count)
        elif 'dir out' in suffix and destination == '10.77.0.0/24' and incoming == 'eth0' and outgoing == '*':
            counters['download'] = int(byte_count)
    if set(counters) != {'upload', 'download'}:
        raise RuntimeError('Could not identify both IPsec ACCEPT counters; refusing to record an incomplete sample')
    return counters


def connect(path):
    dbpath = Path(path)
    dbpath.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    db = sqlite3.connect(dbpath, timeout=15)
    db.execute('PRAGMA journal_mode=WAL')
    db.execute('CREATE TABLE IF NOT EXISTS samples (id INTEGER PRIMARY KEY, timestamp_utc TEXT NOT NULL, boot_id TEXT NOT NULL, upload_raw INTEGER NOT NULL, download_raw INTEGER NOT NULL, upload_delta INTEGER NOT NULL, download_delta INTEGER NOT NULL, reset_detected INTEGER NOT NULL)')
    return db


def sample(path):
    # Read counters before opening DB; failures do not change history.
    current = current_counters()
    boot_id = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    now = dt.datetime.now(dt.timezone.utc).isoformat()
    with connect(path) as db:
        db.execute('BEGIN IMMEDIATE')
        prev = db.execute('SELECT boot_id, upload_raw, download_raw FROM samples ORDER BY id DESC LIMIT 1').fetchone()
        if prev is None:
            # The initial sample establishes a baseline, not prior historical usage.
            up_delta = down_delta = 0
            reset = 0
        else:
            reset = int(prev[0] != boot_id or current['upload'] < prev[1] or current['download'] < prev[2])
            if reset:
                # Counters may have been recreated while the collector was offline.
                # Do not invent traffic across an unknown reset interval.
                up_delta = down_delta = 0
            else:
                up_delta = current['upload'] - prev[1]
                down_delta = current['download'] - prev[2]
        db.execute('INSERT INTO samples(timestamp_utc,boot_id,upload_raw,download_raw,upload_delta,download_delta,reset_detected) VALUES(?,?,?,?,?,?,?)', (now,boot_id,current['upload'],current['download'],up_delta,down_delta,reset))
    return dict(utc=now, raw=current, recorded_delta={'upload':up_delta,'download':down_delta}, reset_detected=bool(reset), baseline=(prev is None))


def report(path, period):
    if not Path(path).is_file():
        raise RuntimeError('No database yet. Run: vpn-usage sample')
    now = dt.datetime.now(dt.timezone.utc)
    if period == 'today':
        boundary = now.replace(hour=0, minute=0, second=0, microsecond=0)
    elif period == 'month':
        boundary = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    else:
        boundary = dt.datetime(1970,1,1,tzinfo=dt.timezone.utc)
    db = sqlite3.connect(f'file:{Path(path).resolve()}?mode=ro', uri=True)
    up, down, n, resets = db.execute('SELECT COALESCE(SUM(upload_delta),0), COALESCE(SUM(download_delta),0),COUNT(*),COALESCE(SUM(reset_detected),0) FROM samples WHERE timestamp_utc >= ?', (boundary.isoformat(),)).fetchone()
    db.close()
    print(json.dumps({'period':period,'timezone':'UTC','upload_bytes':up,'download_bytes':down,'total_bytes':up+down,'samples':n,'counter_resets':resets}, indent=2))


def main():
    p=argparse.ArgumentParser(description='Read-only HVPOC_FWD VPN traffic accounting (forwarded plaintext IP bytes)')
    p.add_argument('--db', default=DEFAULT_DB)
    sub=p.add_subparsers(dest='command',required=True)
    sub.add_parser('sample')
    rep=sub.add_parser('report')
    rep.add_argument('period',choices=['today','month','all'])
    args=p.parse_args()
    try:
        if args.command=='sample':
            print(json.dumps(sample(args.db), indent=2))
        else:
            report(args.db,args.period)
    except (RuntimeError, OSError, subprocess.CalledProcessError, sqlite3.Error) as exc:
        print(f'vpn-usage: {exc}',file=sys.stderr)
        sys.exit(1)
if __name__=='__main__':
    main()
