# HyperVault VPN Traffic Accounting

This small independent Python/SQLite collector reads the two existing IPsec `ACCEPT` counters in `HVPOC_FWD`. It does not modify firewall rules or the Rust VPN.

## Meaning and limitations

- `upload_bytes` is forwarded plaintext IP bytes from `10.77.0.0/24` to `eth0` matched by an inbound IPsec policy.
- `download_bytes` is forwarded plaintext IP bytes from `eth0` to `10.77.0.0/24` matched by an outbound IPsec policy.
- These numbers are **not** the exact encrypted bytes transferred on the VPS NIC, or your provider's billable traffic. ESP/UDP overhead, IKE messages, other VPS services, and possibly local non-forwarded traffic are excluded.
- Sampling begins with a **zero baseline**. Bytes used before installation are not retroactively included.
- If firewall counters are reset, recreated, or the host restarts, the tool records a reset and starts a new baseline. Traffic during the blind interval may be missed, so totals are *estimates / lower bounds*, not precise billing amounts.
- Daily and monthly reports use **UTC** boundaries.
- This version assumes the `HVPOC_FWD` rule format deployed for the iPhone PoC (`eth0`, `10.77.0.0/24`). If those values change, modify the parser accordingly.
- Run as root since reading iptables requires privileges. No sensitive keys are read.

## Installation on Ubuntu VPS

Copy the three files to the VPS, then execute one line at a time:

```bash
sudo install -o root -g root -m 0755 vpn_usage.py /usr/local/sbin/vpn-usage
sudo install -o root -g root -m 0644 vpn-usage.service /etc/systemd/system/vpn-usage.service
sudo install -o root -g root -m 0644 vpn-usage.timer /etc/systemd/system/vpn-usage.timer
sudo systemctl daemon-reload
sudo /usr/local/sbin/vpn-usage sample
sudo systemctl enable --now vpn-usage.timer
sudo systemctl list-timers vpn-usage.timer
```

## Reports

```bash
sudo vpn-usage report today
sudo vpn-usage report month
sudo vpn-usage report all
```

## Troubleshooting / verify

```bash
sudo systemctl status vpn-usage.timer --no-pager
sudo journalctl -u vpn-usage.service -n 20 --no-pager
sudo iptables -nvxL HVPOC_FWD --line-numbers
```

The SQLite database is at `/var/lib/vpn-usage/usage.sqlite3`. Back up this directory to retain usage history. The SQLite journal may be in adjacent `-wal` or `-shm` files while active; prefer SQLite's backup API when hot-backup is needed.

## Safe removal

```bash
sudo systemctl disable --now vpn-usage.timer
sudo rm -f /etc/systemd/system/vpn-usage.timer /etc/systemd/system/vpn-usage.service /usr/local/sbin/vpn-usage
sudo systemctl daemon-reload
```

Keep the database if you need historical figures.

## Quota protection

For a real VPS data-cap alert, separately integrate the hosting provider's quota/billing metrics. Firewall counters alone cannot accurately determine that allowance.
