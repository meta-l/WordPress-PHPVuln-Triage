This tool performs evidence collection and security triage. It does not provide a guarantee that a system has not been compromised and is not a replacement for full digital forensic investigation.

Usage: sudo ./plesk-wordpress-triage.sh [options]

Options:
  --days N          Review retained logs/recent changes for the last N days (default: 14)
  --output DIR      Store the evidence folder under DIR (default: /root)
  --deep            Add slower heuristic searches for suspicious PHP patterns
  --no-archive      Do not create a .tar.gz archive
  -h, --help        Show this help

Apache License 2.0
Copyright 2026 Cyber & Data Protection Limited
