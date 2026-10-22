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

Disclaimer

This tool is intended to support authorised security triage of Plesk-hosted WordPress environments. It collects system, PHP, WordPress, file-integrity, user, process and log information for later review.

The tool is read-only by design. It does not remove malware, repair files, change configuration, update software or remediate vulnerabilities.

The output should not be treated as proof that a system has or has not been compromised. A lack of identified indicators does not guarantee that compromise did not occur. Logs may be incomplete, altered, deleted or unavailable, and some activity may not leave reliable evidence in the sources examined by this tool.

WordPress checksum verification is limited to files and plugins for which authoritative checksums are available. Commercial, custom and privately distributed plugins or themes may be reported as unverified. This does not mean they are malicious, but they may require separate manual review.

Use this tool only on systems you own or where you have explicit permission to conduct security testing and evidence collection. Review the commands and source code before running it in a production environment.

The collected output may contain confidential or security-sensitive information, including usernames, IP addresses, server paths, installed software, authentication events and website configuration details. Evidence archives should be encrypted, access-controlled, retained only as necessary and transferred using an appropriate secure method.

This tool supports initial triage and evidence gathering. It is not a substitute for a full digital forensic investigation, incident-response engagement, vulnerability assessment or professional security advice.

The software is provided without warranty. To the fullest extent permitted by law, the authors and contributors accept no liability for loss, damage, service interruption or other consequences arising from its use or misuse.
