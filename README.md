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

This tool is intended for authorised security triage and evidence collection from Plesk-hosted WordPress environments.

It collects system, PHP, WordPress, account, file-integrity, process and log information for subsequent security analysis. It does not remove malware, repair files, update software, change application configuration or remediate vulnerabilities.

The results must not be treated as proof that a system is secure, compromised or has never been compromised. Absence of identified indicators does not establish absence of compromise. Relevant evidence may have been deleted, altered, rotated, unavailable or outside the scope of the data examined.

WordPress checksum verification is limited to components for which authoritative checksums are available. Commercial, private and custom plugins or themes may therefore be reported as unverified. An unverified component should not, by itself, be considered malicious.

Use this tool only on systems that you own or for which you have explicit authority to conduct security investigation and evidence collection.

The tool may process personal, confidential and security-sensitive information contained in system and application data, including usernames, IP addresses, authentication events, server paths, installed software and security configuration. Users are responsible for ensuring that collection, access, use, storage, transfer, retention and deletion of this information is lawful, proportionate and appropriately secured.

Where the tool is used on behalf of another organisation, the parties remain responsible for establishing their respective legal, contractual and data-protection responsibilities.

Any indication of compromise should be handled through the organisation's incident-response procedures and, where applicable, personal-data-breach procedures. Use of this tool does not suspend, extend or replace any legal, regulatory, contractual or notification obligation.

This tool performs triage against a live system. It is not a forensic acquisition tool and does not create a forensic image or guarantee preservation of all potentially relevant evidence. Where litigation, law-enforcement involvement, regulatory investigation or formal digital forensic analysis may be required, appropriate evidence-preservation procedures should be considered before further investigation.

Some checks depend on third-party services and reference data, including WordPress.org checksum information. The availability and completeness of those sources may affect the results.

This tool supports initial triage and evidence gathering. It is not a substitute for a full digital forensic investigation, incident-response engagement, penetration test, vulnerability assessment or professional security advice.

The software is provided subject to the terms of the repository's LICENSE file. Nothing in this disclaimer modifies or replaces those licence terms
