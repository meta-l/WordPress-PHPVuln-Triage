Plesk / WordPress Security Triage Tool
A read-only security triage and evidence-collection tool for Linux servers running Plesk and WordPress.

The tool provides a repeatable first-pass investigation following a vulnerability, suspected compromise or security incident. It collects host-level and per-site evidence for subsequent analysis without deliberately modifying, repairing or remediating the environment.

Table of contents
Features
Requirements
Installation
Usage
Standard triage
Specify the review period
Deep PHP review
Specify an output location
Disable archive creation
Output
Interpreting results
WordPress core
Plugin checks
Executable files in uploads
Must-use plugins
Administrator accounts
PHP_SESSION_UPLOAD_PROGRESS
HTTP 5xx responses
Recent file changes
Deep heuristic results
Overall assessment
Evidence handling
Limitations
Disclaimer
Licence and liability

Features
Automatic discovery of Plesk-hosted WordPress sites
WordPress core and plugin integrity checks
PHP version, handler, service and process inventory
WordPress administrator and MU-plugin review
Suspicious executable-file discovery
SSH, cron, service and network evidence collection
Plesk web-log triage and HTTP 5xx analysis
Optional heuristic PHP review
Per-site summary and detailed evidence output
SHA-256 evidence and archive integrity hashes
No remediation or automatic deletion
Designed for subsequent human security analysis

The tool records information including:

Operating system and Plesk versions
System PHP version and loaded modules
Plesk PHP versions and handlers
Installed PHP packages
Running PHP services and processes
Root and system cron configuration
Running and enabled systemd services
Listening network services
Established network connections
Successful SSH logins from retained authentication logs
Summary of failed SSH authentication attempts
Authorised SSH key fingerprints
Recently changed files under selected sensitive system paths
Recently created or modified executable files in temporary directories
WordPress collection
WordPress installations are automatically discovered under the standard Plesk virtual-host structure.

For each installation the tool collects:

Domain
Document root
Filesystem/subscription user
WordPress version
WordPress core checksum verification
Installed plugin inventory
Plugin checksum verification where authoritative checksums are available
Installed theme inventory
WordPress administrator accounts and registration dates
WordPress cron events
PHP, PHTML and PHAR files found under wp-content/uploads
Must-use plugin inventory
Recently modified PHP files
Executable PHP files
Potentially exposed backup, SQL and environment files
SHA-256 hashes of higher-interest files
Plesk web-log inventory and available log coverage
Occurrences of PHP_SESSION_UPLOAD_PROGRESS
Recent HTTP 5xx endpoint summary
Samples of recent POST requests resulting in 5xx responses
An optional deep scan searches WordPress content for a small set of PHP constructs commonly worth reviewing during compromise triage.

Requirements
The tool is intended for:

Linux
Plesk-hosted environments
WordPress installations using the standard Plesk virtual-host structure
Bash
Root or equivalent administrative access
WP-CLI
PHP CLI
Python 3
Standard Linux utilities including find, grep, awk, sed, ss, sha256sum, tar, runuser and ssh-keygen
WordPress installations are detected where the following structure exists:

/var/www/vhosts/<domain>/httpdocs/wp-config.php
WP-CLI checks are executed using the filesystem owner of each WordPress installation rather than as root.

Review the script before using it on a production system.

Installation
Clone or download the repository to the server.

Make the script executable:

chmod 700 plesk-wordpress-triage.sh
Run it with root privileges:

sudo ./plesk-wordpress-triage.sh
Administrative access is required so that the collector can read server configuration and Plesk logs. WordPress checks are subsequently executed under each site's filesystem user.

Usage
Standard triage
By default, the tool uses a 14-day review window for recent changes and log analysis:

sudo ./plesk-wordpress-triage.sh
Specify the review period
For example, to use a 30-day window:

sudo ./plesk-wordpress-triage.sh --days 30
The requested period cannot recover evidence that has already been rotated, deleted or was never logged.

Deep PHP review
Enable additional heuristic PHP searches with:

sudo ./plesk-wordpress-triage.sh --days 30 --deep
The deep scan searches PHP files under wp-content for selected constructs including:

eval(
base64_decode(
gzinflate(
shell_exec(
passthru(
proc_open(
These are heuristic indicators only.

Legitimate WordPress plugins and themes can use these functions. A match identifies a file for review; it does not establish that the file is malicious.

Specify an output location
sudo ./plesk-wordpress-triage.sh --output /root/client-evidence
Disable archive creation
sudo ./plesk-wordpress-triage.sh --no-archive
Help
./plesk-wordpress-triage.sh --help
Output
The tool creates a timestamped evidence directory, for example:

/root/wp-triage-servername-20261022T180000Z/
By default, it also creates a compressed archive and SHA-256 checksum:

wp-triage-servername-20261022T180000Z.tar.gz
wp-triage-servername-20261022T180000Z.tar.gz.sha256
The evidence directory itself also contains SHA256SUMS covering the collected evidence files.

Evidence is divided into:

os/
sites/
The main starting point for analysis is:

summary.tsv
The summary contains one row per detected WordPress installation and records:

Domain
Document root
Filesystem user
WordPress version
Core checksum status
Plugin-check status
Number of executable files identified under uploads
Must-use plugin file count
Administrator count
PHP_SESSION_UPLOAD_PROGRESS hit count
Recent HTTP 5xx count
Also review:

README.txt
manifest.txt
errors.txt
SHA256SUMS
A command failing does not necessarily stop the whole collection. errors.txt should therefore always be reviewed before relying on the resulting summary.

Interpreting results
The script is an evidence collector, not an automated compromise detector.

Findings should be considered together rather than treating any individual result as proof of compromise.

WordPress core
A successful core checksum result means that the WordPress core files checked matched the authoritative reference checksums for the installed version.

The --include-root check can also report additional files that are not part of the standard WordPress distribution.

Additional files are not automatically malicious. Examples may include:

.htaccess
certificate-validation files
server configuration
administrator-created files
backups
temporary files
Unexpected files should still be investigated.

A genuine WordPress core checksum mismatch warrants further review.

Plugin checks
A successfully verified plugin matched the checksum available to WP-CLI.

Commercial, custom, bundled and privately distributed plugins may not have authoritative checksums available through WordPress.org.

Treat plugin results as:

Verified: evidence supporting file integrity
Checksum mismatch: requires investigation
Skipped/unverified: inconclusive
An unverified plugin is not automatically malicious.

Executable files in uploads
PHP, PHTML or PHAR files under wp-content/uploads deserve review because upload directories normally contain uploaded content rather than application code.

Their presence does not automatically indicate compromise.

Legitimate security, caching and application plugins may create PHP files within upload directories.

Review the file's ownership, timestamp, hash, contents and expected purpose before taking action.

Must-use plugins
Files under:

wp-content/mu-plugins
are loaded automatically by WordPress.

Legitimate examples can include hosting-management and security components such as Plesk WordPress Toolkit.

Unknown or unexplained MU plugins warrant investigation because this location can also provide persistence for malicious code.

Administrator accounts
Every WordPress administrator account should be accounted for.

An unknown administrator, unexpected registration date or unexplained privilege change should be treated as an investigation lead.

The presence of multiple legitimate administrator accounts is not itself evidence of compromise.

PHP_SESSION_UPLOAD_PROGRESS
The tool searches retained Plesk access logs for:

PHP_SESSION_UPLOAD_PROGRESS
A match warrants investigation but does not prove that exploitation succeeded.

Likewise, no matches do not prove that exploitation did not occur.

HTTP 5xx responses
Internet-facing WordPress sites routinely receive automated probing.

Requests for paths such as:

.env
.git
wp-login.php
phpinfo.php
or requests for configuration files, backups, known plugin endpoints and randomly named PHP files may represent unsuccessful vulnerability scanning.

The presence of hostile requests does not demonstrate successful compromise.

HTTP 5xx activity should be assessed using surrounding evidence, including:

Date and time
Requested endpoint
Request method
Frequency
Source information
Related file changes
Authentication activity
Process or network events
Recent file changes
File timestamps are useful for developing an investigation timeline but are not proof of malicious activity.

WordPress updates, plugin changes, deployments, PHP upgrades and Plesk maintenance can all legitimately modify files.

File timestamps may also be manipulated.

Deep heuristic results
The --deep scan is deliberately broad and may generate false positives.

Functions such as base64_decode, eval, shell_exec, passthru and proc_open can occur in legitimate software.

A heuristic match means:

Review this file.

It does not mean:

This file is malware.

Overall assessment
A triage conclusion should be based on the combined evidence.

Appropriate wording might be:

The environment was exposed to a known vulnerability and experienced automated probing. Review of the available host, WordPress, authentication, integrity and web-log evidence identified no evidence of successful compromise.

This is preferable to describing a system as "clean".

Absence of evidence is not proof that compromise never occurred.

Where credible indicators of compromise are identified, preserve relevant evidence and consider escalation to formal incident response or digital forensic investigation before remediation destroys potentially useful artefacts.

Evidence handling
The generated evidence may contain sensitive information including:

Usernames
IP addresses
Authentication activity
Server paths
Installed software and versions
WordPress administrator information
Security-control details
File metadata
Network activity
Evidence should be:

Access-controlled
Stored securely
Protected during transfer
Restricted to personnel who require access
Retained only for as long as necessary
Securely deleted when no longer required
The collector deliberately avoids copying:

wp-config.php contents
Database credentials
.env contents
SSH key material
Full database dumps
Complete web access logs
The archive should nevertheless be treated as confidential security evidence.

Limitations
This tool performs initial triage against a live system.

Important limitations include:

It does not create a forensic disk or memory image.
It does not acquire volatile memory.
It does not inspect database contents for malicious WordPress records or payloads.
It does not validate commercial/custom plugin code against vendor originals when authoritative checksums are unavailable.
It does not prove that a system is or was uncompromised.
Log analysis is limited to evidence retained on the system at collection time.
Deleted, rotated or tampered-with logs may not be recoverable.
Reverse proxies, CDNs and other infrastructure can affect the source information recorded in origin logs.
Heuristic PHP searches can produce false positives.
The collector itself executes commands against a live system and therefore is not a forensically sterile acquisition process.
Where litigation, regulatory investigation, law-enforcement involvement or formal digital forensic analysis may be required, appropriate evidence-preservation procedures should be considered before further investigation.

Disclaimer
This tool is intended for authorised security triage and evidence collection from Plesk-hosted WordPress environments.

It collects system, PHP, WordPress, account, file-integrity, process and log information for subsequent security analysis. It does not remove malware, repair files, update software, change application configuration or remediate vulnerabilities.

The results must not be treated as proof that a system is secure, compromised or has never been compromised. Absence of identified indicators does not establish absence of compromise. Relevant evidence may have been deleted, altered, rotated, unavailable or outside the scope of the data examined.

WordPress checksum verification is limited to components for which authoritative checksums are available. Commercial, private and custom plugins or themes may therefore be reported as unverified. An unverified component should not, by itself, be considered malicious.

Use this tool only on systems that you own or for which you have explicit authority to conduct security investigation and evidence collection.

The tool may process personal, confidential and security-sensitive information contained in system and application data, including usernames, IP addresses, authentication events, server paths, installed software and security configuration.

Users are responsible for ensuring that collection, access, use, storage, transfer, retention and deletion of this information is lawful, proportionate and appropriately secured.

Where the tool is used on behalf of another organisation, the parties remain responsible for otentially relevant evidence.

Some checks depend on third-party services and reference data, including WordPress.org checksum information. The availability and completeness of those sources may affect the results.

This tool supports initial triage and evidence gathering. It is not a substitute for a full digital forensic investigation, incident-response engagement, penetration test, vulnerability assessment or professional security advice.

Licence and liability
This project is licensed under the Apache License 2.0. See the LICENSE file for the full licence terms.

The software is provided on an "as is" basis, without warranties or conditions of any kind. Use of the tool, interpretation of its output, and any actions taken as a result remain the responsibility of the user.

To the extent permitted by applicable law, Stiperstone and the project's contributors accept no liability for loss, damage, service interruption, data loss or other consequences arising from the use or misuse of this tool.

Nothing in this README modifies, replaces or overrides the terms of the Apache License 2.0 or, where the tool is supplied as part of a professional engagement, the applicable contractual terms.
