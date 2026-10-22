#!/usr/bin/env bash
# Plesk / WordPress compromise triage collector
# Read-only evidence collection. Run as root on a Linux Plesk server.
# It does not prove or disprove compromise and does not repair/delete anything.
# Ian Simons Cyber& Data Protection www.cyber-data.co.uk

set -uo pipefail
IFS=$'\n\t'
umask 077

DAYS=14
OUTPUT_BASE="/root"
MAKE_ARCHIVE=1
DEEP=0

usage() {
  cat <<'EOF'
Usage: sudo ./plesk-wordpress-triage.sh [options]

Options:
  --days N          Review retained logs/recent changes for the last N days (default: 14)
  --output DIR      Store the evidence folder under DIR (default: /root)
  --deep            Add slower heuristic searches for suspicious PHP patterns
  --no-archive      Do not create a .tar.gz archive
  -h, --help        Show this help

Examples:
  sudo ./plesk-wordpress-triage.sh
  sudo ./plesk-wordpress-triage.sh --days 30 --output /root/client-evidence
  sudo ./plesk-wordpress-triage.sh --days 14 --deep
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --days) DAYS="${2:-}"; shift 2 ;;
    --output) OUTPUT_BASE="${2:-}"; shift 2 ;;
    --deep) DEEP=1; shift ;;
    --no-archive) MAKE_ARCHIVE=0; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage; exit 2 ;;
  esac
done

[[ "$DAYS" =~ ^[0-9]+$ ]] || { echo "--days must be a positive integer" >&2; exit 2; }
[[ "$DAYS" -ge 1 ]] || { echo "--days must be at least 1" >&2; exit 2; }
[[ $EUID -eq 0 ]] || { echo "Run this script as root so it can read Plesk logs and switch to subscription users." >&2; exit 1; }

HOST_SHORT="$(hostname -s 2>/dev/null || hostname)"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
CASE_DIR="${OUTPUT_BASE%/}/wp-triage-${HOST_SHORT}-${STAMP}"
OS_DIR="$CASE_DIR/os"
SITES_DIR="$CASE_DIR/sites"
mkdir -p "$OS_DIR" "$SITES_DIR"
chmod 700 "$CASE_DIR" "$OS_DIR" "$SITES_DIR"

LOG="$CASE_DIR/collector.log"
SUMMARY="$CASE_DIR/summary.tsv"
MANIFEST="$CASE_DIR/manifest.txt"
ERRORS="$CASE_DIR/errors.txt"
: > "$LOG"; : > "$ERRORS"
printf 'domain\tpath\towner\twp_version\tcore_check\tplugin_check\tupload_exec_count\tmu_file_count\tadmin_count\tphp2shell_hits\trecent_500_count\n' > "$SUMMARY"

log() { printf '[%s] %s\n' "$(date -u +%FT%TZ)" "$*" | tee -a "$LOG"; }

capture() {
  local outfile="$1"; shift
  {
    printf '$'
    printf ' %q' "$@"
    printf '\n\n'
    "$@"
  } >"$outfile" 2>&1
  local rc=$?
  printf '\n[exit_code=%s]\n' "$rc" >>"$outfile"
  if [[ $rc -ne 0 ]]; then
    printf '%s\t%s\t' "$(date -u +%FT%TZ)" "$rc" >> "$ERRORS"
    printf '%q ' "$@" >> "$ERRORS"
    printf '\n' >> "$ERRORS"
  fi
  return 0
}

run_as_owner() {
  local owner="$1" outfile="$2"; shift 2
  {
    printf '$ runuser -u %q --' "$owner"
    printf ' %q' "$@"
    printf '\n\n'
    runuser -u "$owner" -- "$@"
  } >"$outfile" 2>&1
  local rc=$?
  printf '\n[exit_code=%s]\n' "$rc" >>"$outfile"
  if [[ $rc -ne 0 ]]; then
    printf '%s\t%s\trunuser -u %q -- ' "$(date -u +%FT%TZ)" "$rc" "$owner" >> "$ERRORS"
    printf '%q ' "$@" >> "$ERRORS"
    printf '\n' >> "$ERRORS"
  fi
  return 0
}

first_existing_cmd() {
  local c
  for c in "$@"; do
    if command -v "$c" >/dev/null 2>&1; then command -v "$c"; return 0; fi
    if [[ -x "$c" ]]; then printf '%s\n' "$c"; return 0; fi
  done
  return 1
}

WP_BIN="$(first_existing_cmd wp /usr/local/bin/wp /usr/bin/wp 2>/dev/null || true)"

cat > "$CASE_DIR/README.txt" <<EOF
PLESK / WORDPRESS COMPROMISE TRIAGE EVIDENCE
Host: $HOST_SHORT
Collected UTC: $(date -u +%FT%TZ)
Recent window: $DAYS days
Deep heuristic scan: $DEEP

Purpose
- Collect read-only host and WordPress evidence for later analyst review.
- Automatically discovers WordPress installations at /var/www/vhosts/*/httpdocs/wp-config.php.
- Runs WP-CLI as each site's filesystem owner, not as root.

Important limitations
- This is a triage collector, not a forensic acquisition tool.
- A clean result does not prove that compromise never occurred.
- Plugin checksums are only authoritative where WordPress.org provides checksums.
- Logs may be incomplete because of rotation, retention, proxying or prior deletion.
- File timestamps can be changed and should not be treated as conclusive evidence.
- The archive contains sensitive operational data, usernames, IP addresses and paths.

Deliberate exclusions
- wp-config.php content and database credentials
- .env file contents
- SSH private/public key material (fingerprints only)
- full database dumps
- full web access logs
EOF

log "Collecting host evidence into $CASE_DIR"

# Host identity and patch/runtime inventory
capture "$OS_DIR/identity.txt" bash -lc 'date -u; hostname -f 2>/dev/null || hostname; uname -a; cat /etc/os-release 2>/dev/null; uptime'
capture "$OS_DIR/plesk-version.txt" bash -lc 'plesk version 2>&1 || true'
capture "$OS_DIR/php-cli.txt" bash -lc 'command -v php; readlink -f "$(command -v php)" 2>/dev/null; php -v 2>&1; php -m 2>&1'
capture "$OS_DIR/plesk-php-directories.txt" bash -lc 'ls -la /opt/plesk/php 2>/dev/null || true; for p in /opt/plesk/php/*/bin/php; do [ -x "$p" ] && "$p" -v | head -2; done'
capture "$OS_DIR/plesk-php-handlers.txt" bash -lc 'plesk bin php_handler --list 2>&1 || true'
capture "$OS_DIR/php-packages.txt" bash -lc 'dpkg-query -W -f="${binary:Package}\t${db:Status-Abbrev}\t${Version}\n" "php*" 2>/dev/null | sort || true'
capture "$OS_DIR/running-php.txt" bash -lc 'systemctl --type=service --state=running 2>/dev/null | grep -i php || true; echo; ps -eo pid,user,lstart,cmd | grep -E "[p]hp-fpm|[p]hp-cgi" || true'

# Persistence and access
capture "$OS_DIR/root-crontab.txt" bash -lc 'crontab -l -u root 2>&1 || true'
capture "$OS_DIR/cron-inventory.txt" bash -lc 'for d in /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly; do echo "### $d"; ls -lah "$d" 2>/dev/null || true; done'
capture "$OS_DIR/systemd-running.txt" bash -lc 'systemctl --type=service --state=running --no-pager 2>/dev/null || true'
capture "$OS_DIR/systemd-enabled.txt" bash -lc 'systemctl list-unit-files --type=service --state=enabled --no-pager 2>/dev/null || true'
capture "$OS_DIR/listeners.txt" ss -lntup
capture "$OS_DIR/established-connections.txt" bash -lc 'ss -tunap 2>/dev/null | grep ESTAB || true'
capture "$OS_DIR/accepted-ssh-logins.txt" bash -lc 'zgrep -h "Accepted " /var/log/auth.log* 2>/dev/null || true'
capture "$OS_DIR/failed-ssh-summary.txt" bash -lc 'zgrep -h "Failed password" /var/log/auth.log* 2>/dev/null | awk "{print \$(NF-3),\$(NF)}" | sort | uniq -c | sort -nr | head -100 || true'

# Fingerprint authorised keys without copying key material.
{
  echo "Authorised key files and fingerprints only"
  while IFS= read -r f; do
    echo "### $f"
    stat -c 'owner=%U group=%G mode=%a modified=%y' "$f" 2>/dev/null || true
    ssh-keygen -lf "$f" 2>/dev/null || echo "Unable to fingerprint"
  done < <(find /root /home -name authorized_keys -type f -print 2>/dev/null)
} > "$OS_DIR/authorised-key-fingerprints.txt"

capture "$OS_DIR/recent-sensitive-path-changes.txt" bash -lc "find /etc /usr/local/bin /usr/local/sbin -xdev -type f -mtime -$DAYS -printf '%TY-%Tm-%Td %TH:%TM:%TS %u:%g %m %s %p\\n' 2>/dev/null | sort || true"
capture "$OS_DIR/temp-executable-files.txt" bash -lc "find /tmp /var/tmp /dev/shm -xdev -type f -mtime -$DAYS -perm /111 -printf '%TY-%Tm-%Td %TH:%TM:%TS %u:%g %m %s %p\\n' 2>/dev/null | sort || true"

# Detect WordPress sites.
mapfile -t WP_CONFIGS < <(find /var/www/vhosts -mindepth 3 -maxdepth 4 -type f -path '*/httpdocs/wp-config.php' -print 2>/dev/null | sort)
log "Discovered ${#WP_CONFIGS[@]} WordPress installation(s)"

for config in "${WP_CONFIGS[@]}"; do
  site_path="$(dirname "$config")"
  domain="$(basename "$(dirname "$site_path")")"
  owner="$(stat -c '%U' "$site_path" 2>/dev/null || echo unknown)"
  safe_domain="$(printf '%s' "$domain" | tr -cd 'A-Za-z0-9._-')"
  site_dir="$SITES_DIR/$safe_domain"
  mkdir -p "$site_dir"
  chmod 700 "$site_dir"
  log "Collecting site: $domain (owner=$owner path=$site_path)"

  {
    echo "domain=$domain"
    echo "path=$site_path"
    echo "owner=$owner"
    stat -c 'group=%G mode=%a modified=%y' "$site_path" 2>/dev/null || true
    stat -c 'wp_config_owner=%U wp_config_group=%G wp_config_mode=%a wp_config_modified=%y' "$config" 2>/dev/null || true
  } > "$site_dir/site-metadata.txt"

  wp_version="unknown"
  core_status="not_run"
  plugin_status="not_run"
  admin_count="unknown"

  if [[ -n "$WP_BIN" && "$owner" != "unknown" ]]; then
    run_as_owner "$owner" "$site_dir/wp-version.txt" "$WP_BIN" core version --path="$site_path" --skip-plugins --skip-themes
    wp_version="$(grep -vE '^\$|^\[exit_code=' "$site_dir/wp-version.txt" | sed '/^[[:space:]]*$/d' | tail -1 | tr '\t' ' ' || true)"

    run_as_owner "$owner" "$site_dir/core-checksums.txt" "$WP_BIN" core verify-checksums --include-root --path="$site_path" --skip-plugins --skip-themes
    if grep -q 'Success: WordPress installation verifies against checksums' "$site_dir/core-checksums.txt"; then core_status="pass"; elif grep -qE 'Error:|doesn.t verify|does not verify' "$site_dir/core-checksums.txt"; then core_status="review"; else core_status="inconclusive"; fi

    run_as_owner "$owner" "$site_dir/plugin-list.tsv" "$WP_BIN" plugin list --path="$site_path" --format=csv --fields=name,status,update,version,update_version,auto_update
    run_as_owner "$owner" "$site_dir/plugin-checksums.txt" "$WP_BIN" plugin verify-checksums --all --path="$site_path"
    if grep -q 'Success: Verified' "$site_dir/plugin-checksums.txt"; then plugin_status="partial_or_pass"; elif grep -qE 'Warning:.*checksum|Error:' "$site_dir/plugin-checksums.txt"; then plugin_status="review"; else plugin_status="inconclusive"; fi

    run_as_owner "$owner" "$site_dir/theme-list.tsv" "$WP_BIN" theme list --path="$site_path" --format=csv --fields=name,status,update,version,update_version,auto_update
    # Avoid email addresses in the output; collect only fields needed to review administrators.
    run_as_owner "$owner" "$site_dir/administrators.csv" "$WP_BIN" user list --role=administrator --path="$site_path" --fields=ID,user_login,user_registered,roles --format=csv
    admin_count="$(grep -vE '^\$|^ID,' "$site_dir/administrators.csv" | grep -v '^\[' | sed '/^[[:space:]]*$/d' | wc -l | tr -d ' ')"
    run_as_owner "$owner" "$site_dir/wp-cron-events.txt" "$WP_BIN" cron event list --path="$site_path" --fields=hook,next_run_gmt,next_run_relative,recurrence --format=table
  else
    echo "WP-CLI not available, or owner could not be determined" > "$site_dir/wp-cli-unavailable.txt"
  fi

  uploads_count="$(find "$site_path/wp-content/uploads" -type f \( -iname '*.php' -o -iname '*.phtml' -o -iname '*.phar' -o -iname '*.php[0-9]' \) 2>/dev/null | wc -l | tr -d ' ')"
  find "$site_path/wp-content/uploads" -type f \( -iname '*.php' -o -iname '*.phtml' -o -iname '*.phar' -o -iname '*.php[0-9]' \) -printf '%TY-%Tm-%Td %TH:%TM:%TS\t%u:%g\t%m\t%s\t%p\n' 2>/dev/null | sort > "$site_dir/executable-files-in-uploads.tsv"

  mu_count="$(find "$site_path/wp-content/mu-plugins" -type f 2>/dev/null | wc -l | tr -d ' ')"
  find "$site_path/wp-content/mu-plugins" -type f -printf '%TY-%Tm-%Td %TH:%TM:%TS\t%u:%g\t%m\t%s\t%p\n' 2>/dev/null | sort > "$site_dir/mu-plugin-files.tsv"

  find "$site_path" -xdev -type f \( -iname '*.php' -o -iname '*.phtml' -o -iname '*.phar' \) -mtime "-$DAYS" -printf '%TY-%Tm-%Td %TH:%TM:%TS\t%u:%g\t%m\t%s\t%p\n' 2>/dev/null | sort > "$site_dir/recent-php-files.tsv"
  find "$site_path" -xdev -type f \( -iname '*.php' -o -iname '*.phtml' -o -iname '*.phar' \) -perm /111 -printf '%TY-%Tm-%Td %TH:%TM:%TS\t%u:%g\t%m\t%s\t%p\n' 2>/dev/null | sort > "$site_dir/executable-php-files.tsv"
  find "$site_path" -xdev -type f \( -name '.env' -o -name '*.sql' -o -name '*.sql.gz' -o -name '*.zip' -o -name '*.tar.gz' -o -name '*.bak' -o -name '*~' \) -printf '%TY-%Tm-%Td %TH:%TM:%TS\t%u:%g\t%m\t%s\t%p\n' 2>/dev/null | sort > "$site_dir/sensitive-or-backup-files.tsv"

  # Hash higher-interest files without collecting their contents.
  {
    cut -f5- "$site_dir/executable-files-in-uploads.tsv" 2>/dev/null
    cut -f5- "$site_dir/recent-php-files.tsv" 2>/dev/null
  } | sort -u | while IFS= read -r f; do [[ -f "$f" ]] && sha256sum "$f"; done > "$site_dir/review-file-sha256.txt"

  logs_dir="/var/www/vhosts/system/$domain/logs"
  php2shell_hits=0
  recent_500_count=0
  if [[ -d "$logs_dir" ]]; then
    find "$logs_dir" -maxdepth 1 -type f -printf '%TY-%Tm-%Td %TH:%TM:%TS\t%s\t%f\n' 2>/dev/null | sort > "$site_dir/log-inventory.tsv"

    # Search retained plain and gzip logs. Output only matching records, not complete logs.
    {
      find "$logs_dir" -maxdepth 1 -type f \( -name '*access*log*' -o -name '*proxy*log*' \) -print0 2>/dev/null |
      while IFS= read -r -d '' lf; do
        case "$lf" in
          *.gz) zgrep -H -i 'PHP_SESSION_UPLOAD_PROGRESS' "$lf" 2>/dev/null || true ;;
          *) grep -H -i 'PHP_SESSION_UPLOAD_PROGRESS' "$lf" 2>/dev/null || true ;;
        esac
      done
    } > "$site_dir/php-session-upload-progress-hits.txt"
    php2shell_hits="$(wc -l < "$site_dir/php-session-upload-progress-hits.txt" | tr -d ' ')"

    # Build a combined, date-filtered view of retained access logs using Python.
    python3 - "$logs_dir" "$DAYS" "$site_dir" <<'PY'
import os, sys, re, gzip, datetime, collections
logs_dir, days, outdir = sys.argv[1], int(sys.argv[2]), sys.argv[3]
cutoff = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=days)
rx_date = re.compile(r'\[([^\]]+)\]')
rx_req = re.compile(r'"(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+([^\s"]+)')
rx_status = re.compile(r'"\s+(\d{3})\s')
counts = collections.Counter()
post500 = []
coverage = []
for name in sorted(os.listdir(logs_dir)):
    if 'access' not in name or 'log' not in name: continue
    path = os.path.join(logs_dir, name)
    if not os.path.isfile(path): continue
    opener = gzip.open if name.endswith('.gz') else open
    first_dt = last_dt = None
    try:
        with opener(path, 'rt', errors='replace') as fh:
            for line in fh:
                m = rx_date.search(line)
                if not m: continue
                try: dt = datetime.datetime.strptime(m.group(1), '%d/%b/%Y:%H:%M:%S %z')
                except ValueError: continue
                first_dt = first_dt or dt; last_dt = dt
                if dt < cutoff: continue
                sm = rx_status.search(line); rm = rx_req.search(line)
                if not sm or not rm: continue
                status, uri = sm.group(1), rm.group(1)
                if status.startswith('5'):
                    counts[(status, uri)] += 1
                    if '"POST ' in line: post500.append(line.rstrip())
        if first_dt: coverage.append((name, first_dt.isoformat(), last_dt.isoformat()))
    except (OSError, EOFError) as e:
        coverage.append((name, 'ERROR', str(e)))
with open(os.path.join(outdir, 'log-coverage.tsv'), 'w') as f:
    f.write('file\tfirst_record\tlast_record\n')
    for row in coverage: f.write('\t'.join(row)+'\n')
with open(os.path.join(outdir, 'recent-5xx-summary.tsv'), 'w') as f:
    f.write('count\tstatus\turi\n')
    for (status, uri), count in counts.most_common(200): f.write(f'{count}\t{status}\t{uri}\n')
with open(os.path.join(outdir, 'recent-post-5xx-samples.log'), 'w') as f:
    for line in post500[:500]: f.write(line+'\n')
with open(os.path.join(outdir, 'recent-5xx-count.txt'), 'w') as f:
    f.write(str(sum(counts.values()))+'\n')
PY
    recent_500_count="$(cat "$site_dir/recent-5xx-count.txt" 2>/dev/null || echo unknown)"
  else
    echo "No Plesk log directory found at $logs_dir" > "$site_dir/logs-not-found.txt"
  fi

  if [[ "$DEEP" -eq 1 ]]; then
    # Heuristic only. False positives are expected; no files are altered.
    grep -RIlE --include='*.php' --exclude-dir=cache --exclude-dir=vendor --exclude-dir=node_modules \
      'eval[[:space:]]*\(|base64_decode[[:space:]]*\(|gzinflate[[:space:]]*\(|shell_exec[[:space:]]*\(|passthru[[:space:]]*\(|proc_open[[:space:]]*\(' \
      "$site_path/wp-content" 2>/dev/null | sort > "$site_dir/deep-heuristic-php-hits.txt" || true
  fi

  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$domain" "$site_path" "$owner" "$wp_version" "$core_status" "$plugin_status" \
    "$uploads_count" "$mu_count" "$admin_count" "$php2shell_hits" "$recent_500_count" >> "$SUMMARY"
done

# Final inventory and integrity manifest.
{
  echo "Collector completed UTC: $(date -u +%FT%TZ)"
  echo "Host: $HOST_SHORT"
  echo "Case directory: $CASE_DIR"
  echo "Sites discovered: ${#WP_CONFIGS[@]}"
  echo "WP-CLI: ${WP_BIN:-not found}"
  echo "Days: $DAYS"
  echo "Deep: $DEEP"
} > "$MANIFEST"

find "$CASE_DIR" -type f ! -name 'SHA256SUMS' -print0 | sort -z | xargs -0 sha256sum > "$CASE_DIR/SHA256SUMS"
chmod -R go-rwx "$CASE_DIR"

if [[ "$MAKE_ARCHIVE" -eq 1 ]]; then
  archive="${CASE_DIR}.tar.gz"
  tar -C "$(dirname "$CASE_DIR")" -czf "$archive" "$(basename "$CASE_DIR")"
  chmod 600 "$archive"
  sha256sum "$archive" > "${archive}.sha256"
  chmod 600 "${archive}.sha256"
  log "Archive created: $archive"
  log "Archive checksum: ${archive}.sha256"
fi

log "Collection complete. Review: $SUMMARY"
echo
echo "Evidence folder: $CASE_DIR"
[[ "$MAKE_ARCHIVE" -eq 1 ]] && echo "Evidence archive: ${CASE_DIR}.tar.gz"
echo "Treat the output as confidential client evidence."
