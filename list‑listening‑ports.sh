#!/bin/sh
set -eu

ScriptName="List-Listening-Ports"
LogPath="/tmp/${ScriptName}-script.log"
ARLog="/var/ossec/logs/active-responses.log"
LogMaxKB=100
LogKeep=5
HostName="$(hostname)"
runStart="$(date +%s)"

WriteLog() {
  Message="$1"; Level="${2:-INFO}"
  ts="$(date '+%Y-%m-%d %H:%M:%S')"
  line="[$ts][$Level] $Message"
  printf '%s\n' "$line" >&2
  printf '%s\n' "$line" >> "$LogPath"
}

RotateLog() {
  [ -f "$LogPath" ] || return 0
  size_kb=$(du -k "$LogPath" | awk '{print $1}')
  [ "$size_kb" -le "$LogMaxKB" ] && return 0
  i=$((LogKeep-1))
  while [ $i -ge 0 ]; do
    [ -f "$LogPath.$i" ] && mv -f "$LogPath.$i" "$LogPath.$((i+1))"
    i=$((i-1))
  done
  mv -f "$LogPath" "$LogPath.1"
}

iso_now() { date -u +"%Y-%m-%dT%H:%M:%SZ"; }
escape_json() { printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'; }

BeginNDJSON() { TMP_AR="$(mktemp)"; }
AddRecord() {
  ts="$(iso_now)"
  proto_raw="$1"; port_raw="$2"; pid_raw="$3"; pname="$4"; ppath="$5"; laddr="$6"

  case "$pid_raw" in ''|-|*[!0-9]*) pid_num=0 ;; *) pid_num="$pid_raw" ;; esac
  case "$port_raw" in ''|-|*[!0-9]*) port_json="null" ;; *) port_json="$port_raw" ;; esac

  printf '{"timestamp":"%s","host":"%s","action":"%s","copilot_action":true,"protocol":"%s","port":%s,"pid":%s,"program":"%s","program_path":"%s","local_address":"%s"}\n' \
    "$ts" "$HostName" "$ScriptName" \
    "$(escape_json "$proto_raw")" "$port_json" "$pid_num" \
    "$(escape_json "$pname")" "$(escape_json "$ppath")" "$(escape_json "$laddr")" >> "$TMP_AR"
}
AddStatus() {
  ts="$(iso_now)"; st="${1:-info}"; msg="$(escape_json "${2:-}")"
  printf '{"timestamp":"%s","host":"%s","action":"%s","copilot_action":true,"status":"%s","message":"%s"}\n' \
    "$ts" "$HostName" "$ScriptName" "$st" "$msg" >> "$TMP_AR"
}

CommitNDJSON() {
  [ -s "$TMP_AR" ] || AddStatus "no_results" "no listening sockets parsed"
  AR_DIR="$(dirname "$ARLog")"
  [ -d "$AR_DIR" ] || WriteLog "Directory missing: $AR_DIR (will attempt write anyway)" WARN
  if mv -f "$TMP_AR" "$ARLog"; then
    WriteLog "Wrote NDJSON to $ARLog" INFO
  else
    WriteLog "Primary write FAILED to $ARLog" WARN
    if mv -f "$TMP_AR" "$ARLog.new"; then
      WriteLog "Wrote NDJSON to $ARLog.new (fallback)" WARN
    else
      keep="/tmp/active-responses.$$.ndjson"
      cp -f "$TMP_AR" "$keep" 2>/dev/null || true
      WriteLog "Failed to write both $ARLog and $ARLog.new; saved $keep" ERROR
      rm -f "$TMP_AR" 2>/dev/null || true
      exit 1
    fi
  fi
  for p in "$ARLog" "$ARLog.new"; do
    if [ -f "$p" ]; then
      sz=$(wc -c < "$p" 2>/dev/null || echo 0)
      ino=$(ls -li "$p" 2>/dev/null | awk '{print $1}')
      head1=$(head -n1 "$p" 2>/dev/null || true)
      WriteLog "VERIFY: path=$p inode=$ino size=${sz}B first_line=${head1:-<empty>}" INFO
    fi
  done
}

am_root() { [ "$(id -u)" -eq 0 ]; }
maybe_sudo() {
  if am_root; then "$@"
  elif command -v sudo >/dev/null 2>&1; then sudo "$@"
  else WriteLog "Not root and sudo not available: cannot install packages" WARN; return 1; fi
}

detect_pkg_mgr() {
  for m in apt-get dnf yum zypper pacman apk; do
    command -v "$m" >/dev/null 2>&1 && { echo "$m"; return 0; }
  done
  echo "none"
}

install_pkgs() {
  mgr="$(detect_pkg_mgr)"
  case "$mgr" in
    apt-get) WriteLog "Installing via apt-get: $*" INFO; maybe_sudo apt-get update -y >/dev/null 2>&1 || true; maybe_sudo apt-get install -y "$@" >/dev/null 2>&1 ;;
    dnf)     WriteLog "Installing via dnf: $*" INFO;     maybe_sudo dnf install -y "$@" >/dev/null 2>&1 ;;
    yum)     WriteLog "Installing via yum: $*" INFO;     maybe_sudo yum install -y "$@" >/dev/null 2>&1 ;;
    zypper)  WriteLog "Installing via zypper: $*" INFO;  maybe_sudo zypper -n install "$@" >/dev/null 2>&1 ;;
    pacman)  WriteLog "Installing via pacman: $*" INFO;  maybe_sudo pacman -Sy --noconfirm "$@" >/dev/null 2>&1 ;;
    apk)     WriteLog "Installing via apk: $*" INFO;     maybe_sudo apk add --no-cache "$@" >/dev/null 2>&1 ;;
    *)       WriteLog "No supported package manager found (need: $*)" WARN; return 1 ;;
  esac
}

ensure_tool() {
  bin="$1"; shift
  command -v "$bin" >/dev/null 2>&1 && return 0
  WriteLog "Missing dependency '$bin' — attempting installation..." WARN
  for pkg in "$@"; do
    if install_pkgs "$pkg"; then
      command -v "$bin" >/dev/null 2>&1 && { WriteLog "Installed '$bin' via '$pkg'." INFO; return 0; }
    fi
  done
  WriteLog "Failed to install '$bin' with packages: $*" ERROR
  return 1
}

ensure_dependencies() {
  have_lsof=0; have_ss=0
  command -v lsof >/dev/null 2>&1 || ensure_tool lsof lsof || true
  command -v lsof >/dev/null 2>&1 && have_lsof=1
  command -v ss >/dev/null 2>&1 || ensure_tool ss iproute2 iproute || true
  command -v ss >/dev/null 2>&1 && have_ss=1
  [ "$have_lsof" -eq 1 ] || [ "$have_ss" -eq 1 ]
}

collect_with_lsof() {
  lsof -nP -iTCP -sTCP:LISTEN -iUDP -F pcPnTn 2>/dev/null | awk '
    function flush() {
      if (pid != "" && P != "" && n != "") {
        laddr = n
        port = n
        sub(/^.*:/, "", port)
        proto = tolower(P)
        printf("%s\t%s\t%s\t%s\t%s\n", proto, port, pid, c, laddr)
      }
      pid=c=P=n=""
    }
    /^p/ { flush(); pid=substr($0,2) }
    /^c/ { c=substr($0,2) }
    /^P/ { P=substr($0,2) }
    /^n/ { n=substr($0,2) }
    END { flush() }
  ' | (
    TAB="$(printf '\t')"
    while IFS="$TAB" read -r proto port pid pname laddr; do
      [ -n "$proto" ] || continue
      [ -n "$port" ] || port="-"
      [ -n "$pid" ]  || pid="-"
      [ -n "$pname" ] || pname="-"
      [ -n "$laddr" ] || laddr="-"
      ppath="-"
      if [ "$pid" != "-" ] && [ -L "/proc/$pid/exe" ]; then
        ppath="$(readlink -f "/proc/$pid/exe" 2>/dev/null || echo "-")"
      fi
      AddRecord "$proto" "$port" "$pid" "$pname" "$ppath" "$laddr"
    done
  )
}

collect_with_ss() {
  ss -H -l -n -t -u -p 2>/dev/null | while IFS= read -r line; do
    proto=$(printf '%s' "$line" | awk '{print $1}' | tr '[:upper:]' '[:lower:]')
    laddr=$(printf '%s' "$line" | awk '{print $5}')
    port=$(printf '%s' "$laddr" | awk -F':' '{print $NF}')
    procseg=$(printf '%s' "$line" | sed -n 's/.*users:\[\(.*\)\].*/\1/p')
    pid="$(printf '%s' "$procseg" | sed -n 's/.*pid=\([0-9]\+\).*/\1/p')"; [ -n "$pid" ] || pid="-"
    pname="$(printf '%s' "$procseg" | sed -n 's/.*name="\([^"]*\)".*/\1/p')"; [ -n "$pname" ] || pname="-"
    ppath="-"
    [ "$pid" != "-" ] && ppath="$(readlink -f "/proc/$pid/exe" 2>/dev/null || echo "-")"
    AddRecord "$proto" "$port" "$pid" "$pname" "$ppath" "$laddr"
  done
}

RotateLog
WriteLog "=== SCRIPT START : $ScriptName (host=$HostName) ==="

BeginNDJSON
emitted=0

if ensure_dependencies; then
  if command -v lsof >/dev/null 2>&1; then
    WriteLog "Collecting with lsof" INFO
    collect_with_lsof || true
    emitted=1
  fi
  if [ "$emitted" -eq 0 ] && command -v ss >/dev/null 2>&1; then
    WriteLog "Collecting with ss" INFO
    collect_with_ss || true
    emitted=1
  fi
  [ "$emitted" -eq 1 ] || AddStatus "error" "Dependencies present but no collector executed"
else
  AddStatus "error" "Could not install or find required tools (lsof/ss)"
fi

CommitNDJSON
dur=$(( $(date +%s) - runStart ))
WriteLog "=== SCRIPT END : ${dur}s ==="
