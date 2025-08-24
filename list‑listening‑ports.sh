#!/bin/sh
set -eu

ScriptName="List-Listening-Ports"
LogPath="/tmp/${ScriptName}-script.log"
ARLog="/var/ossec/active-response/active-responses.log"
LogMaxKB=100
LogKeep=5
HostName="$(hostname)"
runStart="$(date +%s)"

WriteLog() {
  Message="$1"; Level="${2:-INFO}"
  ts="$(date '+%Y-%m-%d %H:%M:%S%z')"
  line="[$ts][$Level] $Message"
  printf '%s\n' "$line" >&2
  printf '%s\n' "$line" >> "$LogPath"
}

RotateLog() {
  [ -f "$LogPath" ] || return 0
  size_kb="$(awk -v s="$(wc -c <"$LogPath")" 'BEGIN{printf "%.0f", s/1024}')"
  [ "$size_kb" -le "$LogMaxKB" ] && return 0
  i=$((LogKeep-1))
  while [ $i -ge 1 ]; do
    src="$LogPath.$i"; dst="$LogPath.$((i+1))"
    [ -f "$src" ] && mv -f "$src" "$dst" || true
    i=$((i-1))
  done
  mv -f "$LogPath" "$LogPath.1"
}

escape_json() {
  printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'
}

BeginNDJSON() {
  TMP_AR="$(mktemp)"
}

AddRecord() {
  ts="$(date '+%Y-%m-%d %H:%M:%S%z')"
  proto="$(escape_json "$1")"
  port="$(escape_json "$2")"
  pid="$(escape_json "$3")"
  program="$(escape_json "$4")"
  program_path="$(escape_json "$5")"
  laddr="$(escape_json "$6")"
  printf '{"timestamp":"%s","host":"%s","action":"%s","copilot_action":true,"protocol":"%s","port":"%s","pid":"%s","program":"%s","program_path":"%s","local_address":"%s"}\n' \
    "$ts" "$HostName" "$ScriptName" "$proto" "$port" "$pid" "$program" "$program_path" "$laddr" >> "$TMP_AR"
}

AddError() {
  ts="$(date '+%Y-%m-%d %H:%M:%S%z')"
  msg="$(escape_json "$1")"
  printf '{"timestamp":"%s","host":"%s","action":"%s","copilot_action":true,"status":"error","message":"%s"}\n' \
    "$ts" "$HostName" "$ScriptName" "$msg" >> "$TMP_AR"
}

CommitNDJSON() {
  if [ ! -s "$TMP_AR" ]; then
    AddError "No listening sockets parsed"
  fi
  if mv -f "$TMP_AR" "$ARLog" 2>/dev/null; then
    :
  else
    mv -f "$TMP_AR" "$ARLog.new" 2>/dev/null || printf '{"timestamp":"%s","host":"%s","action":"%s","copilot_action":true,"status":"error","message":"atomic move failed"}\n' \
      "$(date '+%Y-%m-%d %H:%M:%S%z')" "$HostName" "$ScriptName" > "$ARLog.new"
  fi
}
am_root() { [ "$(id -u)" -eq 0 ]; }
maybe_sudo() {
  if am_root; then
    "$@"
  elif command -v sudo >/dev/null 2>&1; then
    sudo "$@"
  else
    WriteLog "Not root and sudo not available: cannot install packages" WARN
    return 1
  fi
}

detect_pkg_mgr() {
  for m in apt-get dnf yum zypper pacman apk; do
    if command -v "$m" >/dev/null 2>&1; then
      echo "$m"; return 0
    fi
  done
  echo "none"
}

install_pkgs() {
  mgr="$(detect_pkg_mgr)"
  case "$mgr" in
    apt-get)
      WriteLog "Installing packages via apt-get: $*" INFO
      maybe_sudo apt-get update -y >/dev/null 2>&1 || true
      maybe_sudo apt-get install -y "$@" >/dev/null 2>&1
      ;;
    dnf)
      WriteLog "Installing packages via dnf: $*" INFO
      maybe_sudo dnf install -y "$@" >/dev/null 2>&1
      ;;
    yum)
      WriteLog "Installing packages via yum: $*" INFO
      maybe_sudo yum install -y "$@" >/dev/null 2>&1
      ;;
    zypper)
      WriteLog "Installing packages via zypper: $*" INFO
      maybe_sudo zypper -n install "$@" >/dev/null 2>&1
      ;;
    pacman)
      WriteLog "Installing packages via pacman: $*" INFO
      maybe_sudo pacman -Sy --noconfirm "$@" >/dev/null 2>&1
      ;;
    apk)
      WriteLog "Installing packages via apk: $*" INFO
      maybe_sudo apk add --no-cache "$@" >/dev/null 2>&1
      ;;
    *)
      WriteLog "No supported package manager found (need: $*)" WARN
      return 1
      ;;
  esac
}

ensure_tool() {
  bin="$1"; shift
  if command -v "$bin" >/dev/null 2>&1; then
    return 0
  fi
  WriteLog "Missing dependency '$bin' — attempting installation..." WARN
  for pkg in "$@"; do
    if install_pkgs "$pkg"; then
      if command -v "$bin" >/dev/null 2>&1; then
        WriteLog "Installed '$bin' via package '$pkg'." INFO
        return 0
      fi
    fi
  done
  WriteLog "Failed to install '$bin' with packages: $*" ERROR
  return 1
}

ensure_dependencies() {
  have_lsof=0; have_ss=0

  if command -v lsof >/dev/null 2>&1; then have_lsof=1; else
    ensure_tool lsof lsof || true
    command -v lsof >/dev/null 2>&1 && have_lsof=1 || have_lsof=0
  fi

  if command -v ss >/dev/null 2>&1; then have_ss=1; else
    ensure_tool ss iproute2 iproute || true
    command -v ss >/dev/null 2>&1 && have_ss=1 || have_ss=0
  fi
  if [ "$have_lsof" -eq 1 ] || [ "$have_ss" -eq 1 ]; then
    return 0
  fi
  return 1
}
collect_with_lsof() {
  # parseable output; numeric addrs/ports
  lsof -nP -iTCP -sTCP:LISTEN -iUDP -F pcPnTn 2>/dev/null | awk '
    function flush() {
      if (pid != "" && P != "" && n != "") {
        laddr = n
        port = n
        sub(/^.*:/, "", port)     # last colon piece as port
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
    pid="$(printf '%s' "$procseg" | sed -n 's/.*pid=\([0-9]\+\).*/\1/p')"
    [ -n "$pid" ] || pid="-"
    pname="$(printf '%s' "$procseg" | sed -n 's/.*name="\([^"]*\)".*/\1/p')"
    [ -n "$pname" ] || pname="-"
    ppath="-"
    [ "$pid" != "-" ] && ppath="$(readlink -f "/proc/$pid/exe" 2>/dev/null || echo "-")"
    AddRecord "$proto" "$port" "$pid" "$pname" "$ppath" "$laddr"
  done
}
RotateLog
WriteLog "START $ScriptName"

BeginNDJSON

if ensure_dependencies; then
  used=""
  if command -v lsof >/dev/null 2>&1; then
    WriteLog "Collecting with lsof" INFO
    collect_with_lsof || true
    used="lsof"
  elif command -v ss >/dev/null 2>&1; then
    WriteLog "Collecting with ss" INFO
    collect_with_ss || true
    used="ss"
  fi
  [ -n "$used" ] || AddError "Dependencies present but no collector executed"
else
  AddError "Could not install or find required tools (lsof/ss)"
fi

CommitNDJSON
dur=$(( $(date +%s) - runStart ))
WriteLog "END $ScriptName in ${dur}s"
