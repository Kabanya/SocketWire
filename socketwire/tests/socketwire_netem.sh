#!/usr/bin/env bash
set -euo pipefail

ANCHOR="com.apple/socketwire_netem"
PIPE_ID="${SOCKETWIRE_NETEM_PIPE_ID:-42}"
PORT="${SOCKETWIRE_NETEM_PORT:-15001}"
PROTO="${SOCKETWIRE_NETEM_PROTO:-udp}"

filter_pfctl_noise() {
  sed \
    -e '/^pfctl: Use of -f option, could result in flushing of rules$/d' \
    -e '/^present in the main ruleset added by the system at startup\.$/d' \
    -e '/^See \/etc\/pf\.conf for further details\.$/d' \
    -e '/^No ALTQ support in kernel$/d' \
    -e '/^ALTQ related functions disabled$/d' \
    -e '/^pf enabled$/d' \
    -e '/^pf already enabled$/d' \
    -e '/^Token : [0-9][0-9]*$/d' \
    -e '/^$/d'
}

run_pfctl() {
  sudo pfctl "$@" 2> >(filter_pfctl_noise >&2)
}

usage() {
  cat <<USAGE
Usage:
  $0 start <profile> [port]
  $0 stop
  $0 status
  $0 help

Profiles:
  perfect_lan       delay 0ms, loss 0%, unlimited bandwidth
  normal_online     delay 30ms, loss 0.5%, unlimited bandwidth
  bad_wifi          delay 60ms, loss 3%, bandwidth 1Mbit/s
  high_ping         delay 150ms, loss 2%, bandwidth 1Mbit/s
  loss_10           delay 60ms, loss 10%, bandwidth 1Mbit/s
  low_bandwidth     delay 60ms, loss 1%, bandwidth 64Kbit/s
  very_bad          delay 100ms, loss 25%, bandwidth 512Kbit/s

Environment:
  SOCKETWIRE_NETEM_PORT      default: 15001
  SOCKETWIRE_NETEM_PROTO     default: udp
  SOCKETWIRE_NETEM_PIPE_ID   default: 42

The script uses sudo pfctl/dnctl on macOS and never runs from ctest.
USAGE
}

profile_args() {
  case "$1" in
    perfect_lan)
      echo "delay 0ms plr 0"
      ;;
    normal_online)
      echo "delay 30ms plr 0.005"
      ;;
    bad_wifi)
      echo "delay 60ms plr 0.03 bw 1Mbit/s"
      ;;
    high_ping)
      echo "delay 150ms plr 0.02 bw 1Mbit/s"
      ;;
    loss_10)
      echo "delay 60ms plr 0.10 bw 1Mbit/s"
      ;;
    low_bandwidth)
      echo "delay 60ms plr 0.01 bw 64Kbit/s"
      ;;
    very_bad)
      echo "delay 100ms plr 0.25 bw 512Kbit/s"
      ;;
    *)
      echo "Unknown profile: $1" >&2
      return 1
      ;;
  esac
}

start_profile() {
  local profile="$1"
  local port="${2:-$PORT}"
  local args
  args="$(profile_args "$profile")"

  sudo dnctl "pipe" "$PIPE_ID" config $args

  printf '%s\n' \
    "dummynet in proto $PROTO from any to any port $port pipe $PIPE_ID" \
    "dummynet out proto $PROTO from any port $port to any pipe $PIPE_ID" \
    | run_pfctl -a "$ANCHOR" -f -

  run_pfctl -E >/dev/null || true

  echo "SocketWire netem enabled: profile=$profile proto=$PROTO port=$port pipe=$PIPE_ID"
}

stop_profile() {
  printf '' | run_pfctl -a "$ANCHOR" -f -
  sudo dnctl pipe delete "$PIPE_ID" 2>/dev/null || true
  echo "SocketWire netem disabled for anchor=$ANCHOR pipe=$PIPE_ID"
}

status_profile() {
  echo "PF anchor rules:"
  run_pfctl -a "$ANCHOR" -s rules || true
  echo
  echo "Dummynet pipe:"
  sudo dnctl pipe show "$PIPE_ID" || true
}

case "${1:-help}" in
  start)
    if [[ $# -lt 2 ]]; then
      usage
      exit 2
    fi
    start_profile "$2" "${3:-$PORT}"
    ;;
  stop)
    stop_profile
    ;;
  status)
    status_profile
    ;;
  help|--help|-h)
    usage
    ;;
  *)
    usage
    exit 2
    ;;
esac
