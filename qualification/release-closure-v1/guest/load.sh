#!/bin/bash
# Disposable load fixture: busy loops until the 1-minute load average reaches
# a target, then leaves them running until `stop`. Guest only.
set -u
PIDS=/home/nqacceptor/nq-load.pids
case "${1:-}" in
start)
  count=${2:-16}; target=${3:-4.5}; deadline=${4:-240}
  : > "$PIDS"
  for _ in $(seq "$count"); do
    setsid nohup sh -c 'while :; do :; done' >/dev/null 2>&1 &
    echo $! >> "$PIDS"
  done
  end=$((SECONDS + deadline))
  while :; do
    load=$(cut -d' ' -f1 /proc/loadavg)
    if awk -v l="$load" -v t="$target" 'BEGIN { exit !(l >= t) }'; then
      printf '{"reached":true,"loadavg1":"%s","cpus":%s,"busy_loops":%s}\n' "$load" "$(nproc)" "$count"
      exit 0
    fi
    if [ "$SECONDS" -ge "$end" ]; then
      printf '{"reached":false,"loadavg1":"%s","cpus":%s,"busy_loops":%s}\n' "$load" "$(nproc)" "$count"
      exit 1
    fi
    sleep 3
  done
  ;;
stop)
  if [ -f "$PIDS" ]; then xargs -r kill -9 < "$PIDS" 2>/dev/null; rm -f "$PIDS"; fi
  pkill -9 -f 'while :; do :; done' 2>/dev/null
  cut -d' ' -f1-3 /proc/loadavg
  ;;
*) echo "usage: load.sh start [count] [target] [deadline] | stop" >&2; exit 2 ;;
esac
