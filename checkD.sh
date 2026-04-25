#!/usr/bin/env bash
#
# SPDX-License-Identifier: GPL-2.0-only
# Copyright (c) 2026 NetIRC Defender
#
# checkD.sh — watchdog for NetIRC Defender V3 (Linux production).
# Intended for cron only (reboot / crash recovery). For manual start|stop|restart|status
# use defender.sh in the same directory.
# Run from cron (e.g. every minute) so the bot restarts after reboot or crash.
#
# Crontab example (same UNIX user that should own the Defender process):
#   crontab -e
#   * * * * * /full/path/to/defender-master/checkD.sh >/dev/null 2>&1
#
# Logging:
#   Default log file: ./checkD.log (same directory as this script), or CHECKD_LOG=...
#   Always logged: ERROR lines, and each restart ("Defender not running; starting...").
#   Defender early output: ./nohup.out (until Main::daemon forks).
# Optional environment:
#   PERL=/usr/bin/perl
#   CHECKD_LOG=/var/log/checkD.log
#   CHECKD_DEBUG=1           — verbose traces to stderr + log file
#   CHECKD_LOG_EVERY_RUN=1   — one audit line on every cron invocation (OK / lock-skip / restart)

set -u

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PIDFILE="$DIR/defender.pid"
LOCKFILE="$DIR/.checkD.lock"
PERL_BIN="${PERL:-perl}"
DEFENDER_PL="$DIR/defender.pl"
LOG="${CHECKD_LOG:-$DIR/checkD.log}"

debug() {
	if [[ "${CHECKD_DEBUG:-}" == "1" ]]; then
		echo "$(date '+%Y-%m-%d %H:%M:%S' 2>/dev/null || date) [checkD:debug] $*" >&2
		echo "$(date '+%Y-%m-%d %H:%M:%S' 2>/dev/null || date) [checkD:debug] $*" >>"$LOG" 2>/dev/null || true
	fi
}

log() {
	echo "$(date '+%Y-%m-%d %H:%M:%S' 2>/dev/null || date) $*" >>"$LOG"
}

log_every_run() {
	[[ "${CHECKD_LOG_EVERY_RUN:-}" == "1" ]] || return 0
	log "checkD: $*"
}

is_running() {
	[[ -f "$PIDFILE" ]] || { debug "pidfile missing: $PIDFILE"; return 1; }
	local pid
	pid="$(head -1 "$PIDFILE" 2>/dev/null | tr -d ' \r\n\t')"
	[[ "$pid" =~ ^[0-9]+$ ]] || { debug "pidfile not a numeric PID: [$pid]"; return 1; }
	kill -0 "$pid" 2>/dev/null || { debug "kill -0 failed for pid=$pid (stale pidfile?)"; return 1; }
	if [[ -r "/proc/$pid/cmdline" ]]; then
		if ! tr '\0' ' ' <"/proc/$pid/cmdline" | grep -q 'defender\.pl'; then
			debug "pid $pid cmdline does not mention defender.pl — treating as not running"
			return 1
		fi
	fi
	debug "Defender appears running (pid=$pid)"
	return 0
}

[[ -f "$DEFENDER_PL" ]] || { log "checkD: ERROR: missing $DEFENDER_PL"; exit 1; }
command -v "$PERL_BIN" >/dev/null 2>&1 || PERL_BIN="perl"
command -v "$PERL_BIN" >/dev/null 2>&1 || { log "checkD: ERROR: perl not found in PATH"; exit 1; }

debug "DIR=$DIR PERL_BIN=$PERL_BIN LOCKFILE=$LOCKFILE"

exec 200>"$LOCKFILE" || exit 1
flock -n 200 || {
	debug "flock busy — another checkD.sh still running, exit 0"
	log_every_run "skip (lock held by another checkD.sh)"
	exit 0
}

if is_running; then
	debug "already running, nothing to do"
	_run_pid="$(head -1 "$PIDFILE" 2>/dev/null | tr -d ' \r\n\t')"
	log_every_run "OK (defender pid ${_run_pid})"
	exit 0
fi

log "checkD: Defender not running; starting from $DIR"
cd "$DIR" || exit 1
nohup "$PERL_BIN" "$DEFENDER_PL" >>"$DIR/nohup.out" 2>&1 &
_wrapper_pid=$!
log "checkD: nohup issued (wrapper pid ${_wrapper_pid}); child pid will be written to $PIDFILE after connect+daemon"
debug "nohup wrapper pid=${_wrapper_pid} nohup.out=$DIR/nohup.out pidfile=$PIDFILE"
exit 0
