#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
# Copyright (c) 2026 NetIRC Defender
# NetIRC Defender V3 - network security service - start / stop / restart (Linux, BSD, macOS)
# Usage: ./defender.sh start|stop|restart|status
# Requires: perl, defender.pl in the same directory as this script.

BASEDIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PIDFILE="$BASEDIR/defender.pid"
PL="$BASEDIR/defender.pl"

is_running() {
	[ -f "$PIDFILE" ] || return 1
	pid=$(cat "$PIDFILE" 2>/dev/null)
	[ -n "$pid" ] || return 1
	kill -0 "$pid" 2>/dev/null
}

read_pid() {
	cat "$PIDFILE" 2>/dev/null
}

case "$1" in
	start)
		if is_running; then
			echo "defender: already running (pid $(read_pid))"
			exit 0
		fi
		if [ -f "$PIDFILE" ]; then
			echo "defender: removing stale pid file"
			rm -f "$PIDFILE"
		fi
		if [ ! -f "$PL" ]; then
			echo "defender: cannot find $PL"
			exit 1
		fi
		cd "$BASEDIR" || exit 1
		if ! command -v perl >/dev/null 2>&1; then
			echo "defender: perl not found in PATH"
			exit 1
		fi
		echo "defender: starting..."
		perl defender.pl || exit 1
		sleep 1
		if is_running; then
			echo "defender: started (pid $(read_pid))"
		else
			echo "defender: start failed or exited immediately (see defender.log / console)"
			exit 1
		fi
		;;
	stop)
		if [ ! -f "$PIDFILE" ]; then
			echo "defender: not running (no pid file)"
			exit 0
		fi
		pid=$(read_pid)
		if ! kill -0 "$pid" 2>/dev/null; then
			echo "defender: not running (removing stale pid file)"
			rm -f "$PIDFILE"
			exit 0
		fi
		echo "defender: sending SIGINT for graceful quit (pid $pid)..."
		kill -INT "$pid" 2>/dev/null || true
		i=0
		while [ "$i" -lt 15 ]; do
			kill -0 "$pid" 2>/dev/null || break
			sleep 1
			i=$((i + 1))
		done
		if kill -0 "$pid" 2>/dev/null; then
			echo "defender: still running; sending SIGKILL"
			kill -KILL "$pid" 2>/dev/null || true
			sleep 1
		fi
		rm -f "$PIDFILE"
		echo "defender: stopped"
		;;
	restart)
		"$0" stop
		sleep 1
		"$0" start
		;;
	status)
		if is_running; then
			echo "defender: running (pid $(read_pid))"
			exit 0
		else
			if [ -f "$PIDFILE" ]; then
				echo "defender: not running (stale pid file: $PIDFILE)"
				exit 1
			fi
			echo "defender: not running"
			exit 1
		fi
		;;
	*)
		echo "Usage: $0 {start|stop|restart|status}" >&2
		echo "  start   — run defender.pl (daemon mode unless --debug)" >&2
		echo "  stop    — SIGINT for clean IRC quit, then SIGKILL if needed" >&2
		echo "  restart — stop then start" >&2
		echo "  status  — print pid if running" >&2
		exit 2
		;;
esac
