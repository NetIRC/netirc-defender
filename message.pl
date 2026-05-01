#!/usr/bin/perl
#
# SPDX-License-Identifier: GPL-2.0-only
# Copyright (c) 2026 NetIRC Defender
#
# NetIRC Defender V3 - network security service

use POSIX qw(strftime);

sub _cmsg {
	my ($plain, $colored) = @_;
	message(($ugly ? $plain : $colored));
}

sub _info_defender_footer {
	my ($snap) = @_;
	my $d = $snap->{defender_server} // '';
	return if $d eq '';
	_cmsg(
		"  \002This instance\002 (\002$d\002): yep, that's me on the link — hehe.",
		"\00305  \00302\002This instance\017 (\00310\002$d\017\00302)\00306: yep, that's me on the link — hehe.\017"
	);
}

sub _is_ircop {
	my ($nick) = @_;
	return 0 unless defined $nick && $nick ne '';
	return 0 unless defined &main::isoper;
	return main::isoper($nick) ? 1 : 0;
}

sub _deny_ircop_only {
	my ($cmd) = @_;
	$cmd = 'this command' unless defined $cmd && $cmd ne '';
	_cmsg(
		"Access denied: IRC operators only ($cmd).",
		"\00304Access denied:\017 \00306IRC operators only (\00302$cmd\00306).\017"
	);
}

sub _run_module_stats {
	my ($mod) = @_;
	no strict 'refs';
	my $sym = "Modules::Scan::${mod}::stats";
	return unless defined &{$sym};
	eval { &{$sym}() };
	print $@ if $@;
}

sub _run_module_cmd_help {
	my ($mod) = @_;
	no strict 'refs';
	my $sym = "Modules::Scan::${mod}::cmd_help";
	return 0 unless defined &{$sym};
	eval { &{$sym}() };
	print $@ if $@;
	return 1;
}

sub _run_handle_notice {
	my ($mod, $sNick, $sIdent, $sHost, $target, $message) = @_;
	no strict 'refs';
	my $sym = "Modules::Scan::${mod}::handle_notice";
	return unless defined &{$sym};
	eval { &{$sym}($sNick, $sIdent, $sHost, $target, $message) };
	print $@ if $@;
}

sub _run_handle_privmsg {
	my ($mod, $sNick, $sIdent, $sHost, $target, $sMessage) = @_;
	no strict 'refs';
	my $sym = "Modules::Scan::${mod}::handle_privmsg";
	return unless defined &{$sym};
	eval { &{$sym}($sNick, $sIdent, $sHost, $target, $sMessage) };
	print $@ if $@;
}

# CTCP flood guard: $CTCP_BURST replies per $CTCP_WINDOW seconds per nick;
# state per nick discarded after $CTCP_MUTE seconds of inactivity.
my %CTCP_HITS;
my %CTCP_LAST;
our $CTCP_BURST   = 3;
our $CTCP_WINDOW  = 10;
our $CTCP_MUTE    = 300;
our $CTCP_GC_KEYS = 1024;

sub _ctcp_gc {
	my $now = time;
	for my $k (keys %CTCP_LAST) {
		if (($now - $CTCP_LAST{$k}) > $CTCP_MUTE) {
			delete $CTCP_LAST{$k};
			delete $CTCP_HITS{$k};
		}
	}
}

sub _ctcp_allow {
	my ($who) = @_;
	return 1 unless defined $who && $who ne '';
	my $key = lc($who);
	my $now = time;
	_ctcp_gc() if scalar(keys %CTCP_LAST) > $CTCP_GC_KEYS;
	if (exists $CTCP_LAST{$key} && ($now - $CTCP_LAST{$key}) > $CTCP_MUTE) {
		delete $CTCP_HITS{$key};
	}
	$CTCP_LAST{$key} = $now;
	my $arr = $CTCP_HITS{$key} ||= [];
	@$arr = grep { ($now - $_) <= $CTCP_WINDOW } @$arr;
	if (scalar(@$arr) >= $CTCP_BURST) {
		return 0;
	}
	push @$arr, $now;
	return 1;
}

sub _ctcp_sanitize_arg {
	my ($s, $max) = @_;
	return '' unless defined $s;
	$max = 50 unless defined $max && $max > 0;
	$s =~ s/[\x00-\x1F\x7F]//g;
	$s = substr($s, 0, $max) if length($s) > $max;
	return $s;
}

sub noticehandler {
	my $raw = shift;

	unless ($raw =~ /^:(.+?)\sNOTICE\s(.+?)\s:(.+?)$/xi) {
		print "Bad input to noticehandler: $raw\n";
		return;
	}

	my ($sNick, $sIdent, $sHost, $target, $message) = ($1, '', '', $2, $3);

	if($sNick =~ /^([^!]+)!([^@]+)\@(\S+)/) {
		$sNick = $1;
		$sIdent = $2;
		$sHost = $3;
	}

	my $bot_numnick = (defined &main::bot_numnick) ? main::bot_numnick() : '';
	if ((lc($target) eq lc($botnick))
	    || ($bot_numnick ne '' && $target eq $bot_numnick)) {
		$target = $sNick;
	}

	$message = quotemeta($message);
	$sNick = quotemeta($sNick);
	$sIdent = quotemeta($sIdent);
	$sHost = quotemeta($sHost);
	$target = quotemeta($target);

	foreach my $mod (@modlist) {
		_run_handle_notice($mod, $sNick, $sIdent, $sHost, $target, $message);
	}
}


sub msghandler {
	my $raw = shift;

	unless ($raw =~ /^:(.+?)\sPRIVMSG\s(.+?)\s:(.+?)$/xi) {
		print "Bad input to msghandler: $raw\n";
		return;
	}

	my ($sNick, $sIdent, $sHost, $target, $message) = ($1, '', '', $2, $3);

	if($sNick =~ /^([^!]+)!([^@]+)\@(\S+)/) {
		$sNick = $1;
		$sIdent = $2;
		$sHost = $3;
	}

	my $bot_numnick = (defined &main::bot_numnick) ? main::bot_numnick() : '';
	my $is_to_bot = (lc($target) eq lc($botnick))
		|| ($bot_numnick ne '' && $target eq $bot_numnick);
	if ($is_to_bot) {
		$target = $sNick;
	}

	if ($is_to_bot && $message =~ /^\001([A-Za-z]+)(?:\s+(.*?))?\001?$/) {
		my $ctcp = uc($1);
		my $arg  = defined $2 ? $2 : '';
		my %known = map { $_ => 1 } qw(VERSION TIME USERINFO PING CLIENTINFO);
		if ($known{$ctcp}) {
			if (!_ctcp_allow($sNick)) {
				print "[CTCP] dropping $ctcp from $sNick (rate limit)\n" if $debug;
				return;
			}
			if ($ctcp eq 'VERSION') {
				notice($sNick, "\001VERSION NetIRC Defender V3 - network security service\001");
			} elsif ($ctcp eq 'TIME') {
				notice($sNick, "\001TIME Time you got a watch?\001");
			} elsif ($ctcp eq 'USERINFO') {
				notice($sNick, "\001USERINFO I'm a user, not an abuser\001");
			} elsif ($ctcp eq 'PING') {
				my $pingarg = _ctcp_sanitize_arg($arg, 50);
				notice($sNick, "\001PING $pingarg\001");
			} elsif ($ctcp eq 'CLIENTINFO') {
				notice($sNick, "\001CLIENTINFO VERSION TIME USERINFO PING CLIENTINFO\001");
			}
			return;
		}
	}

	my $sMessage = quotemeta($message);
	$sNick = grep (/^uuidnick$/, @provides) ? $uuidnick{quotemeta($sNick)} :
	         quotemeta($sNick);
	$sIdent = quotemeta($sIdent);
	$sHost = quotemeta($sHost);
	$target = quotemeta($target);

	foreach my $mod (@modlist) {
		_run_handle_privmsg($mod, $sNick, $sIdent, $sHost, $target, $sMessage);
	}

	if (lc($target) eq quotemeta(lc($mychan)))
	{
		my $needs_ircop =
			($message =~ /^info(?:\s+.*)?$/i) ||
			($message =~ /^status(?:\s+.*)?$/i) ||
			($message =~ /^help(?:\s+.*)?$/i);
		if ($needs_ircop && !_is_ircop($sNick)) {
			my $cmd =
				($message =~ /^info/i)   ? 'info'   :
				($message =~ /^help/i)   ? 'help'   :
				'status';
			_deny_ircop_only($cmd);
			return;
		}

		if ($message =~ /^\Q$botnick\E\s+shutdown\s*$/i) {
			if (!_is_ircop($sNick)) {
				_deny_ircop_only('shutdown');
				return;
			}
			&shutdown;
			return;
		}

		if ($message =~ /^help(?:\s+(\S+))?\s*$/i) {
			my $which = $1 // '';
			$which =~ s/^\s+|\s+$//g;
			if ($which ne '') {
				my $found;
				for my $mod (@modlist) {
					next unless lc($mod) eq lc($which);
					$found = $mod;
					last;
				}
				if (!defined $found) {
					my $list = join(', ', @modlist);
					_cmsg(
						"No scan module named \002$which\002. Loaded: \002$list\002. Use \002help\002 for the full list.",
						"\00304No scan module named \00302\002$which\017\00304.\017 \00306Loaded:\017 \00302$list\017\00306. Use \00302\002help\017\00306 for the full list.\017"
					);
					return;
				}
				_cmsg(
					"\002Help\002 — module \002$found\002:",
					"\00305\002Help\017 \00306— module \00310\002$found\017\00306:\017"
				);
				if (!_run_module_cmd_help($found)) {
					_cmsg(
						"Module \002$found\002 is loaded; there is no extra channel-command help for it (automatic / background only).",
						"\00306Module \00302\002$found\017\00306 is loaded; no extra channel-command help (automatic / background only).\017"
					);
				}
				return;
			}

			_cmsg(
				"\002NetIRC Defender\002 — commands on \002$mychan\002 (depends on loaded modules).",
				"\00302\002NetIRC Defender\017\00305 — commands on \00310\002$mychan\017\00306 (depends on loaded modules).\017"
			);
			_cmsg(
				"\002help\002 / \002help <module>\002 — this list or one module's commands. Active scan modules: \002" . (scalar @modlist) . "\002.",
				"\00302\002help\017 \00306/\017 \00302\002help <module>\017 \00306— full list or one module. Active scan modules: \00302\002" . (scalar @modlist) . "\017\00306.\017"
			);
			_cmsg(
				"\002info\002, \002info help\002 — network snapshot. Same family: \002info servers\002, \002info users\002, \002info chans\002.",
				"\00302\002info\017\00306, \00302\002info help\017 \00306— snapshot. \00302info servers\017\00306, \00302info users\017\00306, \00302info chans\017\00306.\017"
			);
			_cmsg(
				"\002ip\002, \002whois\002, \002seen\002 — GeoIP / link snapshot / last-seen. Details: \002help ipinfo\002, \002help whois\002, \002help seen\002 when those modules are loaded.",
				"\00302\002ip\017\00306, \00302\002whois\017\00306, \00302\002seen\017 \00306— GeoIP / snapshot / last-seen. \00302\002help ipinfo\017\00306, \00302\002help whois\017\00306, \00302\002help seen\017 \00306if loaded.\017"
			);
			_cmsg(
				"\002status\002, \002status all\002, \002status <module>\002 — uptime, metrics, per-module stats.",
				"\00302\002status\017\00306, \00302\002status all\017\00306, \00302\002status <module>\017 \00306— uptime, metrics, per-module stats.\017"
			);
			_cmsg(
				"\002$botnick rehash\002 — reload configuration and scan modules. \002$botnick shutdown\002 — shut down the bot.",
				"\00302\002$botnick rehash\017\00306 — reload config/modules. \00302\002$botnick shutdown\017\00306 — shut down.\017"
			);
			_cmsg(
				"— Module-specific commands (loaded now) —",
				"\00305— Module-specific commands (loaded now) —\017"
			);
			for my $mod (@modlist) {
				if (_run_module_cmd_help($mod)) {
					next;
				}
				_cmsg(
					"\002[$mod]\002 (loaded) — no interactive channel commands documented; see \002status $mod\002.",
					"\00305\002[$mod]\017 \00306(loaded) — no interactive channel commands in help; see \00302\002status $mod\017\00306.\017"
				);
			}
			return;
		}

		if ($message =~ /^info(?:\s+(servers|users(?:\s+list)?|chans(?:\s+list)?|channels(?:\s+list)?|help))?$/i) {
			my $sub = lc($1 // '');
			my $users_dump = ($sub eq 'users list');
			my $chans_dump = ($sub eq 'chans list' || $sub eq 'channels list');
			$sub = 'users' if $users_dump;
			$sub = 'chans' if $chans_dump;
			$sub = 'chans' if $sub eq 'channels';
			if ($sub eq 'help') {
				_cmsg(
					"Command index: \002help\002 / \002help <module>\002 lists commands for loaded modules.",
					"\00306Command index:\017 \00302\002help\017 \00306/\017 \00302\002help <module>\017 \00306— loaded modules.\017"
				);
				_cmsg(
					"\002info\002: P10 link snapshot. Subcommands: \002info servers\002, \002info users\002, \002info chans\002. Lookups: \002ip\002, \002whois\002, \002seen\002 (link cache / last event).",
					"\00305\002info\017\00306: P10 link snapshot. Subcommands: \00302\002info servers\017\00306, \00302\002info users\017\00306, \00302\002info chans\017\00306. Lookups: \00302\002ip\017\00306, \00302\002whois\017\00306, \00302\002seen\017\00306.\017"
				);
				_cmsg(
					"Channels are names observed on this link during the current session (JOIN traffic only), not a complete map of the network.",
					"\00306Channels are names observed on this link during the current session (JOIN traffic only), not a complete map of the network.\017"
				);
				_cmsg(
					"\002info users\002: cached client counts per known server (\0020\002 if none homed there); \002info users list\002: capped nick list.",
					"\00302\002info users\017\00306: counts per known server (\00302\0020\00306 if none homed there); \00302\002info users list\017\00306: capped nick list.\017"
				);
				_cmsg(
					"\002info chans\002: per uplink server, how many distinct channel names had at least one JOIN from a user on that server (same #channel can appear on several servers — row counts do not sum to the global total). \002info chans list\002: flat list of global distinct names (capped).",
					"\00302\002info chans\017\00306: per uplink server, distinct channel names with JOIN from a user on that server (overlap across rows). \00302\002info chans list\017\00306: global distinct names (capped).\017"
				);
				_cmsg(
					"\002killchan\002: on the bot channel, \002add\002 / \002del\002 / \002list\002 require uplink oper (others get access denied). Non-opers who \002join\002 a listed channel get a G-line after \002killchan_join_grace_sec\002 unless they \002part\002 first. \002JOIN-only:\002 users already inside are not scanned until they rejoin.",
					"\00302\002killchan\017\00306: \00302add\017\00306 / \00302del\017\00306 / \00302list\017\00306 on the bot channel — \00306uplink oper required.\017 G-line for non-opers after \00302killchan_join_grace_sec\017\00306; \00306part cancels.\017 \00306\002JOIN-only:\017 not scanned until rejoin.\017"
				);
				return;
			}
			if (!defined &main::network_info_snapshot) {
				_cmsg(
					"\002info\002 is not available for the current link module.",
					"\00304\002info\017\00306 is not available for the current link module.\017"
				);
				return;
			}
			my $snap = main::network_info_snapshot();
			my $cap = 60;
			my $dump = sub {
				my ($title, $arr) = @_;
				my $n = @$arr;
				_cmsg(
					"$title (\002$n\002 total):",
					"\00305\002$title\017 (\00302$n\00305 total):\017"
				);
				my $show = ($n <= $cap) ? $n : $cap;
				for my $i (0 .. $show - 1) {
					_cmsg(
						"  " . $arr->[$i],
						"\00305  \00306" . $arr->[$i] . "\017"
					);
				}
				_cmsg(
					"  ... and \002" . ($n - $cap) . "\002 more (output capped at $cap lines).",
					"\00305  ... and \00302" . ($n - $cap) . "\00305 more (output capped at $cap lines).\017"
				) if $n > $cap;
			};
			if ($sub eq '') {
				my $ns = @{ $snap->{servers} };
				my $nu = @{ $snap->{users} };
				my $nc = @{ $snap->{chans} };
				_cmsg(
					"\002NetIRC Defender V3 - network security service\002 | \002Network snapshot\002: \002$ns\002 server(s), \002$nu\002 user(s) on link, \002$nc\002 channel name(s) seen on JOIN.",
					"\00302\002NetIRC Defender V3\017\00305 - network security service \00310| \00305Network snapshot:\017 \00302$ns\00306 server(s), \00302$nu\00306 user(s) on link, \00302$nc\00306 channel name(s) seen on JOIN.\017"
				);
				_cmsg(
					"Use \002info servers\002, \002info users\002 / \002info chans\002, or \002info help\002. (Users are partitioned by server; channel per-server rows overlap — do not add them to match the channel total.)",
					"\00306Use \00302\002info servers\017\00306, \00302\002info users\017\00306 / \00302\002info chans\017\00306, or \00302\002info help\017\00306. Users by server sum to the user total; channel rows do not sum to the distinct-channel total.\017"
				);
				return;
			}
			if ($sub eq 'servers') {
				$dump->("Servers", $snap->{servers});
				_info_defender_footer($snap);
				return;
			}
			if ($sub eq 'users') {
				if ($users_dump) {
					$dump->("Users (cached nicks, capped)", $snap->{users});
					return;
				}
				my $rows = $snap->{users_by_server} || [];
				my $total = @{ $snap->{users} };
				_cmsg(
					"\002Users on link\002: \002$total\002 client(s) in cache, by server (\0020\002 = none homed there). Sorted by count, then name:",
					"\00305\002Users on link\017: \00302\002$total\00306 client(s) in cache, by server (\00302\0020\00306 = none homed there). Sorted by count, then name:\017"
				);
				if (!@$rows) {
					_cmsg("  (no clients in cache.)", "\00306  (no clients in cache.)\017");
					_info_defender_footer($snap);
					return;
				}
				for my $row (@$rows) {
					my ($srv, $cnt) = @$row;
					_cmsg(
						sprintf("  \002%d\002  %s", $cnt, $srv),
						sprintf("\00305  \00302\002%d\017  \00306%s\017", $cnt, $srv)
					);
				}
				_info_defender_footer($snap);
				_cmsg(
					"For a partial nick list: \002info users list\002.",
					"\00306For a partial nick list: \00302\002info users list\017\00306.\017"
				);
				return;
			}
			if ($sub eq 'chans') {
				if ($chans_dump) {
					$dump->("Channel names (distinct, capped)", $snap->{chans});
					return;
				}
				my $rows = $snap->{chans_by_server} || [];
				my $total = @{ $snap->{chans} };
				_cmsg(
					"\002$total\002 globally distinct channel name(s) seen on JOIN (each #channel counted once network-wide).",
					"\00305\002$total\00306 globally distinct channel name(s) seen on JOIN (each #channel once network-wide).\017"
				);
				_cmsg(
					"Per uplink server: distinct channels that had at least one JOIN from a user homed there (same #channel may appear on multiple rows — row counts do not add up to $total).",
					"\00306Per uplink server: distinct channels with JOIN from a user on that server (rows overlap; do not sum to \00302$total\00306).\017"
				);
				if (!@$rows) {
					_cmsg("  (no channel JOIN data in cache.)", "\00306  (no channel JOIN data in cache.)\017");
					return;
				}
				for my $row (@$rows) {
					my ($srv, $cnt) = @$row;
					_cmsg(
						sprintf("  \002%d\002  %s", $cnt, $srv),
						sprintf("\00305  \00302\002%d\017  \00306%s\017", $cnt, $srv)
					);
				}
				_cmsg(
					"For a partial flat list: \002info chans list\002 (also \002info channels list\002).",
					"\00306For a partial flat list: \00302\002info chans list\017\00306 (also \00302\002info channels list\017\00306).\017"
				);
				return;
			}
		}

		if ($message =~ /^status all/i) {
			_cmsg(
				"\002NetIRC Defender V3\002 — network security service | \002Full module report\002",
				"\00302\002NetIRC Defender V3\017\00305 — network security service \00310| \00305\002Full module report\017"
			);
			message(" ");
			_cmsg(
				"Transport: \002$CONNECT_TYPE\002",
				"\00305Transport:\017 \00302\002$CONNECT_TYPE\017"
			);
			message(" ");
			foreach my $mod (@modlist) {
				_cmsg(
					"Module: \002$mod\002",
					"\00305Module:\017 \00310\002$mod\017"
				);
				message(" ");
				_run_module_stats($mod);
				message(" ");
			}
			my $modtotal = $#modlist+1;
			_cmsg(
				"Scan modules: \002$modtotal\002 loaded",
				"\00305Scan modules:\017 \00302\002$modtotal\00306 loaded\017"
			);
			return;
		}

		if ($message =~ /^\Q$botnick rehash\E$/i) {
			if (!_is_ircop($sNick)) {
				_deny_ircop_only('rehash');
				return;
			}
			message("Rehashing...");
			&rehash;
			foreach my $line (@rehash_data) {
				message($line);
			}
			message("Rehash complete.");
		}

		if ($message =~ /^status/i) {
			_cmsg(
				"\002NetIRC Defender V3\002 — network security service | \002Operational status\002",
				"\00302\002NetIRC Defender V3\017\00305 — network security service \00310| \00305\002Operational status\017"
			);
			if ($message !~ /^status\s+(\S+)$/i)
			{
				my $started_at = strftime("%Y-%m-%d %H:%M:%S", localtime($START_TIME));
				my $started_weekday = strftime("%A", localtime($START_TIME));
				my $delta = time - $START_TIME;
				my $s = $delta;
				my $weeks = int($s / 604800); $s %= 604800;
				my $days = int($s / 86400);   $s %= 86400;
				my $hours = int($s / 3600);   $s %= 3600;
				my $mins = int($s / 60);      $s %= 60;
				my $secs = $s;
				my $uptime = '';
				if ($weeks) { $uptime .= $weeks == 1 ? "$weeks week, " : "$weeks weeks, "; }
				if ($days)  { $uptime .= $days == 1 ? "$days day, " : "$days days, "; }
				if ($hours) { $uptime .= $hours == 1 ? "$hours hour, " : "$hours hours, "; }
				if ($mins)  { $uptime .= $mins == 1 ? "$mins minute, " : "$mins minutes, "; }
				$uptime .= ($secs == 1) ? "$secs second" : "$secs seconds";

				_cmsg(
					"Process started: \002$started_at\002 (\002$started_weekday\002, local time). Current uptime: \002$uptime\002.",
					"\00305Process started:\017 \00302\002$started_at\017 \00306(\00302$started_weekday\00306, local). \00305Current uptime:\017 \00302\002$uptime\017\00306.\017"
				);
				if ($persistent_counters_enabled) {
					_cmsg(
						"Metrics (this run / cumulative): client sign-ons \002$CONNECTS\002 / \002$CONNECTS_LIFE\002 · Defender removals (KILL/G-line) \002$KILLED\002 / \002$KILLED_LIFE\002 · third-party KILL events \002$KILL_SEEN_OTHER\002 / \002$KILL_SEEN_OTHER_LIFE\002",
						"\00305Metrics (this run / cumulative):\017 client sign-ons \00302\002$CONNECTS\017 / \00302\002$CONNECTS_LIFE\017 \00306· removals \00302\002$KILLED\017 / \00302\002$KILLED_LIFE\017 \00306· third-party KILLs \00302\002$KILL_SEEN_OTHER\017 / \00302\002$KILL_SEEN_OTHER_LIFE\017"
					);
					if (defined $PERSISTENT_COUNTERS_SINCE && $PERSISTENT_COUNTERS_SINCE > 0) {
						my $cum_at = strftime("%Y-%m-%d %H:%M:%S", localtime($PERSISTENT_COUNTERS_SINCE));
						my $cum_wd = strftime("%A", localtime($PERSISTENT_COUNTERS_SINCE));
						_cmsg(
							"Cumulative totals since: \002$cum_at\002 (\002$cum_wd\002, local time).",
							"\00306Cumulative totals since:\017 \00302\002$cum_at\017 \00306(\00302$cum_wd\00306, local).\017"
						);
					}
				} else {
					_cmsg(
						"Metrics (this run): client sign-ons \002$CONNECTS\002 · Defender removals \002$KILLED\002 · third-party KILL events \002$KILL_SEEN_OTHER\002",
						"\00305Metrics (this run):\017 client sign-ons \00302\002$CONNECTS\017 \00306· removals \00302\002$KILLED\017 \00306· third-party KILLs \00302\002$KILL_SEEN_OTHER\017"
					);
				}

				my $scanlist = join(", ", @modlist);
				my $link = defined($linkmodule) ? $linkmodule : 'p10';
				my $nscan = $#modlist + 1;
				_cmsg(
					"Uplink: \002$link\002 · Active scan modules (\002$nscan\002): \002$scanlist\002",
					"\00305Uplink:\017 \00310\002$link\017 \00306· Active scan modules (\00302$nscan\00306): \00306$scanlist\017"
				);

				my @prov_clean = grep { length } map { my $x = $_; $x =~ s/\s+\z//; $x } @provides;
				my %link_cap = map { $_ => 1 } qw(core-v1 server p10-server native-gline encoded);
				my @prov_link = grep { $link_cap{$_} } @prov_clean;
				my $plink = join(', ', @prov_link);
				my $nprov_link = @prov_link;
				_cmsg(
					"Core / uplink stack (\002$nprov_link\002): \002$plink\002",
					"\00305Core / uplink stack\017 (\00302$nprov_link\00305):\017 \00306$plink\017"
				);
			} else {
				$message =~ /^status\s+(\S+)$/i;
				my $module = $1;
				message(" ");
				_cmsg(
					"Transport: \002$CONNECT_TYPE\002",
					"\00305Transport:\017 \00302\002$CONNECT_TYPE\017"
				);
				message(" ");

				foreach my $mod (@modlist) {
					if (($module eq "") || ($mod =~ /^\Q$module\E$/i)) {
						_cmsg(
							"Scan module: \002$mod\002",
							"\00305Scan module:\017 \00310\002$mod\017"
						);
						message(" ");
						_run_module_stats($mod);
						message(" ");
					}
				}

				my $modtotal = $#modlist+1;
				_cmsg(
					"Scan modules: \002$modtotal\002 loaded",
					"\00305Scan modules:\017 \00302\002$modtotal\00306 loaded\017"
				);
			}
		}
	}
}


1;
