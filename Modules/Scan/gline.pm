#
# SPDX-License-Identifier: GPL-2.0-only
# Copyright (c) 2026 NetIRC Defender
#
# NetIRC Defender V3 - network security service

package Modules::Scan::gline;

use strict;
use warnings;
use Socket ();

# Default duration applied when no [time] is given to "gline add".
my $DEFAULT_TIME   = 3600;
my $DEFAULT_REASON = "Banned by NetIRC Defender";

# %glines: mask => { added => epoch, expire => epoch, who => nick|sid|server,
#                    reason => str, remote => 0|1 }
# "remote" entries were learned via P10 GL broadcasts (other opers / servers /
# netburst). Local entries are those added via the "gline add" command.
my %glines;
my $g_added       = 0;
my $g_removed     = 0;
my $g_remote_add  = 0;
my $g_remote_del  = 0;

# Filled by handle_gline() while $main::GLINE_STATS_INFLIGHT is true. Used by
# handle_gline_burst_done() to drop entries that exist locally but were not
# returned by the IRCd's STATS g reply — i.e. glines that have been removed
# (or expired) on the server while the bot was disconnected. Reset on each
# burst close.
my %burst_seen;

sub _glines_file { return "$main::dir/glines.conf"; }

# message.pl quotemeta()s nick / target / payload before dispatching to scan
# modules; undo it for safe parsing/printing.
sub _dsp {
	my ($s) = @_;
	return '' unless defined $s;
	$s =~ s/\\(.)/$1/g;
	return $s;
}

# Mirror of message.pl::_cmsg: pick the plain or colour-formatted variant
# according to the global $ugly switch in defender.conf, then push it to the
# control channel via main::message.
sub _cmsg {
	my ($plain, $colored) = @_;
	main::message(($main::ugly ? $plain : $colored));
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
		"\002[GLINE]\002 Access denied: IRC operators only ($cmd).",
		"\00305\002[GLINE]\017 \00304Access denied:\017 \00306IRC operators only (\00302$cmd\00306).\017"
	);
}

sub _save {
	my $f = _glines_file();
	open(my $fh, '>', $f) or do {
		_cmsg(
			"\002[GLINE]\002 Cannot save list ($f): $!",
			"\00305\002[GLINE]\017 \00304\002Cannot save list\017 \00306($f): $!\017"
		);
		return;
	};
	foreach my $mask (sort keys %glines) {
		my $r = $glines{$mask};
		print $fh join("\t",
			$mask,
			$r->{added}  // 0,
			$r->{expire} // 0,
			$r->{who}    // 'unknown',
			$r->{reason} // $DEFAULT_REASON,
			($r->{remote} ? 1 : 0),
		), "\n";
	}
	close $fh;
}

sub _load {
	%glines = ();
	my $f = _glines_file();
	return unless -e $f;
	open(my $fh, '<', $f) or return;
	while (my $line = <$fh>) {
		chomp $line;
		next if $line eq '' || $line =~ /^\s*#/;
		my ($mask, $added, $expire, $who, $reason, $remote) = split(/\t/, $line, 6);
		next unless defined $mask && $mask ne '' && defined $expire;
		$glines{$mask} = {
			added  => 0 + ($added  // time),
			expire => 0 + ($expire // 0),
			who    => ($who    // 'unknown'),
			reason => ($reason // $DEFAULT_REASON),
			remote => (defined $remote && $remote eq '1') ? 1 : 0,
		};
	}
	close $fh;
}

# Drop locally-cached entries whose expiry has already passed; the IRCd will
# have done the same on its side.
sub _purge_expired {
	my $now = time;
	my $changed = 0;
	foreach my $mask (keys %glines) {
		if (($glines{$mask}{expire} // 0) <= $now) {
			delete $glines{$mask};
			$changed = 1;
		}
	}
	_save() if $changed;
	return $changed;
}

# Accepted formats: bare digits = minutes (TCL-style); <N>(s|m|h|d|w).
sub _parse_time {
	my ($s) = @_;
	return undef unless defined $s && $s ne '';
	if ($s =~ /^(\d+)$/) {
		return $1 * 60;
	}
	if ($s =~ /^(\d+)\s*([smhdw])$/i) {
		my ($n, $u) = ($1, lc $2);
		return $n              if $u eq 's';
		return $n * 60         if $u eq 'm';
		return $n * 3600       if $u eq 'h';
		return $n * 86400      if $u eq 'd';
		return $n * 604800     if $u eq 'w';
	}
	return undef;
}

# Loose IPv4 (del / legacy); use _strict_ipv4 for gline add.
sub _is_ipv4 { return defined $_[0] && $_[0] =~ /^(\d{1,3}\.){3}\d{1,3}$/; }

sub _strict_ipv4 {
	my ($ip) = @_;
	return 0 unless defined $ip && $ip =~ /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
	for my $o ($1, $2, $3, $4) {
		return 0 if $o > 255;
	}
	return 1;
}

sub _is_ipv6 { return defined $_[0] && $_[0] =~ /:/ && $_[0] =~ /^[0-9A-Fa-f:.]+$/; }

# Hostname shape (FQDN-style), aligned with ipinfo.pm.
sub _is_hostname {
	my ($name) = @_;
	return 0 unless defined $name && $name ne '';
	return 0 if $name =~ /\s/;
	return 0 if $name =~ /^\./ || $name =~ /\.$/;
	return 0 unless $name =~ /^[A-Za-z0-9.-]+$/;
	return 0 unless $name =~ /\./;
	return 1;
}

sub _is_host { return _is_hostname($_[0]); }

sub _dns_resolves {
	my ($host) = @_;
	return 0 unless defined $host && $host ne '';
	if (defined &Socket::getaddrinfo) {
		my ($err, @res) = Socket::getaddrinfo($host, undef, { socktype => Socket::SOCK_STREAM() });
		return 0 if $err;
		return @res > 0 ? 1 : 0;
	}
	my $packed = gethostbyname($host);
	return defined $packed ? 1 : 0;
}

sub _extra_protect_nicks {
	my %x;
	my $s = $main::gline_protect_nicks // '';
	for my $p (split /,/, $s) {
		$p =~ s/^\s+|\s+$//g;
		$x{lc $p} = 1 if $p ne '';
	}
	return \%x;
}

# Undernet-style channel/reg services (X / C / E) plus common *Serv names.
my %_default_protect_nicks = map { $_ => 1 } qw(
	x c e chanserv nickserv memoserv operserv botserv statserv
);

sub _is_protected_service_nick {
	my ($nick) = @_;
	return 0 unless defined $nick && $nick ne '';
	my $l = lc $nick;
	return 1 if $_default_protect_nicks{$l};
	return 1 if _extra_protect_nicks()->{$l};
	return 0;
}

sub _bot_gline_host_mask {
	my $bn = $main::botnick;
	return undef unless defined $bn && $bn ne '';
	my $h = eval { main::gethost($bn) };
	return undef unless defined $h && $h ne '';
	my (undef, $hp) = split(/\@/, $h, 2);
	return undef unless defined $hp && $hp ne '';
	return '*@' . $hp;
}

sub _format_dur {
	my ($s) = @_;
	$s = int($s);
	return "expired" if $s <= 0;
	my @p;
	my $d = int($s / 86400); $s %= 86400;
	my $h = int($s / 3600);  $s %= 3600;
	my $m = int($s / 60);    $s %= 60;
	push @p, "${d}d" if $d;
	push @p, "${h}h" if $h;
	push @p, "${m}m" if $m;
	push @p, "${s}s" if $s && !@p;
	push @p, "0s" unless @p;
	return join(' ', @p);
}

# Turn a user-supplied target into a "*@host" (or full user\@host) mask.
# Returns ( $mask, $via_nick ) on success ($via_nick set only when resolved from a live nick).
# On failure returns ( undef, undef, $plain_err, $colored_err ).
# $strict: add-command validation (DNS for hostnames, IPv4 octets); del uses $strict=0 (permissive).
sub _resolve_to_mask {
	my ($arg, $strict) = @_;
	$strict = 1 unless defined $strict;
	return (undef, undef, '', '') unless defined $arg && $arg ne '';

	my $_no_nick = sub {
		my ($t) = @_;
		return (
			undef, undef,
			"\002[GLINE]\002 No such nick online: \002$t\002 (use \002gline add <ip>\002, \002hostname\002, or \002*\@host\002).",
			"\00305\002[GLINE]\017 \00304No such nick online:\017 \00302\002$t\017 \00306(use\017 \00302\002gline add <ip>\017\00306,\017 \00302\002hostname\017\00306, or\017 \00302\002*\@host\017\00306).\017"
		);
	};

	if ($arg =~ /\@/) {
		my ($user, $hp) = split(/\@/, $arg, 2);
		if (!defined $hp || $hp eq '') {
			return (
				undef, undef,
				"\002[GLINE]\002 Invalid mask \002$arg\002 (empty host).",
				"\00305\002[GLINE]\017 \00304Invalid mask\017 \00302\002$arg\017 \00306(empty host).\017"
			);
		}
		if ($strict) {
			if (_strict_ipv4($hp)) {
				return ($arg, undef);
			}
			if (_is_ipv6($hp)) {
				return ($arg, undef);
			}
			if (_is_hostname($hp)) {
				if (!_dns_resolves($hp)) {
					return (
						undef, undef,
						"\002[GLINE]\002 Host does not resolve (DNS): \002$hp\002",
						"\00305\002[GLINE]\017 \00304Host does not resolve (DNS):\017 \00302\002$hp\017"
					);
				}
				return ($arg, undef);
			}
			return (
				undef, undef,
				"\002[GLINE]\002 Unrecognized host in mask \002$arg\002 (not a valid IP or hostname).",
				"\00305\002[GLINE]\017 \00304Unrecognized host in mask\017 \00302\002$arg\017 \00306(not a valid IP or hostname).\017"
			);
		}
		return ($arg, undef);
	}

	if ($strict) {
		if (_is_ipv4($arg)) {
			if (!_strict_ipv4($arg)) {
				return (
					undef, undef,
					"\002[GLINE]\002 Invalid IPv4 address: \002$arg\002",
					"\00305\002[GLINE]\017 \00304Invalid IPv4 address:\017 \00302\002$arg\017"
				);
			}
			return ("*\@$arg", undef);
		}
		if (_is_ipv6($arg)) {
			return ("*\@$arg", undef);
		}
		if (_is_hostname($arg)) {
			if (!_dns_resolves($arg)) {
				return (
					undef, undef,
					"\002[GLINE]\002 Host does not resolve (DNS): \002$arg\002",
					"\00305\002[GLINE]\017 \00304Host does not resolve (DNS):\017 \00302\002$arg\017"
				);
			}
			return ("*\@$arg", undef);
		}
	} else {
		if (_is_ipv4($arg) || _is_ipv6($arg)) {
			return ("*\@$arg", undef);
		}
		if ($arg =~ /\./) {
			return ("*\@$arg", undef);
		}
	}

	my $h;
	eval { $h = main::gethost($arg) };
	if (defined $h && $h ne '') {
		my (undef, $hostpart) = split(/\@/, $h, 2);
		if (!defined $hostpart || $hostpart eq '') {
			return (
				undef, undef,
				"\002[GLINE]\002 Cannot build mask for \002$arg\002 (missing host in user\@host from link cache).",
				"\00305\002[GLINE]\017 \00304Cannot build mask for\017 \00302\002$arg\017 \00306(missing host in user\@host from link cache).\017"
			);
		}
		return ("*\@$hostpart", $arg);
	}
	return $_no_nick->($arg);
}

# Permissive resolver for \002gline del\002 (offline nick falls back to raw target in caller).
sub _resolve_target {
	my ($arg) = @_;
	my ($mask) = _resolve_to_mask($arg, 0);
	return $mask;
}

sub register_local_gline {
	my ($who, $mask, $duration, $reason) = @_;
	return 0 unless defined $mask && $mask ne '';
	$duration = $DEFAULT_TIME   unless defined $duration && $duration > 0;
	$reason   = $DEFAULT_REASON unless defined $reason   && $reason ne '';
	$who      = 'local'         unless defined $who      && $who ne '';

	my $now = time;
	my $exp = $now + $duration;
	my $is_new = (!exists $glines{$mask} || $glines{$mask}{remote}) ? 1 : 0;
	$glines{$mask} = {
		added  => $now,
		expire => $exp,
		who    => $who,
		reason => $reason,
		remote => 0,
	};
	$g_added++ if $is_new;
	_save();
	return 1;
}

sub _add_gline_cmd {
	my ($who, $arg) = @_;
	my @tok = defined $arg ? split(/\s+/, $arg, 3) : ();
	my $target = $tok[0];
	if (!defined $target || $target eq '') {
		_cmsg(
			"\002[GLINE]\002 Usage: \002gline add <nick|host|ipv4|ipv6> [time] [reason]\002",
			"\00305\002[GLINE]\017 \00306Usage:\017 \00302\002gline add <nick|host|ipv4|ipv6> [time] [reason]\017"
		);
		return;
	}

	# Optional [time]: if the second token parses as a duration, treat the rest
	# as the reason; otherwise the second token onwards is the reason.
	my ($duration, $reason);
	if (defined $tok[1]) {
		my $maybe = _parse_time($tok[1]);
		if (defined $maybe) {
			$duration = $maybe;
			$reason   = $tok[2];
		} else {
			my $rest = defined $arg ? $arg : '';
			$rest =~ s/^\S+\s+//;
			$reason = $rest;
		}
	}
	$duration = $DEFAULT_TIME   unless defined $duration && $duration > 0;
	$reason   = $DEFAULT_REASON unless defined $reason   && $reason ne '';

	# Refuse bare nick that points at this pseudoclient or at configured / default service nicks.
	if ($target !~ /[\@.:]/ && lc($target) eq lc($main::botnick)) {
		_cmsg(
			"\002[GLINE]\002 Refusing to G-line \002$main::botnick\002 (that's me).",
			"\00305\002[GLINE]\017 \00304Refusing to G-line\017 \00302\002$main::botnick\017 \00306(that's me).\017"
		);
		return;
	}
	if ($target !~ /[\@.:]/ && _is_protected_service_nick($target)) {
		_cmsg(
			"\002[GLINE]\002 Refusing to G-line \002$target\002 (network / channel service nick).",
			"\00305\002[GLINE]\017 \00304Refusing to G-line\017 \00302\002$target\017 \00306(network / channel service nick).\017"
		);
		return;
	}

	my ($mask, $via_nick, $err_p, $err_c) = _resolve_to_mask($target, 1);
	if (!defined $mask) {
		_cmsg($err_p, $err_c) if defined $err_p && $err_p ne '';
		return;
	}

	my $botm = _bot_gline_host_mask();
	if (defined $botm && lc($mask) eq lc($botm)) {
		_cmsg(
			"\002[GLINE]\002 Refusing to G-line mask \002$mask\002 (same host as \002$main::botnick\002).",
			"\00305\002[GLINE]\017 \00304Refusing to G-line mask\017 \00302\002$mask\017 \00306(same host as\017 \00302\002$main::botnick\017\00306).\017"
		);
		return;
	}

	if (defined $via_nick && $via_nick ne '') {
		if (_is_ircop($via_nick)) {
			_cmsg(
				"\002[GLINE]\002 Refusing to G-line \002$via_nick\002 (IRC operator).",
				"\00305\002[GLINE]\017 \00304Refusing to G-line\017 \00302\002$via_nick\017 \00306(IRC operator).\017"
			);
			return;
		}
		if (defined &main::isservice && main::isservice($via_nick)) {
			_cmsg(
				"\002[GLINE]\002 Refusing to G-line \002$via_nick\002 (user mode +k / service client).",
				"\00305\002[GLINE]\017 \00304Refusing to G-line\017 \00302\002$via_nick\017 \00306(user mode +k / service client).\017"
			);
			return;
		}
	}

	if (exists $glines{$mask}) {
		my $left = _format_dur(($glines{$mask}{expire} // 0) - time);
		_cmsg(
			"\002[GLINE]\002 \002$mask\002 already glined (\002$left\002 left). Use \002gline del $mask\002 first to replace it.",
			"\00305\002[GLINE]\017 \00310\002$mask\017 \00306already glined (\00302\002$left\017 \00306left). Use\017 \00302\002gline del $mask\017 \00306first to replace it.\017"
		);
		return;
	}

	main::gline($mask, $duration, $reason);
	register_local_gline($who, $mask, $duration, $reason);
	my $dur = _format_dur($duration);
	_cmsg(
		"\002[GLINE]\002 Added \002$mask\002 for \002$dur\002 (\"$reason\") by \002$who\002.",
		"\00305\002[GLINE]\017 \00303\002+\017 \00310\002$mask\017 \00306for\017 \00302\002$dur\017 \00306(\"\00306$reason\00306\") by\017 \00302\002$who\017\00306.\017"
	);
}

sub _del_all_gline_cmd {
	my ($who) = @_;
	_purge_expired();
	if (!%glines) {
		_cmsg(
			"\002[GLINE]\002 No active glines to remove.",
			"\00305\002[GLINE]\017 \00306No active glines to remove.\017"
		);
		return;
	}
	if (!defined &main::ungline) {
		_cmsg(
			"\002[GLINE]\002 Link module does not expose ungline(); aborting.",
			"\00305\002[GLINE]\017 \00304Link module does not expose ungline();\017 \00306aborting.\017"
		);
		return;
	}
	my @masks = sort keys %glines;
	my $n     = scalar @masks;
	my $local = scalar grep { !$glines{$_}{remote} } @masks;
	my $rem   = $n - $local;
	foreach my $mask (@masks) {
		main::ungline($mask);
		delete $glines{$mask};
		$g_removed++;
	}
	_save();
	_cmsg(
		"\002[GLINE]\002 Removed \002$n\002 gline(s) (\002$local\002 local, \002$rem\002 remote) by \002$who\002.",
		"\00305\002[GLINE]\017 \00304\002-\017 \00306Removed\017 \00302\002$n\017 \00306gline(s) (\00302\002$local\017 \00306local,\017 \00302\002$rem\017 \00306remote) by\017 \00302\002$who\017\00306.\017"
	);
}

sub _del_gline_cmd {
	my ($who, $arg) = @_;
	my @tok = defined $arg ? split(/\s+/, $arg) : ();
	my $target = $tok[0];
	if (!defined $target || $target eq '') {
		_cmsg(
			"\002[GLINE]\002 Usage: \002gline del <mask|nick|host|ip|all>\002",
			"\00305\002[GLINE]\017 \00306Usage:\017 \00302\002gline del <mask|nick|host|ip|all>\017"
		);
		return;
	}

	if (lc($target) eq 'all') {
		_del_all_gline_cmd($who);
		return;
	}

	# Resolve to the same canonical mask form used by add/list, so users can
	# say e.g. "gline del 1.2.3.4" or "gline del somenick".
	my $mask = _resolve_target($target);
	$mask = $target unless defined $mask;

	my $known = exists $glines{$mask};
	if (!$known) {
		_cmsg(
			"\002[GLINE]\002 \002$mask\002 not in local list; sending removal to the IRCd anyway.",
			"\00305\002[GLINE]\017 \00310\002$mask\017 \00306not in local list; sending removal to the IRCd anyway.\017"
		);
	} else {
		delete $glines{$mask};
		_save();
	}

	if (defined &main::ungline) {
		main::ungline($mask);
	} else {
		_cmsg(
			"\002[GLINE]\002 Link module does not expose ungline(); local entry removed only.",
			"\00305\002[GLINE]\017 \00304Link module does not expose ungline();\017 \00306local entry removed only.\017"
		);
	}
	$g_removed++;
	_cmsg(
		"\002[GLINE]\002 Removed \002$mask\002 (by \002$who\002).",
		"\00305\002[GLINE]\017 \00304\002-\017 \00310\002$mask\017 \00306removed (by\017 \00302\002$who\017\00306).\017"
	);
}

sub _list_gline_cmd {
	_purge_expired();
	if (!%glines) {
		_cmsg(
			"\002[GLINE]\002 No active glines.",
			"\00305\002[GLINE]\017 \00306No active glines.\017"
		);
		return;
	}
	my $n     = scalar keys %glines;
	my $local = scalar grep { !$glines{$_}{remote} } keys %glines;
	my $rem   = $n - $local;
	_cmsg(
		"\002[GLINE]\002 \002$n\002 active gline(s) (\002$local\002 local, \002$rem\002 remote) sorted by expiry:",
		"\00305\002[GLINE]\017 \00302\002$n\017 \00306active gline(s) (\00302\002$local\017 \00306local, \00302\002$rem\017 \00306remote) sorted by expiry:\017"
	);
	my $now = time;
	foreach my $mask (sort { ($glines{$a}{expire} // 0) <=> ($glines{$b}{expire} // 0) } keys %glines) {
		my $r    = $glines{$mask};
		my $left = ($r->{expire} // 0) - $now;
		my $dur  = _format_dur($left);
		my $age  = _format_dur($now - ($r->{added} // $now));
		my $tag  = $r->{remote} ? 'remote' : 'local';
		my $tagcol = $r->{remote} ? "\00304\002remote\017" : "\00303\002local\017";
		_cmsg(
			"  [\002$tag\002] \002$mask\002 - left: \002$dur\002 - added: \002$age ago\002 - by \002$r->{who}\002 - \"$r->{reason}\"",
			"\00305  [\017$tagcol\00305]\017 \00310\002$mask\017 \00306- left:\017 \00302\002$dur\017 \00306- added:\017 \00302\002$age ago\017 \00306- by\017 \00302\002$r->{who}\017 \00306- \"\00306$r->{reason}\00306\"\017"
		);
	}
}

sub _help_gline_cmd {
	_cmsg(
		"\002[GLINE]\002 Subcommands: \002gline add <nick|host|ipv4|ipv6> [time] [reason]\002 (or \002gline <same>\002), \002gline del <mask|nick|host|ip>\002, \002gline list\002.",
		"\00305\002[GLINE]\017 \00306Subcommands:\017 \00302\002gline add <nick|host|ipv4|ipv6> [time] [reason]\017 \00306(or\017 \00302\002gline <same>\017\00306),\017 \00302\002gline del <mask|nick|host|ip>\017\00306,\017 \00302\002gline list\017\00306.\017"
	);
	_cmsg(
		"\002[GLINE]\002 \002gline del all\002 removes every active gline currently in the local cache (local + remote).",
		"\00305\002[GLINE]\017 \00302\002gline del all\017 \00306removes every active gline currently in the local cache (local + remote).\017"
	);
	_cmsg(
		"\002[GLINE]\002 Time formats: bare number = minutes, or \002Ns\002 / \002Nm\002 / \002Nh\002 / \002Nd\002 / \002Nw\002. Default time: \0021h\002. Default reason: \"$DEFAULT_REASON\".",
		"\00305\002[GLINE]\017 \00306Time formats: bare number = minutes, or\017 \00302\002Ns\017 \00306/\017 \00302\002Nm\017 \00306/\017 \00302\002Nh\017 \00306/\017 \00302\002Nd\017 \00306/\017 \00302\002Nw\017\00306. Default time:\017 \00302\0021h\017\00306. Default reason: \"\00306$DEFAULT_REASON\00306\".\017"
	);
}

sub cmd_help {
	_help_gline_cmd();
}

sub handle_privmsg {
	my ($nick, $ident, $host, $chan, $msg) = @_;
	my $chan_d = _dsp($chan);
	return if $chan_d !~ /^\Q$main::mychan\E$/i;
	my $msg_d  = _dsp($msg);
	my $nick_d = _dsp($nick);

	if ($msg_d =~ /^gline\s+add(?:\s+(.+?))?\s*$/i) {
		if (!_is_ircop($nick_d)) {
			_deny_ircop_only('gline add');
			return;
		}
		_add_gline_cmd($nick_d, $1);
		return;
	}
	if ($msg_d =~ /^gline\s+del(?:\s+(.+?))?\s*$/i) {
		if (!_is_ircop($nick_d)) {
			_deny_ircop_only('gline del');
			return;
		}
		_del_gline_cmd($nick_d, $1);
		return;
	}
	if ($msg_d =~ /^gline\s+list\s*$/i) {
		if (!_is_ircop($nick_d)) {
			_deny_ircop_only('gline list');
			return;
		}
		_list_gline_cmd();
		return;
	}
	# Shorthand: same as "gline add" (e.g. "gline test") so invalid/offline targets still get a reply.
	if ($msg_d =~ /^gline\s+(.+)$/i && $msg_d !~ /^gline\s+(add|del|list|help)\b/i) {
		if (!_is_ircop($nick_d)) {
			_deny_ircop_only('gline');
			return;
		}
		_add_gline_cmd($nick_d, $1);
		return;
	}
	if ($msg_d =~ /^gline(?:\s+help)?\s*$/i) {
		if (!_is_ircop($nick_d)) {
			_deny_ircop_only('gline');
			return;
		}
		_help_gline_cmd();
		return;
	}
}

sub stats {
	_purge_expired();
	my $n     = scalar keys %glines;
	my $local = scalar grep { !$glines{$_}{remote} } keys %glines;
	my $rem   = $n - $local;
	_cmsg(
		"Active glines:                       \002$n\002 (\002$local\002 local, \002$rem\002 remote)",
		"\00305Active glines:\017                       \00302\002$n\017 \00306(\00302\002$local\017 \00306local,\017 \00302\002$rem\017 \00306remote)\017"
	);
	_cmsg(
		"Local adds / removals (this session):  \002$g_added\002 / \002$g_removed\002",
		"\00305Local adds / removals (this session):\017  \00302\002$g_added\017 \00306/\017 \00302\002$g_removed\017"
	);
	_cmsg(
		"Remote adds / removals seen on link:   \002$g_remote_add\002 / \002$g_remote_del\002",
		"\00305Remote adds / removals seen on link:\017   \00302\002$g_remote_add\017 \00306/\017 \00302\002$g_remote_del\017"
	);
}

# Called by Modules/Link/p10.pm for every GL message seen on the link, no
# matter who set/removed it. Parameters:
#   $source   display name of the originator (oper nick or server hostname)
#   $action   '+' add, '-' remove (other P10 control verbs are ignored)
#   $mask     the user@host being glined
#   $expire   absolute epoch when the gline expires (0 if not provided)
#   $lastmod  absolute epoch of last modification (informational)
#   $reason   human-readable reason
sub handle_gline {
	my ($source, $action, $mask, $expire, $lastmod, $reason) = @_;
	return unless defined $action && defined $mask && $mask ne '';

	my $now = time;
	# Stay quiet during the initial netburst AND while the post-EB
	# STATS g reply is streaming in, so we don't dump every existing
	# network gline to #console at startup.
	my $stats_inflight = (defined $main::GLINE_STATS_INFLIGHT
		&& $main::GLINE_STATS_INFLIGHT > $now) ? 1 : 0;
	my $loud = (!defined $main::NETJOIN || $main::NETJOIN == 0)
		&& !$stats_inflight;

	if ($action eq '+') {
		my $exp = (defined $expire && $expire > 0) ? 0 + $expire : ($now + $DEFAULT_TIME);
		# Track every mask the IRCd reports during the post-EB STATS g reply
		# so handle_gline_burst_done() can purge whatever is in our local
		# cache but missing from the network's authoritative list.
		$burst_seen{$mask} = 1 if $stats_inflight;
		# Don't clobber a local entry's "who" with the network echo.
		if (exists $glines{$mask} && !$glines{$mask}{remote}) {
			$glines{$mask}{expire} = $exp;
			$glines{$mask}{reason} = $reason if defined $reason && $reason ne '';
			_save();
			return;
		}
		$glines{$mask} = {
			added  => $now,
			expire => $exp,
			who    => (defined $source && $source ne '') ? $source : 'remote',
			reason => (defined $reason && $reason ne '') ? $reason : $DEFAULT_REASON,
			remote => 1,
		};
		_save();
		$g_remote_add++;
		if ($loud) {
			my $left  = _format_dur($exp - $now);
			my $src   = $source // 'remote';
			my $rsn   = $reason // '';
			_cmsg(
				"\002[GLINE]\002 \002+\002 \002$mask\002 by \002$src\002 (\002$left\002): \"$rsn\"",
				"\00305\002[GLINE]\017 \00303\002+\017 \00310\002$mask\017 \00306by\017 \00302\002$src\017 \00306(\00302\002$left\017\00306): \"\00306$rsn\00306\"\017"
			);
		}
		return;
	}

	if ($action eq '-') {
		if (exists $glines{$mask}) {
			delete $glines{$mask};
			_save();
		}
		$g_remote_del++;
		if ($loud) {
			my $src = $source // 'remote';
			_cmsg(
				"\002[GLINE]\002 \002-\002 \002$mask\002 removed by \002$src\002",
				"\00305\002[GLINE]\017 \00304\002-\017 \00310\002$mask\017 \00306removed by\017 \00302\002$src\017"
			);
		}
		return;
	}
}

# Called by Modules/Link/p10.pm when RPL_ENDOFSTATS (219, letter g) closes
# the post-burst STATS g reply we issued. Reconciles the local cache with
# the network's authoritative state: any mask we have in %glines that the
# IRCd did NOT mention in this burst has been removed (or expired) on the
# server side while the bot was disconnected, so we drop it locally and
# rewrite glines.conf. Intentionally silent on #console when nothing
# changes; reports a one-liner only when stale entries were actually
# pruned (so the operator can notice an external mass-removal).
sub handle_gline_burst_done {
	my @stale;
	foreach my $mask (keys %glines) {
		push @stale, $mask unless $burst_seen{$mask};
	}
	if (@stale) {
		my $local_pruned  = scalar grep { !$glines{$_}{remote} } @stale;
		my $remote_pruned = scalar(@stale) - $local_pruned;
		foreach my $mask (@stale) {
			delete $glines{$mask};
		}
		_save();
		my $n = scalar @stale;
		_cmsg(
			"\002[GLINE]\002 Pruned \002$n\002 stale entry(ies) from local cache (\002$local_pruned\002 local, \002$remote_pruned\002 remote) — no longer present on the network.",
			"\00305\002[GLINE]\017 \00306Pruned\017 \00302\002$n\017 \00306stale entry(ies) from local cache (\00302\002$local_pruned\017 \00306local,\017 \00302\002$remote_pruned\017 \00306remote) - no longer present on the network.\017"
		);
	}
	%burst_seen = ();
}

sub handle_topic  {}
sub handle_join   {}
sub handle_part   {}
sub handle_mode   {}
sub handle_notice {}
sub scan_user     {}

sub init {
	if (!main::depends("core-v1")) {
		print "This module requires version 1.x of defender.\n";
		exit(0);
	}
	if (!main::depends("native-gline")) {
		print "Modules::Scan::gline requires the link layer to provide native-gline.\n";
		exit(0);
	}
	main::provides("gline");
	_load();
}

1;
