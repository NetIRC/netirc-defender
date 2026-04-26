#
# SPDX-License-Identifier: GPL-2.0-only
# Copyright (c) 2026 NetIRC Defender
#
# NetIRC Defender V3 - network security service

package Modules::Scan::seen;

use strict;
use warnings;
use POSIX qw(strftime);
use Storable qw(nstore retrieve);

# lc(nick) => hash with: ts, nick, userhost, server, intro, chans, event, reason, newnick, killer
our %SEEN;
our $SEEN_DIRTY;
our $SEEN_LAST_SAVE;
our $SEEN_SAVE_SEC = 8;

sub _path {
	return '' unless defined $main::dir && $main::dir ne '';
	return "$main::dir/seen_state.sto";
}

sub _max_entries {
	my $m = $main::dataValues{'seen_max_entries'} // '';
	$m = 10000 if $m !~ /^\d+$/;
	$m = 0 + $m;
	$m = 10      if $m < 10;
	$m = 200000  if $m > 200000;
	return $m;
}

sub _dsp {
	my ($s) = @_;
	return '' unless defined $s;
	$s =~ s/\\(.)/$1/g;
	return $s;
}

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
		"\002[SEEN]\002 Access denied: IRC operators only ($cmd).",
		"\00305\002[SEEN]\017 \00304Access denied:\017 \00306IRC operators only (\00302$cmd\00306).\017"
	);
}

sub _safe {
	my ($s) = @_;
	return '' unless defined $s;
	$s =~ s/[\x00-\x1F\x7F]//g;
	return $s;
}

sub _abs_rel_time {
	my ($ts) = @_;
	return 'unknown time' unless defined $ts && $ts =~ /^\d+$/ && $ts > 0;
	my $age = time - 0 - $ts;
	my $abs = strftime '%a %d %b %Y %H:%M:%S (local)', localtime(0 + $ts);
	if ($age < 2) { return "$abs (just now)"; }
	if ($age < 60) { return "$abs — " . $age . "s ago"; }
	if ($age < 3600) { return "$abs — " . int($age / 60) . "m ago"; }
	if ($age < 86400) { return "$abs — " . int($age / 3600) . "h ago"; }
	return $abs . ' — ' . int($age / 86400) . 'd ago';
}

sub _chans_ellipsis {
	my ($s, $max) = @_;
	$max = 300 unless defined $max && $max > 0;
	$s = '' unless defined $s;
	return 'none in link cache' if $s eq '';
	if (length $s > $max) {
		return substr($s, 0, $max - 3) . '...';
	}
	return $s;
}

sub _fmt_idle {
	my ($sec) = @_;
	return 'n/a' unless defined $sec && $sec =~ /^\d+$/;
	$sec = 0 + $sec;
	return '0s' if $sec <= 0;
	my $d = int($sec / 86400); $sec %= 86400;
	my $h = int($sec / 3600);  $sec %= 3600;
	my $m = int($sec / 60);    $sec %= 60;
	my @p;
	push @p, "${d}d" if $d;
	push @p, "${h}h" if $h;
	push @p, "${m}m" if $m;
	push @p, "${sec}s" if $sec || !@p;
	return join ' ', @p;
}

sub _cmsg_away_from_info {
	my ($info) = @_;
	return unless $info && ref $info eq 'HASH';
	my $aw  = $info->{away} // 0;
	my $awm = _safe($info->{away_msg} // '');
	if ($aw) {
		my $show = $awm;
		$show = substr($show, 0, 220) . '...' if length($show) > 220;
		if ($show ne '') {
			_cmsg("  Away: yes — $show", "  \00306Away:\017 \00306yes — \00302$show\017");
		} else {
			_cmsg("  Away: yes (empty message)", "  \00306Away:\017 \00306yes (empty message)\017");
		}
	} else {
		_cmsg("  Away: no", "  \00306Away:\017 \00302no\017");
	}
}

sub _load {
	%SEEN = ();
	$SEEN_DIRTY   = 0;
	$SEEN_LAST_SAVE = 0;
	my $p = _path;
	return if $p eq '' || !-f $p;
	local $@;
	my $h = eval { retrieve($p) };
	if (!$@ && ref $h eq 'HASH') {
		%SEEN = %$h;
	} elsif ($@ && -f $p) {
		warn "[seen] could not read $p — starting empty ($@)\n";
	}
}

sub _trim {
	my $max = _max_entries();
	my $n = scalar keys %SEEN;
	return if $n <= $max;
	my @k = sort { ($SEEN{$a}{ts} // 0) <=> ($SEEN{$b}{ts} // 0) } keys %SEEN;
	while ($n > $max && @k) {
		my $drop = shift @k;
		delete $SEEN{$drop};
		$n--;
	}
	$SEEN_DIRTY = 1;
}

sub _save_flush {
	my $p = _path;
	return if $p eq '';
	my $tmp = "$p.tmp.$$";
	local $@;
	eval { nstore(\%SEEN, $tmp) };
	if ($@ || !-f $tmp) {
		unlink $tmp if -f $tmp;
		return;
	}
	if (!rename $tmp, $p) {
		eval { nstore(\%SEEN, $p) };
		if ($@) {
			warn "[seen] could not write $p: $@\n";
			unlink $tmp if -f $tmp;
			return;
		}
		unlink $tmp if -f $tmp;
	}
	$SEEN_DIRTY     = 0;
	$SEEN_LAST_SAVE = time;
}

sub _maybe_save {
	return unless $SEEN_DIRTY;
	my $now = time;
	if ($now - ( $SEEN_LAST_SAVE // 0 ) >= $SEEN_SAVE_SEC) {
		_save_flush;
	}
}

sub _record_from_info {
	my ($info, $event, $reason, $opt) = @_;
	$opt //= {};
	return unless $info && ref $info eq 'HASH';
	my $nick = $info->{nick} // '';
	$nick = _safe($nick);
	return if $nick eq '';
	my $lc = lc $nick;
	my $ch = $info->{channels};
	my $ch_s = '';
	if (ref $ch eq 'ARRAY' && @$ch) {
		$ch_s = join ', ', map { _safe($_) } @$ch;
	}
	my $e = {
		ts       => time,
		nick     => $nick,
		userhost => _safe($info->{userhost} // ''),
		server   => _safe($info->{server}   // ''),
		intro    => _safe($info->{p10_intro_display} // ''),
		chans    => $ch_s,
		event    => $event,
		reason   => _safe($reason // ''),
		newnick  => (defined $opt->{newnick} ? _safe($opt->{newnick}) : ''),
		killer   => (defined $opt->{killer}  ? _safe($opt->{killer})  : ''),
	};
	$e->{reason} = substr($e->{reason}, 0, 400) if length $e->{reason} > 400;
	$SEEN{$lc} = $e;
	_trim;
	$SEEN_DIRTY = 1;
	_maybe_save;
}

sub handle_quit {
	my ($quitnick, $quitreason, $quitserver) = @_;
	return unless defined &main::client_link_info;
	my $info = main::client_link_info($quitnick);
	_record_from_info($info, 'quit', $quitreason, {});
}

sub handle_kill {
	my ($killer, $victim, $killreason) = @_;
	return unless defined &main::client_link_info;
	my $info = main::client_link_info($victim);
	_record_from_info($info, 'kill', $killreason, { killer => $killer });
}

sub handle_nick {
	my ($old, $new) = @_;
	return if !defined $new || $new eq '';
	return if !defined $old || $old eq '';
	# Drop any last-seen record for the old nick; history follows the new nick only.
	my $lc = lc $old;
	if (exists $SEEN{$lc}) {
		delete $SEEN{$lc};
		_trim;
		$SEEN_DIRTY = 1;
		_maybe_save;
	}
}

sub _handle_seen {
	my ($requester, $arg) = @_;
	$arg = $arg // '';
	$arg =~ s/^\s+|\s+$//g;
	if ($arg !~ /^\S+$/) {
		_cmsg(
			"\002[SEEN]\002 Usage: \002seen <nick>\002 — online snapshot (incl. away) from the link, or last quit/kill for that nick (old nick is cleared on nick change).",
			"\00305\002[SEEN]\017 \00306Usage:\017 \00302\002seen <nick>\017 \00306— online (incl. away) / last quit|kill; old nick history dropped on nick change.\017"
		);
		return;
	}
	if (!defined &main::client_link_info) {
		_cmsg(
			"\002[SEEN]\002 Link module does not expose \002client_link_info()\002.",
			"\00305\002[SEEN]\017 \00304Link has no \00302client_link_info()\00304.\017"
		);
		return;
	}

	my $q = $arg;
	my $q_lc = lc $q;
	if (defined $main::botnick && $q_lc eq lc($main::botnick)) {
		_cmsg(
			"\002[SEEN]\002 You are looking at me (\002$main::botnick\002): always online, never afk, professionally nosy.",
			"\00305\002[SEEN]\017 \00306You are looking at me (\00302\002$main::botnick\017\00306): always online, never afk, professionally nosy.\017"
		);
		return;
	}
	my $info = main::client_link_info($q);

	if ($info && ref $info eq 'HASH') {
		my $n     = _safe($info->{nick}     // $q);
		my $uh    = _safe($info->{userhost} // '');
		my $srv   = _safe($info->{server}   // '');
		$srv = 'n/a' if $srv eq '';
		my $int   = _safe($info->{p10_intro_display} // '');
		my $chref = $info->{channels};
		my $ch_t  = (ref $chref eq 'ARRAY' && @$chref)
			? _chans_ellipsis(join(', ', map { _safe($_) } @$chref))
			: 'none in link cache';

		my ($p0, $c0) = (
			"\002[SEEN]\002 \002$n\002 is \002online\002 (P10 service link) — $uh — server $srv",
			"\00305\002[SEEN]\017 \00302\002$n\017 \00306is \00302\002online\00306 — \00310$uh\00306 — server \00302$srv\017"
		);
		_cmsg($p0, $c0);
		if ($int ne '') {
			_cmsg(
				"  Introducing link: $int",
				"  \00306Introducing link:\017 \00310$int\017"
			);
		}
		_cmsg_away_from_info($info);
		_cmsg("  Channels: $ch_t", "  \00306Channels:\017 \00310$ch_t\017");
		return;
	}

	my $e = $SEEN{$q_lc};
	if ($e && ref $e eq 'HASH' && (defined $e->{ts} && $e->{ts} > 0)) {
		my $when  = _abs_rel_time($e->{ts});
		my $n     = _safe($e->{nick}     // $q);
		my $ev    = $e->{event}    // 'quit';
		my $rs    = $e->{reason}   // '';
		my $uh    = _safe($e->{userhost} // '');
		my $srv   = _safe($e->{server}   // '');
		my $int   = _safe($e->{intro}    // '');
		my $ch    = _chans_ellipsis($e->{chans} // '');
		my $nicks = $e->{newnick}  // '';
		my $killp = $e->{killer}   // '';

		my $line = '';
		if ($ev eq 'kill') {
			$line = "Killed" . ($killp ne '' ? " (from $killp)" : '') . ( $rs ne '' ? ": $rs" : '' );
		} elsif ($ev eq 'nick') {
			$line = ( $nicks ne '' ? "Changed nick to \002$nicks\002" : 'Nick change' ) . ( $rs ne '' ? " — $rs" : '' );
		} else {
			$line = 'Quit' . ( $rs ne '' ? ": $rs" : '' );
		}

		_cmsg(
			"\002[SEEN]\002 \002$q\002 is \002offline\002 — last on link: $when — $line",
			"\00305\002[SEEN]\017 \00302\002$q\017 \00306is \00304offline\00306 — \00310$when\00306 — $line\017"
		);
		_cmsg(
			"  host $uh — server $srv — channels: $ch",
			"  \00310$uh\017 \00306— server \00302$srv\017 \00306— channels: \00310$ch\017"
		) if $uh ne '' || $srv ne '' || $ch ne '';
		if ($int ne '') {
			_cmsg("  Introducing link: $int", "  \00306Intro:\017 \00310$int\017");
		}
		if ($nicks ne '' && $nicks ne $n) {
			if (my $i2 = main::client_link_info($nicks)) {
				_cmsg(
					"  \002Current nick\002 \002$nicks\002 is \002online\002 (same person if nick change was the last event).",
					"  \00306Current nick\017 \00302\002$nicks\017 \00306is \002online\002.\017"
				);
				_cmsg_away_from_info($i2);
			}
		}
		return;
	}

	_cmsg(
		"\002[SEEN]\002 No link snapshot for \002$q\002, and \002no\002 stored quit/kill for that nick (or the nick was dropped after a name change).",
		"\00305\002[SEEN]\017 \00306No cache / no \002seen\002 for\017 \00302\002$q\017\00306.\017"
	);
}

sub cmd_help {
	_cmsg(
		"\002[SEEN]\002 \002seen <nick>\002 — if online, user\@host, away, server, channels (link cache). If offline, last \002quit\002 or \002kill\002; changing nick drops the \002old\002 nick from last-seen.",
		"\00305\002[SEEN]\017 \00302seen <nick>\017 \00306— online (away, server, channels) / last quit|kill; old nick cleared on nick change.\017"
	);
}

sub handle_privmsg {
	my ($nick, $ident, $host, $chan, $msg) = @_;
	my $chan_d = _dsp($chan);
	return if $chan_d !~ /^\Q$main::mychan\E$/i;
	my $msg_d  = _dsp($msg);
	my $nick_d = _dsp($nick);

	if ($msg_d !~ /^seen\s+(\S+)\s*$/i) {
		return;
	}
	if (!_is_ircop($nick_d)) {
		_deny_ircop_only('seen');
		return;
	}
	_maybe_save;    # opportunistic
	my $ok = eval { _handle_seen($nick_d, $1); 1 };
	if (!$ok) {
		my $err = $@ // 'unknown error';
		$err =~ s/\s+$//s;
		_cmsg(
			"\002[SEEN]\002 Error: $err",
			"\00305\002[SEEN]\017 \00304Error:\017 \00306$err\017"
		);
	}
}

sub stats {
	_save_flush if $SEEN_DIRTY;
	my $n = scalar keys %SEEN;
	_cmsg(
		"[SEEN] In-memory last-seen table: $n nicks; max " . _max_entries() . "; persist " . _path(),
		"\00305[SEEN]\017 $n nicks; max \00310" . _max_entries() . "\017; \00306" . _path() . "\017"
	);
}

sub handle_topic  { }
sub handle_mode   { }
sub handle_part   { }
sub handle_join   { }
sub handle_notice { }
sub scan_user     { }

sub init {
	if (!main::depends("core-v1")) {
		print "This module requires version 1.x of defender.\n";
		exit(0);
	}
	_load;
	main::provides("seen");
}

1;
