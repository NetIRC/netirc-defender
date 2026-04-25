#
# SPDX-License-Identifier: GPL-2.0-only
# Copyright (c) 2026 NetIRC Defender
#
# NetIRC Defender V3 - network security service

package Modules::Scan::whois;

use strict;
use warnings;
use POSIX qw(strftime);

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
		"\002[WHOIS]\002 Access denied: IRC operators only ($cmd).",
		"\00305\002[WHOIS]\017 \00304Access denied:\017 \00306IRC operators only (\00302$cmd\00306).\017"
	);
}

sub _whois_safe {
	my ($s) = @_;
	return '' unless defined $s;
	$s =~ s/[\x00-\x1F\x7F]//g;
	return $s;
}

sub _whois_row {
	my ($label, $plain_val, $col_val) = @_;
	$col_val = $plain_val unless defined $col_val && $col_val ne '';
	my $pad = 13 - length $label;
	$pad = 1 if $pad < 1;
	my $gap = ' ' x $pad;
	return (
		"  $label$gap$plain_val",
		"  \00310$label\017$gap\00302$col_val\017"
	);
}

sub _whois_row_channels {
	my ($chans_ref) = @_;
	my @ch = (defined $chans_ref && ref $chans_ref eq 'ARRAY') ? @$chans_ref : ();
	if (!@ch) {
		my ($p0, $c0) = _whois_row(
			'Channels',
			'none observed this session (only JOIN/PART while Defender is linked)',
		);
		_cmsg($p0, $c0);
		return;
	}
	my $text = join ', ', @ch;
	my $max  = 380;
	my @chunks;
	while (length $text > $max) {
		my $slice = substr($text, 0, $max);
		my $comma = rindex($slice, ',');
		$comma = $max - 1 if $comma < 40;
		push @chunks, substr($text, 0, $comma + 1);
		$text = substr($text, $comma + 1);
		$text =~ s/^\s+//;
	}
	push @chunks, $text if $text ne '';

	my $first = shift @chunks;
	my ($p, $c) = _whois_row('Channels', $first);
	_cmsg($p, $c);
	for my $cont (@chunks) {
		_cmsg("             $cont", "             \00302$cont\017");
	}
	return;
}

sub _emit_whois_lines {
	my ($info) = @_;
	my $n     = _whois_safe($info->{nick}     // '');
	my $uh    = _whois_safe($info->{userhost} // '');
	my $srv   = _whois_safe($info->{server}   // '');
	$srv = 'n/a' if $srv eq '';
	my $gecos = _whois_safe($info->{gecos}    // '');
	my $op    = $info->{isoper};
	my $svc   = $info->{isservice};
	my $cip   = _whois_safe($info->{client_ip} // '');
	my $acct  = _whois_safe($info->{account}   // '');
	my $sts   = $info->{signon_ts};
	my $away  = $info->{away} // 0;
	my $aw_m  = _whois_safe($info->{away_msg} // '');
	my $chref = $info->{channels};

	my $net = _whois_safe($main::netname // '');
	my $hdr_net = ($net ne '') ? " | $net" : '';
	my ($p, $c) = (
		"\002[WHOIS]\002 Client snapshot$hdr_net — \002$n\002",
		"\00305\002[WHOIS]\017 \00306Client snapshot\00302$hdr_net\00306 — \00302\002$n\017"
	);
	_cmsg($p, $c);

	($p, $c) = _whois_row('Nickname', $n);
	_cmsg($p, $c);
	($p, $c) = _whois_row('User@host', $uh);
	_cmsg($p, $c);
	if ($cip ne '') {
		my $ip_out = ($cip eq '0.0.0.0')
			? 'n/a (no real client IP on link)'
			: $cip;
		($p, $c) = _whois_row('Seen IP', $ip_out);
		_cmsg($p, $c);
	}
	($p, $c) = _whois_row('Real name', ($gecos ne '') ? $gecos : 'n/a');
	_cmsg($p, $c);
	($p, $c) = _whois_row('Account', ($acct ne '') ? $acct : 'n/a');
	_cmsg($p, $c);
	if ($away) {
		my $show = $aw_m;
		$show = substr($show, 0, 220) . '...' if length($show) > 220;
		my $plain_v = ($show ne '') ? "yes — $show" : 'yes (empty message)';
		my $col_v = ($show ne '')
			? "\00306yes — \00302$show\017"
			: "\00306yes (empty message)\017";
		($p, $c) = _whois_row('Away', $plain_v, $col_v);
		_cmsg($p, $c);
	} else {
		($p, $c) = _whois_row('Away', 'no');
		_cmsg($p, $c);
	}
	if ($svc) {
		($p, $c) = _whois_row('Sign-on', 'n/a (service; link time not a client sign-on clock)');
	} elsif (defined $sts && $sts =~ /^\d+$/ && $sts > 0) {
		my $hum = strftime('%a %d %b %Y %H:%M:%S', localtime(0 + $sts));
		($p, $c) = _whois_row('Sign-on', "$hum (server local)");
	} else {
		($p, $c) = _whois_row('Sign-on', 'n/a');
	}
	_cmsg($p, $c);
	($p, $c) = _whois_row('Server', $srv);
	_cmsg($p, $c);

	_whois_row_channels($chref);

	my @st;
	push @st, 'IRC operator' if $op;
	push @st, 'Service (+k)' if $svc;
	push @st, 'None (regular user)' if !@st;
	($p, $c) = _whois_row('Privileges', join('; ', @st));
	_cmsg($p, $c);
}

sub _handle_whois {
	my ($nick, $arg) = @_;
	my $target = defined $arg ? $arg : '';
	$target =~ s/^\s+|\s+$//g;
	if ($target =~ /^nick\s+(\S+)\s*$/i) {
		$target = $1;
	}

	if ($target eq '') {
		_cmsg(
			"\002[WHOIS]\002 Usage: \002whois <nick>\002 or \002whois nick <nick>\002 — client snapshot from the service link.",
			"\00305\002[WHOIS]\017 \00306Usage:\017 \00302\002whois <nick>\017 \00306or\017 \00302\002whois nick <nick>\017 \00306— link snapshot.\017"
		);
		return;
	}

	if (!defined &main::client_link_info) {
		_cmsg(
			"\002[WHOIS]\002 Link module does not expose client_link_info().",
			"\00305\002[WHOIS]\017 \00304Link module does not expose client_link_info().\017"
		);
		return;
	}

	my $info = main::client_link_info($target);
	if (!defined $info) {
		_cmsg(
			"\002[WHOIS]\002 No match in uplink cache: \002$target\002 (user not visible to Defender on this link).",
			"\00305\002[WHOIS]\017 \00304No match in uplink cache:\017 \00302\002$target\017 \00306(not visible on this link).\017"
		);
		return;
	}

	_emit_whois_lines($info);
}

sub cmd_help {
	_cmsg(
		"\002[WHOIS]\002 \002whois <nick>\002 — link cache: user\@host, Seen IP, account, away (P10 while linked), sign-on, server, channels, privileges. Service clients (+k) often have no real IP/clock sign-on on the P10 cache. Idle is not on this snapshot; use server /whois for that.",
		"\00305\002[WHOIS]\017 \00302whois <nick>\017 \00306— link cache incl. \00314away\017\00306 (P10 on link; no \00314idle\017\00306 — use server \00314WHOIS\017\00306).\017"
	);
}

sub handle_privmsg {
	my ($nick, $ident, $host, $chan, $msg) = @_;
	my $chan_d = _dsp($chan);
	return if $chan_d !~ /^\Q$main::mychan\E$/i;
	my $msg_d  = _dsp($msg);
	my $nick_d = _dsp($nick);

	if ($msg_d =~ /^whois(?:\s+(.+?))?\s*$/i) {
		if (!_is_ircop($nick_d)) {
			_deny_ircop_only('whois');
			return;
		}
		my $ok = eval { _handle_whois($nick_d, $1); 1 };
		if (!$ok) {
			my $err = $@ // 'unknown error';
			$err =~ s/\s+$//s;
			_cmsg(
				"\002[WHOIS]\002 Error: $err",
				"\00305\002[WHOIS]\017 \00304Error:\017 \00306$err\017"
			);
		}
		return;
	}
}

sub stats {
	_cmsg(
		"[WHOIS] \002$main::mychan\002: \002whois <nick>\002 — uplink client report.",
		"\00305[WHOIS]\017 \00310\002$main::mychan\017\00306:\017 \00302\002whois <nick>\017 \00306— uplink client report.\017"
	);
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
	main::provides("whois");
}

1;
