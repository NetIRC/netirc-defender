#
# SPDX-License-Identifier: GPL-2.0-only
# Copyright (c) 2026 NetIRC Defender
#
# NetIRC Defender V3 - network security service

package Modules::Scan::killchan;

use warnings;
use strict;

my $killed = 0;
my %killchans;
# Pending killchan enforcement after JOIN grace: key "lc_nick\tlc_chan" => { at, nick, chan_disp, listkey }
my %killchan_pending;

my $gline_time = 1800;

sub _killchan_grace_sec {
	my $v = $main::dataValues{'killchan_join_grace_sec'};
	$v = 20 unless defined $v && $v =~ /^[0-9]+$/;
	$v = int($v);
	return 0 if $v < 0;
	return 300 if $v > 300;
	return $v;
}

# Gap after "timer expired" NOTICE before G-line / oper notice (lets the client show two lines).
sub _killchan_post_notice_delay_sec {
	my $v = $main::dataValues{'killchan_post_notice_delay_sec'};
	$v = 1 unless defined $v && $v =~ /^[0-9]+$/;
	$v = int($v);
	return 0 if $v < 0;
	return 5 if $v > 5;
	return $v;
}

sub _killchan_pending_key {
	my ($nick, $chan) = @_;
	return lc($nick) . "\t" . lc($chan);
}

# gethost() returns "ident@host" in p10; tolerate plain host or lookup failure.
sub _killchan_host_for_gline {
	my ($nick) = @_;
	return undef unless defined $nick && $nick ne '';
	my $gh = eval { main::gethost($nick) };
	return undef unless defined $gh && $gh ne '';
	if ($gh =~ /@/) {
		my $tail = (split(/@/, $gh, 2))[1];
		return $tail if defined $tail && $tail ne '';
	}
	return $gh;
}

# Run G-line or oper notice (used immediately when grace=0, or from handle_expire after grace).
sub _killchan_do_join_penalty {
	my ($nick, $chan, $listkey) = @_;
	return unless defined $nick && $nick ne '' && defined $chan && $chan ne '';
	return unless defined $listkey && exists $killchans{$listkey};

	my $gline_mins = int($gline_time / 60);
	my $host = _killchan_host_for_gline($nick);
	if (!defined $host || $host eq '') {
		_cmsg(
			"\002[KILLCHAN]\002 Cannot enforce join on \002$nick\002 (\002$chan\002): no host in cache (nick gone or not registered on link yet).",
			"\00305\002[KILLCHAN]\017 \00304Cannot enforce\017 \00302$nick\00306 on \00302$chan\00306: no host in cache.\017"
		);
		return;
	}

	my $reason = $killchans{$listkey};
	if (!main::isoper($nick)) {
		my $mask = "*\@$host";
		my $why  = "You joined a banned channel ($reason)";
		main::gline($mask, $gline_time, $why);
		# Keep gline.pm cache in sync with automatic killchan GLINEs (same pattern as dnsbl.pm).
		if (defined &Modules::Scan::gline::register_local_gline) {
			Modules::Scan::gline::register_local_gline('killchan', $mask, $gline_time, $why);
		}
		main::message("$nick joined $chan and was glined ($reason)");
		$killed++;
	} else {
		main::message("$nick joined $chan but is an ircop, so was not glined");
		main::notice($nick,
			"\2IRC operator:\2 no G-line is placed on you. Channel \2$chan\2 is on the killchan list — \2only non-operators\2 who join there get a G-line (\2$gline_mins\2 minutes)."
		);
	}
}

sub handle_mode {}

sub handle_topic
{
}


sub handle_join {

	return if ($main::NETJOIN == 1);

	my ($nick, $chan) = @_;
	# p10 passes quotemeta()d nick/channel to scan modules (same as PRIVMSG).
	$nick = _dsp($nick);
	$chan = _dsp($chan);

	foreach (keys %killchans) {
		if (lc $chan eq lc $_) {
			my $listkey = $_;
			my $grace   = _killchan_grace_sec();
			if ($grace > 0) {
				my $pk = _killchan_pending_key($nick, $chan);
				$killchan_pending{$pk} = {
					at        => int(time()) + int($grace),
					nick      => $nick,
					chan_disp => $chan,
					listkey   => $listkey,
				};
				# IRC opers: only #console (no NOTICE spam); non-opers: console + NOTICE (G-line warning).
				if (main::isoper($nick)) {
					_cmsg(
						"\002[KILLCHAN]\002 (oper) \002$nick\002 joined \002$chan\002 — enforcement in \002$grace\002s if still there (\002part\002 to cancel). No NOTICE until timer expires.",
						"\00305\002[KILLCHAN]\017 \00306(oper)\017 \00302$nick\00306 joined \00302\002$chan\017\00306 — \00306enforcement in\017 \00302$grace\00306s if still there (\00306part\00306 to cancel). \00306No NOTICE until timer expires.\017"
					);
				} else {
					_cmsg(
						"\002[KILLCHAN]\002 $nick joined \002$chan\002 — enforcement in \002$grace\002s if still there (part to cancel).",
						"\00305\002[KILLCHAN]\017 \00302$nick\00306 joined \00302\002$chan\017\00306 — enforcement in \00302$grace\00306s if still there (\00306part to cancel\00306).\017"
					);
					main::notice($nick,
						"\2$chan\2 is on the killchan list. You have \2$grace\2 seconds to \2/part $chan\2 or you will be \2G-lined\2. Leave the channel now to cancel."
					);
				}
			} else {
				_killchan_do_join_penalty($nick, $chan, $listkey);
			}
			last;
		}
	}

}

sub handle_part {

	my ($nick, $chan) = @_;
	$nick = _dsp($nick);
	$chan = _dsp($chan);
	my $pk = _killchan_pending_key($nick, $chan);
	return unless exists $killchan_pending{$pk};
	delete $killchan_pending{$pk};
	_cmsg(
		"\002[KILLCHAN]\002 $nick left \002$chan\002 — pending enforcement cancelled.",
		"\00305\002[KILLCHAN]\017 \00302$nick\00306 left \00302\002$chan\017\00306 — \00306pending enforcement cancelled.\017"
	);
	main::notice($nick,
		"You left \2$chan\2 in time — killchan enforcement was \2cancelled\2."
	);

}

sub handle_expire {

	my $now = int(time());
	for my $pk (keys %killchan_pending) {
		my $e = $killchan_pending{$pk};
		next unless ref $e eq 'HASH';
		next if $now < int($e->{at} // 0);
		my $listkey = $e->{listkey};
		next unless defined $listkey && exists $killchans{$listkey};
		my $cn = $e->{chan_disp};
		my $nn = $e->{nick};
		if (!exists $e->{post_notice_at}) {
			main::notice($nn,
				"Killchan timer expired for \2$cn\2 — applying network policy now."
			);
			my $gap = _killchan_post_notice_delay_sec();
			$e->{post_notice_at} = ($gap > 0) ? ($now + $gap) : $now;
			$killchan_pending{$pk} = $e;
			next;
		}
		next if $now < int($e->{post_notice_at} // 0);
		delete $killchan_pending{$pk};
		_killchan_do_join_penalty($nn, $cn, $listkey);
	}

}

sub handle_quit {

	my ($nick, $reason, $server) = @_;
	return unless defined $nick && $nick ne '';
	my $nlc = lc($nick);
	for my $pk (keys %killchan_pending) {
		delete $killchan_pending{$pk} if (index($pk, "$nlc\t") == 0);
	}

}

sub handle_nick {

	my ($old, $new) = @_;
	return unless defined $old && $old ne '';
	return unless defined $new && $new ne '';
	my $o = lc($old);
	my $n = lc($new);
	return if $o eq $n;
	for my $pk (keys %killchan_pending) {
		next if (index($pk, "$o\t") != 0);
		my $e = delete $killchan_pending{$pk};
		my $suffix = substr($pk, length($o) + 1);
		my $npk = $n . "\t" . $suffix;
		$e->{nick} = $new;
		$killchan_pending{$npk} = $e;
	}

}

# message.pl passes quotemeta()d PRIVMSG args; undo for channel/text matching.
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
		"\002[KILLCHAN]\002 Access denied: IRC operators only ($cmd).",
		"\00305\002[KILLCHAN]\017 \00304Access denied:\017 \00306IRC operators only (\00302$cmd\00306).\017"
	);
}

# Hash key for the same channel name (IRC channel compare is case-insensitive).
sub _killchan_find_key {
	my ($cand) = @_;
	return undef unless defined $cand && $cand ne '';
	for my $k (keys %killchans) {
		return $k if lc($k) eq lc($cand);
	}
	return undef;
}

sub stats {

	my $chans;
	my @kc = keys %killchans;
	$chans = scalar @kc;
	
	main::message("Killed users:                  \002$killed\002");
	main::message("Blacklisted channels:          \002$chans\002");
	main::message("Killchan join grace (seconds): \002" . _killchan_grace_sec() . "\002");
	main::message("Killchan pending timers:     \002" . (scalar keys %killchan_pending) . "\002");

}

sub scan_user {}

sub handle_notice {}

sub dump_chans {

	open(CHANS, ">$main::dir/killchans.conf");

	foreach my $key (keys %killchans) {

		print CHANS "$key\t$killchans{$key}\n";

	}
	
	close(CHANS);

}

sub add_killchan {
	my ($c,$m) = @_;
	$killchans{$c} = $m;
	dump_chans;
	return;
}

sub cmd_help {
	_cmsg(
		"\002[KILLCHAN]\002 \002killchan add #channel reason\002, \002killchan del #channel\002, \002killchan list\002 — control-channel commands need uplink oper; non-opers get a G-line after the configured join grace if they enter a listed channel (JOIN-only).",
		"\00305\002[KILLCHAN]\017 \00302killchan add #channel reason\017\00306,\017 \00302killchan del #channel\017\00306,\017 \00302killchan list\017 \00306— uplink oper on \00310\002$main::mychan\017\00306;\017 non-opers: G-line after join grace (\00302JOIN\017\00306 only).\017"
	);
}

sub handle_privmsg {

	my($nick,$ident,$host,$chan,$msg) = @_;
	$chan = _dsp($chan);
	$msg  = _dsp($msg);

	return if($chan !~ /^\Q$main::mychan\E$/i);

	if($msg =~ /^killchan(?:\s+|$)/i) {

		my $nick_d = _dsp($nick);
		if (!_is_ircop($nick_d)) {
			_deny_ircop_only('killchan');
			return;
		}

		$msg =~ s/^killchan\s+//i;
		$msg =~ s/^\s+//;

		if($msg =~ /^add (\S+) (.+)$/i) {

			my ($newc, $newr) = ($1, $2);
			if (my $ex = _killchan_find_key($newc)) {
				my $er = $killchans{$ex};
				_cmsg(
					"\002[KILLCHAN]\002 \002$newc\002 is already on the list (as \002$ex\002 — $er). Use \002killchan del $ex\002 first to remove or change it.",
					"\00305\002[KILLCHAN]\017 \00302\002$newc\017\00306 is already listed as \00302\002$ex\017\00306 — \00302$er\017\00306. Use \00302killchan del $ex\017\00306 first.\017"
				);
				return;
			}
			$killchans{$newc} = $newr;
			dump_chans;
			_cmsg(
				"\002[KILLCHAN]\002 Added \002$newc\002 to killchans list (\002$newr\002).",
				"\00305\002[KILLCHAN]\017 \00306Added\017 \00302\002$newc\017\00306 — \00302$newr\017\00306 (saved).\017"
			);
			_cmsg(
				"\002[KILLCHAN]\002 Note: clients \002already in\002 $newc are \002not\002 scanned — killchan only runs on \002JOIN\002. They are affected only after they /part and rejoin (or reconnect).",
				"\00305\002[KILLCHAN]\017 \00306Note:\017 clients \00302already in\017 \00302\002$newc\017\00306 are \00304not\017\00306 scanned — \00302JOIN\017\00306 only; \00306/part + rejoin\017\00306 or reconnect triggers enforcement.\017"
			);
			return;

		}

		if($msg =~ /^del (\S+)$/i) {

			my $want = $1;
			if (my $ex = _killchan_find_key($want)) {
				delete $killchans{$ex};
				dump_chans;
				_cmsg(
					"\002[KILLCHAN]\002 Removed \002$ex\002 from killchans list.",
					"\00305\002[KILLCHAN]\017 \00306Removed\017 \00302\002$ex\017\00306 from killchans list.\017"
				);
				return;
			}

			_cmsg(
				"\002[KILLCHAN]\002 \002$want\002 is not on the killchans list.",
				"\00305\002[KILLCHAN]\017 \00302\002$want\017\00306 is not on the killchans list.\017"
			);
			return;

		}

		if($msg =~ /^list$/i) {

			_cmsg(
				"\002[KILLCHAN]\002 Killchans list:",
				"\00305\002[KILLCHAN]\017 \00306killchans list:\017"
			);

			my $flag = 0;

			foreach my $key (sort keys %killchans) {

				$flag++;
				my $r = $killchans{$key};
				_cmsg(
					"  \002$key\002 — $r",
					"\00305  \00302\002$key\017\00306 — \00302$r\017"
				);

			}

			_cmsg(
				"\002[KILLCHAN]\002 (no channels on the list.)",
				"\00305\002[KILLCHAN]\017 \00306(no channels on the list.)\017"
			) if !$flag;
			return;

		}

		_cmsg(
			"\002[KILLCHAN]\002 Unrecognized command. Use: \002killchan add #channel reason\002 | \002killchan del #channel\002 | \002killchan list\002",
			"\00305\002[KILLCHAN]\017 \00306Unrecognized. Use:\017 \00302killchan add #channel reason\017 \00306|\017 \00302killchan del #channel\017 \00306|\017 \00302killchan list\017"
		);

	}

}

sub init {

	if(!main::depends("core-v1")) {

		print "This module requires version 1.x of defender.\n";
		exit(0);

	}

	main::provides("killchan");

	%killchans = ();

	if (open(my $CHANS, '<', "$main::dir/killchans.conf")) {
		while (<$CHANS>) {
			chomp;
			my ($chan, $reason) = split(/\t/);
			$killchans{$chan} = $reason if defined $chan;
		}
		close $CHANS;
	}

}

1;
