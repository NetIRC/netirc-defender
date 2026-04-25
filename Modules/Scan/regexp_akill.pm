#
# SPDX-License-Identifier: GPL-2.0-only
# Copyright (c) 2026 NetIRC Defender
#
# NetIRC Defender V3 - network security service

package Modules::Scan::regexp_akill;

use strict;
use warnings;

my $connects = 0;
my $killed = 0;
my $timeouts = 0;

my %akills;    # pattern string => reason (persistence / commands)
my @akill_qr;  # [ compiled_qr, reason, pattern_str ] — scan order

sub _akill_alarm_sec {
	my $v = $main::dataValues{'regexp_akill_alarm_sec'};
	$v = 3 unless defined $v && $v =~ /^[0-9]+$/;
	$v = int($v);
	return 0 if $v < 1;    # 0 = disable wall-clock guard (not recommended)
	return 8 if $v > 8;
	return $v;
}

sub _rebuild_akill_qr {
	@akill_qr = ();
	for my $pat (sort keys %akills) {
		next if !defined $pat || $pat eq '';
		my $qr = eval { qr/$pat/i };
		if (!$qr) {
			warn "[regexp_akill] skip invalid pattern (compile error): $pat — $@\n";
			next;
		}
		push @akill_qr, [ $qr, $akills{$pat}, $pat ];
	}
}

# message.pl passes quotemeta()d PRIVMSG args; undo for channel/text matching.
sub _dsp {
	my ($s) = @_;
	return '' unless defined $s;
	$s =~ s/\\(.)/$1/g;
	return $s;
}

sub handle_topic { }
sub handle_mode { }
sub handle_join { }
sub handle_part { }

sub stats {

	my $percent = $connects ? $killed / $connects * 100 : 0;
	$percent = $percent ? sprintf("%.3f", $percent) : 0;

	main::message("Total clients killed: \002$killed\002");
	main::message("Total connecting clients scanned: \002$connects\002");
	main::message("Regexp scan timeouts (skipped):  \002$timeouts\002");
	main::message("Percentage of akilled clients: $percent%");

}

sub scan_user {

	my ($ident, $host, $serv, $nick, $fullname, $print_always) = @_;

	$connects++;

	my $hostmask = "$nick!$ident\@$host $fullname";

	my $alarm_sec = _akill_alarm_sec();
	my $matched;
	my $reason;
	my $which;

	eval {
		local $SIG{ALRM} = sub { die "__akill_to__\n" };
		alarm($alarm_sec) if $alarm_sec > 0;
		for my $ent (@akill_qr) {
			my ($qr, $rsn, $label) = @$ent;
			if ($hostmask =~ $qr) {
				$matched = 1;
				$reason  = $rsn;
				$which   = $label;
				last;
			}
		}
		alarm(0);
		1;
	} or do {
		alarm(0);
		if ($@ =~ /__akill_to__/) {
			$timeouts++;
			main::message(
				"\002regexp_akill\002: pattern scan timed out after ${alarm_sec}s for \002$nick\002 — not akilled (review regex list).");
			return;
		}
		die $@;
	};

	if ($matched && $nick !~ /^Guest\d+/i) {
		my (undef, $ghost) = split('@', main::gethost($nick));
		main::gline("*\@$ghost", 600, $reason);
		main::message("User $hostmask matches regexp akill (\002$which\002)!");
		$killed++;
	}
}

sub handle_notice { }

sub dump_blacklist {

	my $path = "$main::dir/regexp_akill.conf";
	open my $BL, '>', $path or do {
		warn "[regexp_akill] cannot write $path: $!\n";
		return;
	};

	for my $key (sort keys %akills) {
		print {$BL} "$key\t" . $akills{$key} . "\n";
	}

	close $BL;

}

sub handle_privmsg {

	my ($nick, $ident, $host, $chan, $msg) = @_;
	$chan = _dsp($chan);
	$msg  = _dsp($msg);

	return if ($chan !~ /^\Q$main::mychan\E$/i);

	if ($msg =~ /^regexp_akill\s+/) {
		my $nick_d = _dsp($nick);
		if (!main::_is_ircop($nick_d)) {
			main::_deny_ircop_only('regexp_akill');
			return;
		}
		$msg =~ s/^regexp_akill\s+//;

		if ($msg =~ /^add (\S+) (.+)$/i) {
			my $regexp = $1;
			my $reason = $2;

			$regexp =~ s/\@/\\x40/g;
			$regexp =~ s/\%/\\x25/g;

			if ($regexp =~ /\$\w/) {
				main::message('The character \'$\' is not allowed in this usage.');
				return;
			}

			main::message(
				'Note: multiple \'.*\' in one pattern can cause heavy CPU — optimize where possible.')
				if ($regexp =~ /\Q.*\E.*?\Q.*\E/);

			$akills{$regexp} = $reason;
			_rebuild_akill_qr();
			dump_blacklist;
			main::message("Regexp akill added. ($regexp)");

		}
		elsif ($msg =~ /^del (.+)$/i) {

			for my $key (keys %akills) {

				if ($key eq $1) {

					delete $akills{$1};
					_rebuild_akill_qr();
					dump_blacklist;
					main::message("Regexp akill deleted. ($1)");
					return;

				}

			}

			main::message("No such regexp akill.");

		}
		elsif ($msg =~ /^list$/i) {

			main::message('Listing regexp kills:');

			my $flag = 0;

			for my $key (sort keys %akills) {
				$flag++;
				main::message("$key     " . $akills{$key});

			}

			main::message('No regexp akills defined!') unless $flag;

		}
		else {
			main::message('Unrecognized regexp_akill command!');
		}

	}

}

sub cmd_help {
	main::_cmsg(
		"\002[REGEXP_AKILL]\002 On each new client sign-on the bot builds one line: \002nick!ident\@host realname\002 (Perl regex, case-insensitive). If any saved pattern matches, that user is \002G-lined\002 (~10 min) with the reason you set. Rules file: \002regexp_akill.conf\002.",
		"\00305\002[REGEXP_AKILL]\017 \00306On sign-on:\017 \00302nick!ident\@host realname\017 \00306vs your regexes (case-insensitive). Match \00304G-line\017\00306 ~10m + reason. File:\017 \00302regexp_akill.conf\017\00306.\017"
	);
	main::_cmsg(
		"\002[REGEXP_AKILL]\002 Commands: \002regexp_akill add <pattern> <reason>\002 | \002regexp_akill del <pattern>\002 | \002regexp_akill list\002. Avoid long/backtrack-heavy patterns (e.g. many \002.*\002); scans have a short time limit.",
		"\00305\002[REGEXP_AKILL]\017 \00306Commands:\017 \00302add <pattern> <reason>\017 \00306|\017 \00302del <pattern>\017 \00306|\017 \00302list\017\00306. Avoid heavy regexes (\00302.*\017\00306); time-limited scan.\017"
	);
}

sub init {

	if (!main::depends("core-v1")) {
		print "This module requires version 1.x of defender.\n";
		exit(0);
	}
	main::provides("regexp_akill");

	%akills = ();
	@akill_qr = ();

	my $path = "$main::dir/regexp_akill.conf";
	if (open my $BL, '<', $path) {
		while (<$BL>) {
			chomp;
			s/\r\z//;
			next if /^\s*$/ || /^\s*#/;
			my ($regexp, $reason) = split(/\t/);
			next unless defined $regexp && $regexp ne '';
			$reason //= '';
			$akills{$regexp} = $reason;
		}
		close $BL;
	}
	else {
		warn "[regexp_akill] $path not found — no rules until you create the file or use regexp_akill add.\n";
	}
	_rebuild_akill_qr();
}

1;
