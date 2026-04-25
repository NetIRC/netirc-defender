#
# SPDX-License-Identifier: GPL-2.0-only
# Copyright (c) 2026 NetIRC Defender
#
# NetIRC Defender V3 - network security service

package Modules::Scan::verbose;

use strict;
use warnings;

sub _dsp {
	my ($s) = @_;
	return '' unless defined $s;
	$s =~ s/\\(.)/$1/g;
	return $s;
}

sub _trunc {
	my ($s, $max) = @_;
	$max //= 120;
	return '' unless defined $s;
	return $s if length($s) <= $max;
	return substr($s, 0, $max - 3) . '...';
}

# Omit quit "reason" when it only repeats our label or stock client text (e.g. "Signed off").
sub _redundant_quit_reason {
	my ($r) = @_;
	return 1 unless defined $r;
	$r =~ s/^\s+|\s+$//g;
	return 1 if $r eq '';
	$r =~ s/^Quit:\s*//i;
	return 1 if $r =~ /^(signed off|signing off|disconnected|connection closed|client exited|client quit|remote quit|leaving|gone|quit)\.?$/i;
	return 1 if $r =~ /^(ping timeout|connection reset|read error|broken pipe)/i;
	return 0;
}

# P10/ircu often appends channel TS after MODE args; strip for concise #console output only.
sub _display_mode_params {
	my ($p) = @_;
	return $p unless defined $p && $p ne '' && $p ne '(none)';
	$p =~ s/\s+\d{9,12}\z//;
	return $p;
}

sub handle_join
{
        return if ($main::NETJOIN == 1);
        my ($nick, $chan) = @_;
	$nick = _dsp($nick);
	$chan = _dsp($chan);
	if ($main::ugly) {
	main::message("Joined channel: $nick joined $chan");
	}else{
        main::message("\00305Joined channel: \00302\002$nick\017\00305 joined \017\002$chan\017");
	}
}

sub handle_part
{
        my ($nick, $chan) = @_;
	$nick = _dsp($nick);
	$chan = _dsp($chan);
	if ($main::ugly) {
	main::message("Left channel: $nick left $chan");
	}else{
        main::message("\00305Left channel: \00302\002$nick\017\00305 left \017\002$chan\017");
	}

}

sub handle_kick
{
        my($nick,$chan,$kicked,$reason) = @_;
	$nick   = _dsp($nick);
	$chan   = _dsp($chan);
	$kicked = _dsp($kicked);
	$reason = _dsp($reason);
	$reason = '(none given)' if !defined($reason) || $reason eq '';
        if ($main::ugly) {
        main::message("Kick: $kicked was removed from $chan by $nick — $reason");
        }else{
        main::message("\00304Kick: \00302\002$kicked\017\00305 removed from \017\002$chan\017 by \00302\002$nick\017\00305 — \00306$reason\017");
        }
}

sub handle_kill
{
	my ($killer, $victim, $reason) = @_;
	$killer = defined $killer ? _dsp($killer) : '';
	$victim = defined $victim ? _dsp($victim) : '';
	my $rs = defined $reason ? _dsp($reason) : '';
	$rs = '(no reason)' if $rs eq '';
	my $src = ($killer ne '') ? $killer : '(unknown source)';
	if ($main::ugly) {
		main::message("KILL: $victim by $src — $rs");
	} else {
		main::message("\00304KILL:\017 \00302\002$victim\017 \00305by\017 \00302\002$src\017 \00305—\017 \00306$rs\017");
	}
}

sub handle_quit
{
        my ($quitnick, $quitreason, $serv) = @_;
	$quitnick = _dsp($quitnick);
	my $qr = defined $quitreason ? _dsp($quitreason) : '';
	$serv = defined $serv ? _dsp($serv) : '';
	my $srv_plain = ($serv ne '') ? " | Server: \002$serv\002" : '';
	my $srv_color = ($serv ne '') ? " \00305| Server:\017 \00302$serv\017" : '';
	my $reason_bit_plain = ($qr ne '' && !_redundant_quit_reason($qr)) ? " — $qr" : '';
	my $reason_bit_color = ($qr ne '' && !_redundant_quit_reason($qr)) ? " \00305— \00306$qr\017" : '';
	if ($main::ugly) {
	main::message("Signed off: $quitnick$reason_bit_plain$srv_plain");
	} elsif ($reason_bit_plain ne '') {
        main::message("\00304Signed off: \00302\002$quitnick\017$reason_bit_color$srv_color");
	} else {
        main::message("\00304Signed off: \00302\002$quitnick\017$srv_color");
	}
}


sub handle_topic
{
	return if ($main::NETJOIN == 1);
	my($nick,$chan,$topic) = @_;
	$nick  = _dsp($nick);
	$chan  = _dsp($chan);
	$topic = _dsp($topic);
	my $prev = _trunc($topic, 120);
	my $by = ($nick ne '') ? " by $nick" : '';
	if ($main::ugly) {
	main::message("Topic on $chan was set$by: $prev");
	}else{
	main::message("\00305Topic on \017\002$chan\017\00305 set$by:\017 \00306$prev\017");
	}
}

sub handle_mode
{
	return if ($main::NETJOIN == 1);
	my ($nick, $target, $params) = @_;
	$nick   = _dsp($nick);
	$target = _dsp($target);
	$params = _dsp($params);
	$params = '(none)' if !defined($params) || $params eq '';
	my $modes = _display_mode_params($params);
	my $who = ($nick ne '') ? $nick : '(unknown)';
	my $is_chan = (defined $target && $target =~ /^[#&+!]/);
	if ($is_chan) {
		if ($main::ugly) {
			main::message("MODE on $target by $who: $modes");
		} else {
			main::message("\00305MODE on\017 \017\002$target\017 \00305by\017 \00302\002$who\017\00305:\017 \00306$modes\017");
		}
	} else {
		if ($main::ugly) {
			main::message("MODE on user $target by $who: $modes");
		} else {
			main::message("\00305MODE on user\017 \00302\002$target\017 \00305by\017 \00302\002$who\017\00305:\017 \00306$modes\017");
		}
	}
}

sub scan_user
{
        my ($ident,$host,$serv,$nick,$gecos,$print_always) = @_;
        return if ($main::NETJOIN == 1);
	$ident  = _dsp($ident);
	$host   = _dsp($host);
	$serv   = _dsp($serv);
	$nick   = _dsp($nick);
	$gecos  = _dsp($gecos);
	my $srv = (defined $serv && $serv ne '') ? $serv : 'unknown';
	if ($main::ugly) {
	main::message("Signed on: $nick!$ident@$host | Server: $srv | Real name: $gecos");
	}else{
        main::message("\00305Signed on: \00302\002$nick\017\00306!\017$ident\00306\@\017\00302$host\017 \00305| Server: \00306$srv\017 \00305| Real name: \00306$gecos\017");
	}
}

sub handle_nick
{
        my ($oldnick,$newnick) = @_;
	$oldnick = _dsp($oldnick);
	$newnick = _dsp($newnick);
	if ($main::ugly) {
	main::message("Nickname changed: $oldnick is now $newnick");
	}else{
        main::message("\00305Nickname changed: \00302\002$oldnick\017 \00305→ \00302\002$newnick\017");
	}
}

sub handle_away
{
	# Suppress noise during net synchronisation: when we (re)connect to
	# the hub the burst replays AWAY state for every away client.
	return if ($main::NETJOIN == 1);
	my ($nick, $msg) = @_;
	$nick = _dsp($nick);
	$msg  = defined $msg ? _dsp($msg) : '';
	# Trim a known noise source: clients that send literal CR/LF inside
	# the AWAY argument (rare, but seen in practice).
	$msg =~ s/[\r\n]+/ /g;
	my $trimmed = _trunc($msg, 200);
	if ($msg ne '') {
		if ($main::ugly) {
			main::message("AWAY: $nick is now away — $trimmed");
		} else {
			main::message("\00305AWAY: \00302\002$nick\017 \00305is now away — \00306$trimmed\017");
		}
	} else {
		if ($main::ugly) {
			main::message("AWAY: $nick is back");
		} else {
			main::message("\00305AWAY: \00302\002$nick\017 \00305is back\017");
		}
	}
}

sub handle_notice
{

}

sub handle_privmsg
{

}

sub stats {
	main::message("Verbose: sign-on/off, KILL (P10 D), join/part, kick, topic, channel/user MODE, nick change - no numeric stats.");
}

sub init {

        if (!main::depends("core-v1")) {
                print "This module requires version 1.x of defender.\n";
                exit(0);
        }
        main::provides("verbose");
        if (!$main::ugly) {
                print "verbose: formatted control-channel event log (set ugly=1 for plain text). Loading... ";
        }
}

1;
