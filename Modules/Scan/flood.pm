#
# SPDX-License-Identifier: GPL-2.0-only
# Copyright (c) 2026 NetIRC Defender
#
# NetIRC Defender V3 - network security service

package Modules::Scan::flood;

use strict;
use warnings;

sub _sanitize_p10_flood_extra {
	my ($raw) = @_;
	return '' if !defined $raw || $raw eq '';
	$raw =~ s/\s+//g;
	my $out = '';
	for my $ch (split //, $raw) {
		$out .= $ch if $ch =~ /^[ntsprca]$/i;
	}
	return $out;
}

sub _flood_mode_string {
	my ($extra) = @_;
	$extra //= '';
	return '+mi' . $extra;
}

my %chans;
my @lockchans;
my @locktime;
my @lockmodes;
my $flood_lock_seconds = 60;
my $flood_mode_double = 1;
my $nextinterval = 0;
my $threshold1 = 12;
my $threshold2 = 20;
my $threshold3 = 25;
my $floodmodes = "";
my $locked = 0;
my $warned = 0;
my $logged = 0;
my $totaljoins = 0;
my $nexttalk = 0;
my $interval = 5;

sub stats
{
	main::message("Flood threshold (log to channel):\002 $threshold1\002");
	main::message("Flood threshold (send globops):  \002 $threshold2\002");
	main::message("Flood threshold (lock channel):  \002 $threshold3\002");
	main::message("Flood lock MODE template:        \002" . _flood_mode_string($floodmodes) . "\002");
	main::message("Flood auto-unlock after:         \002$flood_lock_seconds\002 seconds");
	main::message("Flood MODE double-send:          \002" . ($flood_mode_double ? "yes" : "no") . "\002");
	main::message("Total channels locked:           \002 $locked\002");
	main::message("Total warnings given:            \002 $warned\002");
	main::message("Total floods logged:             \002 $logged\002");
	main::message(" ");
	main::message("\002Locked channels:\002");
	main::message(" ");
	my $totalchans = 0;
	foreach my $channel (keys %chans) {
		$totalchans++;
	}
	my $totallocked = 0;
	foreach my $lck (@lockchans) {
		$totallocked++;
		main::message("   $lck\n");
	}
	main::message(" ");
	main::message("Currently watching\002 $totalchans\002 channels, with a total of\002 $totaljoins\002 joins and parts");
	main::message("in the last\002 $interval\002 second interval.\002 $totallocked\002 channels are currently locked.");
}

sub _apply_channel_modes {
	my ($channel, $modes) = @_;
	return unless defined $channel && $channel ne '' && defined $modes && $modes ne '';
	main::mode($channel, $modes);
	main::mode($channel, $modes) if $flood_mode_double;
}

sub handle_expire
{
	while (defined $locktime[0] && $locktime[0] ne '' && time >= $locktime[0]) {
		my $chan = $lockchans[0];
		my $locked_with = $lockmodes[0] // _flood_mode_string($floodmodes);
		$locked_with = _flood_mode_string($floodmodes) unless defined $locked_with && $locked_with =~ /^\+/;
		my $unset = '-' . substr($locked_with, 1);
		_apply_channel_modes($chan, $unset);
		main::message("\002$chan\002 flood lock expired - removed \002$unset\002 (timer was ${flood_lock_seconds}s)");
		shift @lockchans;
		shift @locktime;
		shift @lockmodes;
	}
}

sub islocked
{
	my $comp = $_[0];
	if (defined($locktime[0]))
	{
		foreach my $chan (@lockchans) {
			if ($comp eq $chan) {
				return 1;
			}
		}
	}
	return 0;
}

sub handle_topic
{
}


sub generic_handler
{
	if ($main::NETJOIN == 1) {
		return;
	}

	my ($nick,$channel) = @_;
	$channel = lc($channel);

	if ($channel !~ /^#/) {
		return;
	}

	if (time > $nextinterval)
	{
		$nextinterval = time + $interval;
		%chans = ();
		$totaljoins = 0;
	}

	$totaljoins++;

	if (defined($chans{$channel})) {
		if ($chans{$channel} eq '') {
			$chans{$channel} = 0;
		}
	}
	else {
		$chans{$channel} = 0;
	}

	$chans{$channel}++;
	if ($chans{$channel} > $threshold3)
	{
		if (!islocked($channel)) {
			my $setmodes = _flood_mode_string($floodmodes);
			_apply_channel_modes($channel, $setmodes);
			main::notice($channel,"Join/part flood: applied \002$setmodes\002 - auto-remove in \002$flood_lock_seconds\002 seconds.");
			main::globops("ALERT: \002$channel\002 join/part flood - \002$setmodes\002 for \002$flood_lock_seconds\002 s (auto undo).");
			$chans{$channel} = 0;
			push @locktime,     time + $flood_lock_seconds;
			push @lockchans,    $channel;
			push @lockmodes,    $setmodes;
			$locked++;
		}
		return;
	}
	if ($chans{$channel} > $threshold2)
	{
		if (time > $nexttalk)
		{
			main::globops("ALERT! \002$channel\002 has been joined/parted " . $chans{$channel} . " times in the last $interval seconds, if it reaches $threshold3 joins and parts, it will be locked temporarily.");
			$warned++;
			$nexttalk = time+20;
		}
		return;
	}
	if ($chans{$channel} > $threshold1)
	{
		if (time > $nexttalk)
		{
			main::message("Channel \002$channel\002 has had " . $chans{$channel} . " joins/parts in the past\002 $interval\002 seconds, $threshold2 triggers oper alert.");
			$logged++;
			$nexttalk = time+20;
		}
		return;
	}
}

sub handle_join
{
	&generic_handler(@_);
	&handle_expire;
}

sub handle_part
{
	&generic_handler(@_);
	&handle_expire;
}


sub scan_user
{
	my ($ident,$host,$serv,$nick,$gecos,$print_always) = @_;
	&handle_expire;
}


sub handle_notice
{
	my ($nick,$ident,$host,$chan,$notice) = @_;
}


sub handle_mode
{
	my ($nick,$target,$params) = @_;
	&handle_expire;
}


sub handle_privmsg
{
        my ($nick,$ident,$host,$chan,$msg) = @_;
	&handle_expire;
}


sub init {

        if (!main::depends("core-v1","server")) {
                print "This module requires version 1.x of defender and a server link module to be loaded.\n";
                exit(0);
        }
        main::provides("flood");

	$threshold1 = $main::dataValues{'flood_log'};
	$threshold2 = $main::dataValues{'flood_globops'};
	$threshold3 = $main::dataValues{'flood_lock'};
	my $raw_flood = $main::dataValues{'flood_mode'} // '';
	$floodmodes = _sanitize_p10_flood_extra($raw_flood);
	my $wa = $main::dataValues{'flood_lock_channel_a'};
	my $want_a = 1;
	$want_a = 0 if defined $wa && $wa =~ /^(0|no|false)$/i;
	$floodmodes .= 'a' if $want_a && $floodmodes !~ /a/i;
	if ($raw_flood =~ /[^ntsprca\s]/i) {
		warn "[flood] flood_mode: invalid characters dropped (allowed: n t s p r c a)\n";
	}
	$flood_lock_seconds = $main::dataValues{'flood_lock_seconds'} // 60;
	$flood_lock_seconds = 60 if $flood_lock_seconds < 10 || $flood_lock_seconds > 3600;
	my $fd = $main::dataValues{'flood_mode_double'};
	$flood_mode_double = (defined $fd && $fd =~ /^(0|no|false)$/i) ? 0 : 1;
	$interval = $main::dataValues{'flood_interval'} // 5;
	$interval = 5 if $interval !~ /^[0-9]+$/ || $interval < 1;
	$interval = 3600 if $interval > 3600;
	$nextinterval = time + $interval;
	&handle_expire;
}

1;
