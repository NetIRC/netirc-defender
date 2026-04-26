#
# SPDX-License-Identifier: GPL-2.0-only
# Copyright (c) 2026 NetIRC Defender
#
# NetIRC Defender V3 - network security service

package Modules::Scan::conn_average;

use strict;
use warnings;

my $conns = 0;
my $currtime = time;
my $max_conns_per_min = 0;
my $peak = 0;
my $ptime = "(Never)";
my $pbroken = "(Never)";
my $autoblock_until = 0;
my $autoblock_actions = 0;
my %autoblock_masks_seen;

sub _autoblock_enabled {
	my $v = $main::dataValues{"conn_average_autoblock"};
	my $on = ($v =~ /^(1|true|yes|on)$/i) ? 1 : 0;
	if (defined &main::is_attack_mode && main::is_attack_mode()) {
		my $av = $main::dataValues{"conn_average_autoblock_attack_mode"};
		my $aon = (!defined $av || $av eq '') ? 1 : (($av =~ /^(1|true|yes|on)$/i) ? 1 : 0);
		return 1 if $aon;
	}
	return $on;
}

sub _autoblock_duration_sec {
	my $k = "conn_average_autoblock_duration_sec";
	if (defined &main::is_attack_mode && main::is_attack_mode()) {
		my $ak = "attack_" . $k;
		$k = $ak if defined $main::dataValues{$ak} && $main::dataValues{$ak} ne '';
	}
	my $v = $main::dataValues{$k};
	$v = 600 unless defined $v && $v =~ /^[0-9]+$/;
	$v = int($v);
	return 60 if $v < 60;
	return 86400 if $v > 86400;
	return $v;
}

sub _attack_enter_conn_per_min {
	my $v = $main::dataValues{"attack_mode_enter_conn_per_min"};
	$v = $max_conns_per_min if !defined $v || $v eq '';
	$v = int($v) if defined $v && $v =~ /^[0-9]+$/;
	$v = 0 unless defined $v && $v =~ /^[0-9]+$/;
	return $v;
}

sub _autoblock_reason {
	my $r = $main::dataValues{"conn_average_autoblock_reason"};
	$r = 'Connection flood emergency block' if !defined $r || $r eq '';
	$r =~ s/[\x00\r\n]//g;
	$r = substr($r, 0, 180) if length($r) > 180;
	return $r;
}

sub _autoblock_mask_for_nick {
	my ($nick) = @_;
	return undef unless defined $nick && $nick ne '';
	if (defined &main::client_link_info) {
		my $info = eval { main::client_link_info($nick) };
		if ($info && ref $info eq 'HASH') {
			my $ip = $info->{client_ip};
			if (defined $ip && $ip =~ /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/) {
				my @o = ($1, $2, $3, $4);
				if (!grep { $_ > 255 } @o) {
					return '*@' . join('.', @o);
				}
			}
		}
	}
	my $uh = eval { main::gethost($nick) };
	return undef unless defined $uh && $uh ne '';
	my $host = ($uh =~ /@/) ? (split(/@/, $uh, 2))[1] : $uh;
	return undef unless defined $host && $host ne '';
	return '*@' . $host;
}

sub _maybe_autoblock_current_nick {
	my ($nick) = @_;
	return unless _autoblock_enabled();
	return unless time() < $autoblock_until;
	my $mask = _autoblock_mask_for_nick($nick);
	return unless defined $mask && $mask ne '';
	return if exists $autoblock_masks_seen{lc $mask};
	$autoblock_masks_seen{lc $mask} = 1;
	my $why = _autoblock_reason();
	my $dur = _autoblock_duration_sec();
	main::gline($mask, $dur, $why);
	if (defined &Modules::Scan::gline::register_local_gline) {
		Modules::Scan::gline::register_local_gline('conn_average', $mask, $dur, $why);
	}
	$autoblock_actions++;
}

sub _mirror_console {
	my $v = $main::dataValues{"conn_average_mirror_console"};
	return 1 if !defined $v || $v eq '';
	return $v ne "0";
}

sub handle_topic
{
}

sub handle_mode
{
}

sub handle_join
{

}

sub handle_part
{

}

sub stats {
	main::message("Connections in last minute:       \002$conns\002");
	main::message("Connections per minute peak:      \002$peak\002 at \002$ptime\002");
	main::message("Configuration alert level:        \002$max_conns_per_min\002 connections/minute");
	main::message("Alert peak last broken:           \002$pbroken\002");
	my $left = ($autoblock_until > time()) ? ($autoblock_until - time()) : 0;
	main::message("Conn-average autoblock:           \002" . (_autoblock_enabled() ? "ON" : "OFF") . "\002");
	main::message("Autoblock active (seconds left):  \002$left\002");
	main::message("Autoblock GLINE actions:          \002$autoblock_actions\002");
}

sub scan_user
{
	return if ($main::NETJOIN == 1);

	my ($ident,$host,$serv,$nick,$gecos,$print_always) = @_;
	$conns++;
	_maybe_autoblock_current_nick($nick);
	if (time > ($currtime+60))
	{
		if ($max_conns_per_min > 0 && $conns > $max_conns_per_min)
		{
			my $attack_tr = _attack_enter_conn_per_min();
			if ($attack_tr > 0 && $conns >= $attack_tr && defined &main::enter_attack_mode) {
				main::enter_attack_mode("high connection rate (${conns}/min)");
			}
			my $msg =
				"\002WARNING!\002 Connections in the last minute was \002$conns\002, which is above the maximum safe connections of $max_conns_per_min per minute!";
			main::globops($msg);
			if (_mirror_console()) {
				main::message(
					"\002[CONN_AVERAGE]\002 $msg Automatic blocks: \002dnsbl\002 (IP), \002version\002 + deny_version.conf (CTCP VERSION); optional \002regexp_akill\002 if in modules=."
				);
			}
			if (_autoblock_enabled()) {
				my $dur = _autoblock_duration_sec();
				%autoblock_masks_seen = () if time >= $autoblock_until;
				my $new_until = time + $dur;
				$autoblock_until = $new_until if $new_until > $autoblock_until;
				main::globops("[CONN_AVERAGE] Emergency autoblock enabled for ${dur}s (new clients will be G-lined).");
				if (_mirror_console()) {
					main::message("\002[CONN_AVERAGE]\002 Emergency autoblock enabled for ${dur}s (new clients will be G-lined).");
				}
			}
			$pbroken = localtime;
		}
		if ($conns > $peak)
		{
			$peak = $conns;
			$ptime = localtime;
		}
		$conns = 0;
		$currtime = time;
	}
}


sub handle_notice
{
	my ($nick,$ident,$host,$chan,$notice) = @_;
}

sub handle_privmsg
{
        my ($nick,$ident,$host,$chan,$msg) = @_;
}


sub init {

        if (!main::depends("core-v1")) {
                print "This module requires version 1.x of defender.\n";
                exit(0);
        }
        main::provides("conn_average");

	$currtime = time;
	$peak = 0;
	$autoblock_until = 0;
	$autoblock_actions = 0;
	%autoblock_masks_seen = ();
	my $raw = $main::dataValues{"conn_average_max"};
	if ( !defined $raw || $raw eq '' || $raw !~ /^[0-9]+$/ ) {
		$max_conns_per_min = 30;
	}
	else {
		$max_conns_per_min = int($raw);
	}
}

1;
