#
# SPDX-License-Identifier: GPL-2.0-only
# Copyright (c) 2026 NetIRC Defender
#
# NetIRC Defender V3 - network security service

package Modules::Scan::cgiirc;

use strict;
use warnings;

our $cgi_connects;
our $cgi_killtotal;

my @whitelist_qr;    # compiled patterns from cgiirc.conf

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
	my $per = (($Modules::Scan::cgiirc::cgi_killtotal / ($Modules::Scan::cgiirc::cgi_connects + 0.0001)) * 100);
	if (length($per) > 6) {
		$per = substr($per, 0, 6);
	}
	main::message("Total clients killed:             \002$Modules::Scan::cgiirc::cgi_killtotal\002");
	main::message("Total connecting clients scanned: \002$Modules::Scan::cgiirc::cgi_connects\002");
	main::message("Percentage CGI users:             \002$per%\002");
}

sub scan_user
{
	my ($ident, $host, $serv, $nick, $fullname, $print_always) = @_;
	$ident    = _dsp($ident);
	$host     = _dsp($host);
	$serv     = _dsp($serv);
	$nick     = _dsp($nick);
	$fullname = _dsp($fullname);
	my $nicksyms = 0;
	my $nicknums = 0;
	my $total    = 0;
	my $status   = "";

	if (($fullname =~ /^\[[0-9a-f]{8}\]../i) || ($ident =~ /^[0-9a-f]{8}$/i)) {
		main::message_to($nick, "\001VERSION\001");
		main::message("Possible unauthorised CGI:IRC usage by $nick!$ident\@$host, \"$fullname\"");
		my $coded = "";
		if ($fullname =~ /^\[([0-9a-f]{8})\]../i) {
			$coded = $1;
		}
		if ($ident =~ /^([0-9a-f]{8})$/i) {
			$coded = $1;
		}
	}
	$cgi_connects++;
}

sub handle_notice
{
	my ($nick, undef, $host, undef, $notice) = @_;
	$nick   = _dsp($nick);
	$host   = _dsp($host);
	$notice = _dsp($notice);

	for my $qr (@whitelist_qr) {
		return if $host =~ $qr;
	}
	if ($notice =~ /\001VERSION CGI\:IRC ([^ \001]+)[^\001]*\001/) {
		my $version = $1;
		$cgi_killtotal++;
		main::message(
			"\002Killed! Unauthorised IRC VERIFIED\002 from nickname $nick (using CGI:IRC version \002$version\002)");
		main::gline(
			$host,
			1200,
			"You are using an \002unauthorised CGI:IRC gateway\002 to connect to $main::netname. This is a form of \002open proxy\002 used to evade bans and get around firewall policies, and is therefore not allowed. Please email \002$main::killmail\002 for a list of authorised CGI:IRC proxies for connecting to $main::netname."
		);
	}
}

sub handle_privmsg { }

sub _load_cgiirc_whitelist {
	@whitelist_qr = ();
	my $path = "$main::dir/cgiirc.conf";
	open my $fh, '<', $path or do {
		warn "[cgiirc] $path not found — whitelist empty (create file to add host patterns).\n";
		return;
	};
	while (my $line = <$fh>) {
		chomp $line;
		$line =~ s/\r\z//;
		next if $line =~ /^\s*$/ || $line =~ /^\s*#/;
		my $qr = eval { qr/$line/i };
		if (!$qr) {
			warn "[cgiirc] skip invalid whitelist line (compile error): $line — $@\n";
			next;
		}
		push @whitelist_qr, $qr;
	}
	close $fh;
}

sub init {

	if (!main::depends("core-v1")) {
		print "This module requires version 1.x of defender.\n";
		exit(0);
	}
	main::provides("cgiirc");

	_load_cgiirc_whitelist();

	$cgi_killtotal = 0;
	$cgi_connects  = 0;
}

1;
