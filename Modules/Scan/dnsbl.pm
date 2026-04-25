#
# SPDX-License-Identifier: GPL-2.0-only
# Copyright (c) 2026 NetIRC Defender
#
# NetIRC Defender V3 - network security service

package Modules::Scan::dnsbl;

use strict;
use warnings;
use Socket;
use Config::General;
use Tie::IxHash;

my $dnsblconnects = 0;
my $dnsblkilled = 0;
my $dnsbl_cache_hits = 0;

tie my %dnsbls, "Tie::IxHash";

my %dnsbl_ip_cache;

sub _dnsbl_cache_ttl {
	my $v = $main::dataValues{'dnsbl_cache_ttl'};
	$v = 300 unless defined $v && $v =~ /^[0-9]+$/;
	$v = int($v);
	return 0 if $v < 0;
	return 86400 if $v > 86400;
	return $v;
}

sub _prune_expired_cache {
	my $now = time;
	for my $ip (keys %dnsbl_ip_cache) {
		my $rec = $dnsbl_ip_cache{$ip};
		next unless ref $rec eq 'ARRAY' && defined $rec->[0];
		delete $dnsbl_ip_cache{$ip} if $rec->[0] <= $now;
	}
}

sub _client_ipv4 {
	my ($host) = @_;
	return undef unless defined $host && $host ne '';
	if ($host =~ /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/ ) {
		my @o = ($1, $2, $3, $4);
		return undef if grep { $_ > 255 } @o;
		return join('.', @o);
	}
	my $addr = gethostbyname($host);
	return undef unless defined $addr;
	return inet_ntoa($addr);
}

sub _apply_dnsbl_hit {
	my ($nick, $ident, $host, $ip, $dnsbl, $ipres) = @_;
	my $desc = $dnsbls{$dnsbl}{'reply'}{$ipres};
	$desc = 'listed' unless defined $desc && $desc ne '';
	my $reason = $dnsbls{$dnsbl}{'reason'};
	$reason =~ s/\$ip/$ip/g;
	my $full_reason = "$desc $reason";
	main::message("User $nick!$ident\@$host ($ip) matches on $dnsbl ($desc)!");
	main::gline("*\@$ip", $dnsbls{$dnsbl}{'duration'}, $full_reason);
	# Keep Modules::Scan::gline cache in sync for automatic DNSBL GLINEs,
	# even when the network does not echo our own GL line back immediately.
	if (defined &Modules::Scan::gline::register_local_gline) {
		Modules::Scan::gline::register_local_gline(
			'dnsbl',
			"*\@$ip",
			$dnsbls{$dnsbl}{'duration'},
			$full_reason
		);
	}
	$dnsblkilled++;
}

sub handle_topic { }
sub handle_mode { }
sub handle_join { }
sub handle_part { }

sub stats
{
	my $percent = $dnsblconnects ? $dnsblkilled / $dnsblconnects * 100 : 0;
	$percent = $percent ? sprintf("%.3f", $percent) : 0;

	main::message("Total clients killed: \002$dnsblkilled\002");
	main::message("Total connecting clients scanned: \002$dnsblconnects\002");
	main::message("DNSBL cache hits:                 \002$dnsbl_cache_hits\002");
	main::message("Percentage of akilled clients: $percent%");
}

sub scan_user
{
	my ($ident, $host, $serv, $nick, $fullname, $print_always) = @_;
	return if ($main::NETJOIN == 1);
	$dnsblconnects++;
	_prune_expired_cache() if (rand() < 0.02);

	my $ip = _client_ipv4($host);
	return unless defined $ip;

	my $ttl = _dnsbl_cache_ttl();
	if ($ttl > 0 && exists $dnsbl_ip_cache{$ip}) {
		my $rec = $dnsbl_ip_cache{$ip};
		if (ref $rec eq 'ARRAY' && $rec->[0] > time) {
			$dnsbl_cache_hits++;
			my $tag = $rec->[1];
			if ($tag eq 'CLEAN') {
				return;
			}
			if (ref $tag eq 'HASH') {
				_apply_dnsbl_hit($nick, $ident, $host, $ip, $tag->{dnsbl}, $tag->{ipres});
				return;
			}
		}
	}

	my $arpa = join '.', reverse split /\./, $ip;
	foreach my $dnsbl (keys %dnsbls) {
		my $res1 = gethostbyname("$arpa.$dnsbl");
		if (defined $res1) {
			my ($ver1, $ver2, $ver3, $ipres) = split(/\./, inet_ntoa($res1));
			if ($ver1 != 127 && $ver2 != 0 && $ver3 != 0) {
				main::message("DNS Resolve through $dnsbl returned an invalid reply (" .
					inet_ntoa($res1) . ")!");
			}
			else {
				if ($ttl > 0) {
					$dnsbl_ip_cache{$ip} = [
						time + $ttl,
						{ dnsbl => $dnsbl, ipres => $ipres },
					];
				}
				_apply_dnsbl_hit($nick, $ident, $host, $ip, $dnsbl, $ipres);
				return;
			}
		}
	}

	if ($ttl > 0) {
		$dnsbl_ip_cache{$ip} = [ time + $ttl, 'CLEAN' ];
	}
}

sub handle_notice { }
sub handle_privmsg { }

sub init
{
	if (!main::depends("core-v1")) {
		print "This module requires version 1.x of defender.\n";
		exit(0);
	}
	main::provides("dnsbl");

	%dnsbl_ip_cache = ();
	$dnsbl_cache_hits = 0;

	my $conf = new Config::General(
		-ConfigFile      => "$main::dir/dnsbl.conf",
		-ExtendedAccess  => 1,
		-LowerCaseNames  => 1,
		-BackslashEscape => 1,
		-Tie             => "Tie::IxHash"
	);
	%dnsbls = $conf->getall;
}

1;
