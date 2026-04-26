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
my $dnsbl_query_timeouts = 0;
my $dnsbl_cb_skipped = 0;
my $dnsbl_backlog_skipped = 0;
my $dnsbl_cb_until = 0;
my @dnsbl_conn_times;
my @dnsbl_timeout_times;
my $dnsbl_cb_notice_state = 0;

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

sub _dnsbl_query_timeout_sec {
	my $k = 'dnsbl_query_timeout_sec';
	if (defined &main::is_attack_mode && main::is_attack_mode()) {
		my $ak = 'attack_' . $k;
		$k = $ak if defined $main::dataValues{$ak} && $main::dataValues{$ak} ne '';
	}
	my $v = $main::dataValues{$k};
	$v = 2 unless defined $v && $v =~ /^[0-9]+$/;
	$v = int($v);
	return 0 if $v < 0;
	return 10 if $v > 10;
	return $v;
}

sub _dnsbl_cb_trigger_conn_per_min {
	my $k = 'dnsbl_cb_trigger_conn_per_min';
	if (defined &main::is_attack_mode && main::is_attack_mode()) {
		my $ak = 'attack_' . $k;
		$k = $ak if defined $main::dataValues{$ak} && $main::dataValues{$ak} ne '';
	}
	my $v = $main::dataValues{$k};
	$v = 80 unless defined $v && $v =~ /^[0-9]+$/;
	$v = int($v);
	return 0 if $v < 0;
	return 5000 if $v > 5000;
	return $v;
}

sub _dnsbl_cb_trigger_timeouts_per_min {
	my $k = 'dnsbl_cb_trigger_timeouts_per_min';
	if (defined &main::is_attack_mode && main::is_attack_mode()) {
		my $ak = 'attack_' . $k;
		$k = $ak if defined $main::dataValues{$ak} && $main::dataValues{$ak} ne '';
	}
	my $v = $main::dataValues{$k};
	$v = 20 unless defined $v && $v =~ /^[0-9]+$/;
	$v = int($v);
	return 0 if $v < 0;
	return 5000 if $v > 5000;
	return $v;
}

sub _dnsbl_cb_cooldown_sec {
	my $k = 'dnsbl_cb_cooldown_sec';
	if (defined &main::is_attack_mode && main::is_attack_mode()) {
		my $ak = 'attack_' . $k;
		$k = $ak if defined $main::dataValues{$ak} && $main::dataValues{$ak} ne '';
	}
	my $v = $main::dataValues{$k};
	$v = 120 unless defined $v && $v =~ /^[0-9]+$/;
	$v = int($v);
	return 10 if $v < 10;
	return 3600 if $v > 3600;
	return $v;
}

sub _dnsbl_backlog_skip_ttl_sec {
	my $v = $main::dataValues{'dnsbl_backlog_skip_ttl_sec'};
	$v = 15 unless defined $v && $v =~ /^[0-9]+$/;
	$v = int($v);
	return 0 if $v < 0;
	return 300 if $v > 300;
	return $v;
}

sub _dnsbl_should_yield_parser {
	if (defined &main::link_dispatch_batch_count) {
		my $b = eval { main::link_dispatch_batch_count() };
		return 1 if defined $b && $b > 1;
	}
	return 0 unless defined &main::link_input_pending;
	my $busy = eval { main::link_input_pending() };
	return ($busy ? 1 : 0);
}

sub _dnsbl_soft_cache_clean {
	my ($ip, $ttl) = @_;
	return unless defined $ip && $ip ne '';
	return unless defined $ttl && $ttl > 0;
	$dnsbl_ip_cache{$ip} = [ time + $ttl, 'CLEAN' ];
}

sub _dnsbl_lookup_with_timeout {
	my ($query) = @_;
	my $to = _dnsbl_query_timeout_sec();
	if ($to <= 0) {
		return (gethostbyname($query), 0);
	}
	my $timed_out = 0;
	my $res;
	eval {
		local $SIG{ALRM} = sub { die "__DNSBL_TIMEOUT__\n" };
		alarm($to);
		$res = gethostbyname($query);
		alarm(0);
	};
	if ($@) {
		$timed_out = ($@ =~ /__DNSBL_TIMEOUT__/) ? 1 : 0;
		eval { alarm(0) };
	}
	return ($res, $timed_out);
}

sub _dnsbl_record_conn_rate {
	my $now = time;
	push @dnsbl_conn_times, $now;
	@dnsbl_conn_times = grep { $_ > ($now - 60) } @dnsbl_conn_times;
}

sub _dnsbl_record_timeout_rate {
	my $now = time;
	push @dnsbl_timeout_times, $now;
	@dnsbl_timeout_times = grep { $_ > ($now - 60) } @dnsbl_timeout_times;
}

sub _dnsbl_cb_maybe_trip {
	my ($reason) = @_;
	my $cool = _dnsbl_cb_cooldown_sec();
	my $new_until = time + $cool;
	$dnsbl_cb_until = $new_until if $new_until > $dnsbl_cb_until;
	if (!$dnsbl_cb_notice_state) {
		main::globops("[DNSBL] Circuit breaker enabled for ${cool}s ($reason).");
		main::message("\002[DNSBL]\002 Circuit breaker enabled for ${cool}s ($reason).");
		$dnsbl_cb_notice_state = 1;
	}
}

sub _dnsbl_cb_should_skip {
	my $now = time;
	if ($dnsbl_cb_until > $now) {
		return 1;
	}
	if ($dnsbl_cb_notice_state) {
		main::message("\002[DNSBL]\002 Circuit breaker disabled; DNSBL checks resumed.");
		$dnsbl_cb_notice_state = 0;
	}
	my $tr_conn = _dnsbl_cb_trigger_conn_per_min();
	if ($tr_conn > 0 && scalar(@dnsbl_conn_times) >= $tr_conn) {
		_dnsbl_cb_maybe_trip('high connect rate');
		return 1;
	}
	my $tr_to = _dnsbl_cb_trigger_timeouts_per_min();
	if ($tr_to > 0 && scalar(@dnsbl_timeout_times) >= $tr_to) {
		_dnsbl_cb_maybe_trip('excess DNS timeouts');
		return 1;
	}
	return 0;
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

sub _client_ipv4_from_link_cache {
	my ($nick) = @_;
	return undef unless defined $nick && $nick ne '';
	return undef unless defined &main::client_link_info;
	my $info = eval { main::client_link_info($nick) };
	return undef unless $info && ref $info eq 'HASH';
	my $ip = $info->{client_ip};
	return undef unless defined $ip && $ip ne '';
	return undef unless $ip =~ /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
	my @o = ($1, $2, $3, $4);
	return undef if grep { $_ > 255 } @o;
	return join('.', @o);
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
	main::message("DNSBL query timeouts:             \002$dnsbl_query_timeouts\002");
	main::message("DNSBL CB skipped checks:          \002$dnsbl_cb_skipped\002");
	main::message("DNSBL parser-yield skips:         \002$dnsbl_backlog_skipped\002");
	my $cb_left = ($dnsbl_cb_until > time) ? ($dnsbl_cb_until - time) : 0;
	main::message("DNSBL CB active (seconds left):   \002$cb_left\002");
	main::message("Percentage of akilled clients: $percent%");
}

sub scan_user
{
	my ($ident, $host, $serv, $nick, $fullname, $print_always) = @_;
	return if ($main::NETJOIN == 1);
	$dnsblconnects++;
	_prune_expired_cache() if (rand() < 0.02);
	_dnsbl_record_conn_rate();
	if (_dnsbl_cb_should_skip()) {
		$dnsbl_cb_skipped++;
		return;
	}
	my $ttl = _dnsbl_cache_ttl();
	my $soft = _dnsbl_backlog_skip_ttl_sec();
	if (_dnsbl_should_yield_parser()) {
		$dnsbl_backlog_skipped++;
		return;
	}

	my $ip = _client_ipv4_from_link_cache($nick);
	if (!defined $ip && _dnsbl_should_yield_parser()) {
		$dnsbl_backlog_skipped++;
		return;
	}
	$ip = _client_ipv4($host) unless defined $ip;
	return unless defined $ip;

	if (_dnsbl_should_yield_parser()) {
		$dnsbl_backlog_skipped++;
		_dnsbl_soft_cache_clean($ip, (($soft < $ttl) ? $soft : $ttl)) if $soft > 0;
		return;
	}
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
		if (_dnsbl_should_yield_parser()) {
			$dnsbl_backlog_skipped++;
			_dnsbl_soft_cache_clean($ip, (($soft < $ttl) ? $soft : $ttl)) if $soft > 0;
			last;
		}
		my ($res1, $timed_out) = _dnsbl_lookup_with_timeout("$arpa.$dnsbl");
		if ($timed_out) {
			$dnsbl_query_timeouts++;
			_dnsbl_record_timeout_rate();
			next;
		}
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
	$dnsbl_query_timeouts = 0;
	$dnsbl_cb_skipped = 0;
	$dnsbl_backlog_skipped = 0;
	$dnsbl_cb_until = 0;
	@dnsbl_conn_times = ();
	@dnsbl_timeout_times = ();
	$dnsbl_cb_notice_state = 0;

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
