#
# SPDX-License-Identifier: GPL-2.0-only
# Copyright (c) 2026 NetIRC Defender
#
# NetIRC Defender V3 - network security service

package Modules::Log::Text;

use strict;
use warnings;

our $filename = '';
our $next_log_check_at = 0;

sub _max_bytes {
	my $mb = $main::dataValues{"log_rotate_mb"};
	$mb = 10 unless defined $mb && $mb =~ /^[0-9]+(?:\.[0-9]+)?$/;
	return 0 if $mb <= 0;    # 0 = disabled (grow forever or use system logrotate)
	return int($mb * 1024 * 1024);
}

sub _keep_count {
	my $k = $main::dataValues{"log_rotate_keep"};
	$k = 7 unless defined $k && $k =~ /^[0-9]+$/;
	$k = int($k);
	return $k < 1 ? 7 : $k;
}

sub _check_interval {
	my $s = $main::dataValues{"log_rotate_interval_sec"};
	$s = 300 unless defined $s && $s =~ /^[0-9]+$/;
	$s = int($s);
	return $s < 60 ? 60 : $s;
}

sub _rotate_chain {
	my ($path, $keep) = @_;
	return unless defined $path && $path ne '' && -f $path;
	$keep = _keep_count() unless defined $keep;
	unlink "$path.$keep" if -e "$path.$keep";
	for (my $i = $keep - 1; $i >= 1; $i--) {
		next unless -e "$path.$i";
		rename "$path.$i", "$path." . ($i + 1) or warn "Text log: rename $path.$i: $!\n";
	}
	rename $path, "$path.1" or warn "Text log: rotate $path: $!\n";
}

sub _reopen_log {
	my ($path) = @_;
	close STDOUT;
	close STDERR;
	open STDOUT, '>>', $path or die "Text log: cannot reopen STDOUT $path: $!\n";
	open STDERR, '>&STDOUT' or die "Text log: cannot dup STDERR: $!\n";
}

sub _rotate_if_oversize {
	my ($path) = @_;
	my $max = _max_bytes();
	return 0 if $max <= 0;
	return 0 unless -f $path;
	my $sz = -s _;
	return 0 unless defined $sz && $sz >= $max;
	_rotate_chain($path);
	return 1;
}

sub maybe_check {
	return unless $filename ne '' && -f $filename;
	my $max = _max_bytes();
	return if $max <= 0;

	my $now = time;
	return if $now < ($next_log_check_at // 0);
	$next_log_check_at = $now + _check_interval();

	return unless _rotate_if_oversize($filename);
	_reopen_log($filename);
	print STDERR localtime() . " [defender] log rotated (size limit ", ($main::dataValues{"log_rotate_mb"} // 10), " MB)\n";
	return;
}

sub init {
	$filename = $main::dataValues{"logpath"} // '';
	return unless $filename ne '';

	my $did_rotate = _rotate_if_oversize($filename);

	open STDOUT, '>>', $filename or die "Text log: cannot open $filename: $!\n";
	open STDERR, '>&STDOUT' or die "Text log: cannot dup STDERR: $!\n";

	if ($did_rotate) {
		print STDERR localtime() . " [defender] log rotated at startup (size limit ", ($main::dataValues{"log_rotate_mb"} // 10), " MB)\n";
	}
}

sub shutdown {
	close STDOUT;
}

1;
