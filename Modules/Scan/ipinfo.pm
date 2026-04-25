#
# SPDX-License-Identifier: GPL-2.0-only
# Copyright (c) 2026 NetIRC Defender
#
# NetIRC Defender V3 - network security service
#

package Modules::Scan::ipinfo;

use strict;
use warnings;
use Socket qw(inet_ntoa);

my $lookups_ok    = 0;
my $lookups_fail  = 0;
my $last_err      = '';
my $cache_hits    = 0;

our $CACHE_TTL_SEC      = 300;
our $LOCAL_BURST_LIMIT  = 20;
our $LOCAL_BURST_WINDOW = 60;
our $LOOKUP_TIMEOUT_SEC  = 10;
my @recent_lookup_times = ();
my %ip_cache            = ();

sub _ipinfo_cfg_int {
	my ($key, $default, $min, $max) = @_;
	my $v = $main::dataValues{$key} // '';
	if (!defined $v || $v eq '' || $v !~ /^[0-9]+$/) {
		return $default;
	}
	$v = 0 + $v;
	$v = $min if $v < $min;
	$v = $max if $max > 0 && $v > $max;
	return $v;
}

sub _ipinfo_apply_defender_config {
	$CACHE_TTL_SEC = _ipinfo_cfg_int('ipinfo_cache_ttl_sec', 300, 0, 604800);
	$LOCAL_BURST_LIMIT  = _ipinfo_cfg_int('ipinfo_burst_limit', 20, 1, 1000);
	$LOCAL_BURST_WINDOW = _ipinfo_cfg_int('ipinfo_burst_window_sec', 60, 1, 86400);
	$LOOKUP_TIMEOUT_SEC = _ipinfo_cfg_int('ipinfo_http_timeout_sec', 10, 1, 300);
}

sub _dsp {
	my ($s) = @_;
	return '' unless defined $s;
	$s =~ s/\\(.)/$1/g;
	return $s;
}

sub _cmsg {
	my ($plain, $colored) = @_;
	my $msg = $main::ugly ? $plain : $colored;
	$msg = _ascii_safe($msg);
	main::message($msg);
}

sub _ascii_safe {
	my ($s) = @_;
	return '' unless defined $s;
	$s =~ tr/\x{00C0}\x{00C1}\x{00C2}\x{00C3}\x{00C4}\x{00C5}\x{00E0}\x{00E1}\x{00E2}\x{00E3}\x{00E4}\x{00E5}/AAAAAAAAAAAA/; # A/a variants
	$s =~ tr/\x{00C8}\x{00C9}\x{00CA}\x{00CB}\x{00E8}\x{00E9}\x{00EA}\x{00EB}/EEEEeeee/; # E/e variants
	$s =~ tr/\x{00CC}\x{00CD}\x{00CE}\x{00CF}\x{00EC}\x{00ED}\x{00EE}\x{00EF}/IIIIiiii/; # I/i variants
	$s =~ tr/\x{00D2}\x{00D3}\x{00D4}\x{00D5}\x{00D6}\x{00D8}\x{00F2}\x{00F3}\x{00F4}\x{00F5}\x{00F6}\x{00F8}/OOOOOOoooooo/; # O/o variants
	$s =~ tr/\x{00D9}\x{00DA}\x{00DB}\x{00DC}\x{00F9}\x{00FA}\x{00FB}\x{00FC}/UUUUuuuu/; # U/u variants
	$s =~ tr/\x{00C7}\x{00E7}/Cc/; # C cedilla
	$s =~ tr/\x{00D1}\x{00F1}/Nn/; # N tilde
	$s =~ tr/\x{015E}\x{015F}\x{0218}\x{0219}/SsSs/; # S comma/cedilla (Romanian/Turkish)
	$s =~ tr/\x{0162}\x{0163}\x{021A}\x{021B}/TtTt/; # T comma/cedilla (Romanian/Turkish)
	$s =~ tr/\x{0102}\x{0103}\x{00C2}\x{00E2}/AaAa/; # Romanian A-breve / A-circumflex
	$s =~ tr/\x{00CE}\x{00EE}/Ii/; # Romanian I-circumflex
	$s =~ s/[^\x00-\x7F]/?/g;
	return $s;
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
		"\002[IPINFO]\002 Access denied: IRC operators only ($cmd).",
		"\00305\002[IPINFO]\017 \00304Access denied:\017 \00306IRC operators only (\00302$cmd\00306).\017"
	);
}

sub _is_ipv4 {
	my ($ip) = @_;
	return 0 unless defined $ip;
	return 0 unless $ip =~ /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
	return 0 if grep { $_ > 255 } ($1, $2, $3, $4);
	return 1;
}

sub _is_ipv6 {
	my ($ip) = @_;
	return 0 unless defined $ip && $ip =~ /:/;
	return 0 unless $ip =~ /^[0-9A-Fa-f:]+$/;
	return 1;
}

sub _is_hostname {
	my ($name) = @_;
	return 0 unless defined $name && $name ne '';
	return 0 if $name =~ /\s/;
	return 0 if $name =~ /^\./ || $name =~ /\.$/;
	return 0 unless $name =~ /^[A-Za-z0-9.-]+$/;
	return 0 unless $name =~ /\./;
	return 1;
}

sub _resolve_all_ips_for_host {
	my ($host) = @_;
	my @ips;

	if (defined &Socket::getaddrinfo) {
		my ($err, @res) = Socket::getaddrinfo($host, undef, { socktype => Socket::SOCK_STREAM() });
		if (!$err) {
			while (@res) {
				my $ai = shift @res;
				next unless ref($ai) eq 'HASH';
				my $fam  = $ai->{family};
				my $addr = $ai->{addr};
				next unless defined $fam && defined $addr;
				if ($fam == Socket::AF_INET()) {
					my (undef, $raw) = Socket::sockaddr_in($addr);
					my $ip = inet_ntoa($raw);
					push @ips, $ip if defined $ip && $ip ne '';
					next;
				}
				if (defined &Socket::AF_INET6 && $fam == Socket::AF_INET6()) {
					if (defined &Socket::sockaddr_in6 && defined &Socket::inet_ntop) {
						my (undef, $raw6) = Socket::sockaddr_in6($addr);
						my $ip6 = Socket::inet_ntop(Socket::AF_INET6(), $raw6);
						push @ips, $ip6 if defined $ip6 && $ip6 ne '';
					}
				}
			}
		}
	}

	if (!@ips) {
		my $packed = gethostbyname($host);
		if (defined $packed) {
			my $ip = inet_ntoa($packed);
			push @ips, $ip if defined $ip && $ip ne '';
		}
	}

	my %seen;
	return grep { !$seen{$_}++ } @ips;
}

sub _resolve_input {
	my ($input) = @_;
	return (undef, 'missing target') unless defined $input && $input ne '';

	if (_is_ipv4($input) || _is_ipv6($input)) {
		return ([ { ip => $input, source => $input } ], undef);
	}

	if (_is_hostname($input)) {
		my @ips = _resolve_all_ips_for_host($input);
		return (undef, "DNS resolution failed for $input") unless @ips;
		my @out = map { { ip => $_, source => $input } } @ips;
		return (\@out, undef);
	}

	if (defined &main::gethost) {
		my $uh = eval { main::gethost($input) };
		if (defined $uh && $uh ne '') {
			my (undef, $hostpart) = split(/\@/, $uh, 2);
			$hostpart = $uh unless defined $hostpart && $hostpart ne '';
			if (_is_ipv4($hostpart) || _is_ipv6($hostpart)) {
				return ([ { ip => $hostpart, source => $input } ], undef);
			}
			if (_is_hostname($hostpart)) {
				my @ips = _resolve_all_ips_for_host($hostpart);
				return (undef, "DNS resolution failed for $hostpart (nick: $input)") unless @ips;
				my @out = map { { ip => $_, source => $input } } @ips;
				return (\@out, undef);
			}
			return (undef, "nick $input has unsupported host format: $hostpart");
		}
	}

	return (undef, "invalid target (expected ip/hostname/nick): $input");
}

sub _safe {
	my ($v, $fallback) = @_;
	$fallback = 'N/A' unless defined $fallback;
	return $fallback unless defined $v && $v ne '';
	return $v;
}

sub _bool {
	my ($v) = @_;
	return 'true' if $v;
	return 'false';
}

sub _bool_or_unknown {
	my ($v) = @_;
	return 'unknown' unless defined $v;
	return $v ? 'true' : 'false';
}

sub _prune_cache {
	my $now = time;
	for my $k (keys %ip_cache) {
		my $rec = $ip_cache{$k};
		next unless ref $rec eq 'HASH' && defined $rec->{expire_at};
		delete $ip_cache{$k} if $rec->{expire_at} <= $now;
	}
}

sub _allow_local_lookup {
	my $now = time;
	@recent_lookup_times = grep { ($now - $_) <= $LOCAL_BURST_WINDOW } @recent_lookup_times;
	return 0 if @recent_lookup_times >= $LOCAL_BURST_LIMIT;
	push @recent_lookup_times, $now;
	return 1;
}

sub _http_get_json {
	my ($url) = @_;
	eval { require HTTP::Tiny; 1 } or return (undef, "HTTP::Tiny not available: $@");
	eval { require JSON::PP; 1 } or return (undef, "JSON::PP not available: $@");

	my $ua = HTTP::Tiny->new(
		timeout => $LOOKUP_TIMEOUT_SEC,
		agent   => 'Defender-IPInfo/1.0',
	);
	my $res = $ua->get($url);
	return (undef, "upstream HTTP error $res->{status} from ipinfo.io")
		unless $res->{success};

	my $data = eval { JSON::PP::decode_json($res->{content}) };
	return (undef, "invalid JSON payload: $@") if $@ || ref $data ne 'HASH';
	return ($data, undef);
}

sub _ipinfo_token_state {
	my $raw = $main::dataValues{'ipinfo_token'} // '';
	$raw =~ s/^\s+|\s+$//g;
	if ($raw eq '') {
		return ('missing',
			'ipinfo_token missing or empty in defender.conf — set ipinfo_token= in defender.conf; without it, rate limits are strict and some fields may be missing.');
	}
	if ($raw =~ /[^A-Za-z0-9_-]/ || length($raw) < 8) {
		return ('invalid',
			'ipinfo_token in defender.conf looks invalid (use only A–Z, a–z, 0–9, hyphen, underscore; length at least 8 in defender.conf).');
	}
	return ('ok', '');
}

sub _build_ipinfo_url {
	my ($ip) = @_;
	my $tok = $main::dataValues{'ipinfo_token'} // '';
	$tok =~ s/^\s+|\s+$//g;
	my $url = "https://ipinfo.io/$ip/json";
	$url .= "?token=$tok" if $tok ne '';
	return $url;
}

sub _lookup_ip {
	my ($ip) = @_;

	_prune_cache();
	if (exists $ip_cache{$ip}) {
		my $rec = $ip_cache{$ip};
		if (ref $rec eq 'HASH' && defined $rec->{expire_at} && $rec->{expire_at} > time) {
			$cache_hits++;
			return ($rec->{data}, undef);
		}
	}

	if (!_allow_local_lookup()) {
		return (undef, "local rate limit reached: max $LOCAL_BURST_LIMIT lookups per $LOCAL_BURST_WINDOW seconds");
	}

	my $url = _build_ipinfo_url($ip);
	my ($data, $http_err) = _http_get_json($url);
	return (undef, $http_err) unless defined $data;

	if (defined $data->{error}) {
		my $why = ref($data->{error}) eq 'HASH' ? ($data->{error}{title} // 'request failed') : $data->{error};
		return (undef, "ipinfo error: $why");
	}
	return (undef, 'ipinfo returned no IP data') unless defined $data->{ip} && $data->{ip} ne '';

	$ip_cache{$ip} = {
		expire_at => time + $CACHE_TTL_SEC,
		data      => $data,
	};
	return ($data, undef);
}

sub _handle_ip_cmd {
	my ($nick, $arg) = @_;
	my $target = defined $arg ? $arg : '';
	$target =~ s/^\s+|\s+$//g;

	if ($target eq '') {
		_cmsg(
			"\002[IPINFO]\002 Usage: \002ip <ipv4|ipv6|hostname|nick>\002",
			"\00305\002[IPINFO]\017 \00306Usage:\017 \00302\002ip <ipv4|ipv6|hostname|nick>\017"
		);
		return;
	}

	my ($targets, $resolve_err) = _resolve_input($target);
	if (!defined $targets) {
		_cmsg(
			"\002[IPINFO]\002 $resolve_err",
			"\00305\002[IPINFO]\017 \00304$resolve_err\017"
		);
		return;
	}

	for my $ent (@$targets) {
		my $ip = $ent->{ip};
		my $source = $ent->{source};
		my ($data, $err) = _lookup_ip($ip);
		if (!defined $data) {
			$lookups_fail++;
			$last_err = $err // 'unknown error';
			_cmsg(
				"\002[IPINFO]\002 Lookup failed for \002$target\002 (\002$ip\002): $last_err",
				"\00305\002[IPINFO]\017 \00304Lookup failed\017 \00306for \00302\002$target\017 \00306(\00302\002$ip\017\00306): $last_err\017"
			);
			next;
		}

		$lookups_ok++;
		my $query = _safe($data->{ip}, $ip);
		my $city  = _safe($data->{city});
		my $reg   = _safe($data->{region});
		my $ctry  = _safe($data->{country});
		my ($lat, $lon) = ('N/A', 'N/A');
		if (defined $data->{loc} && $data->{loc} =~ /^([+-]?\d+(?:\.\d+)?),([+-]?\d+(?:\.\d+)?)$/) {
			($lat, $lon) = ($1, $2);
		}
		my $tz    = _safe($data->{timezone});
		my $host  = _safe($data->{hostname});
		my $isp   = _safe($data->{org});
		my $mob   = _bool_or_unknown($data->{is_mobile});
		my $prx   = _bool_or_unknown(
			(ref($data->{anonymous}) eq 'HASH')
				? $data->{anonymous}{is_proxy}
				: undef
		);
		my $subject_plain = ($source ne $ip) ? "$source ($query)" : $query;
		my $subject_col   = ($source ne $ip)
			? "\00302$source\00306 (\00310\002$query\017\00306)"
			: "\00310\002$query\017";
		my @extra_plain;
		my @extra_col;
		if ($mob ne 'unknown') {
			push @extra_plain, "Mobile: $mob";
			push @extra_col, "Mobile: \00302$mob\00306";
		}
		if ($prx ne 'unknown') {
			push @extra_plain, "Proxy: $prx";
			push @extra_col, "Proxy: \00302$prx\017";
		}
		my $extra_plain = @extra_plain ? " ; " . join(" ; ", @extra_plain) : '';
		my $extra_col   = @extra_col   ? " ; " . join(" ; ", @extra_col)   : '';

		_cmsg(
			"$subject_plain is located in $city, $reg, $ctry ($lat, $lon) ; TimeZone: $tz ; Host: $host ; ISP: $isp$extra_plain",
			"\00305\002[IPINFO]\017 $subject_col \00306is located in\017 \00302$city\00306, $reg, $ctry (\00302$lat\00306, \00302$lon\00306) ; TimeZone: \00302$tz\00306 ; Host: \00302$host\00306 ; ISP: \00302$isp\00306$extra_col"
		);
	}
}

sub cmd_help {
	_cmsg(
		"\002[IPINFO]\002 \002ip\002 or \002ip <ipv4|ipv6|hostname|nick>\002 - GeoIP / host summary on the control channel.",
		"\00305\002[IPINFO]\017 \00302ip\017 \00306or\017 \00302ip <host|nick>\017 \00306- GeoIP / host summary.\017"
	);
}

sub handle_privmsg {
	my ($nick, $ident, $host, $chan, $msg) = @_;
	my $chan_d = _dsp($chan);
	return if $chan_d !~ /^\Q$main::mychan\E$/i;

	my $msg_d  = _dsp($msg);
	my $nick_d = _dsp($nick);

	if ($msg_d =~ /^ip(?:\s+(.+?))?\s*$/i) {
		if (!_is_ircop($nick_d)) {
			_deny_ircop_only('ip');
			return;
		}
		my $ok = eval { _handle_ip_cmd($nick_d, $1); 1 };
		if (!$ok) {
			my $err = $@ // 'unknown runtime error';
			$err =~ s/\s+$//;
			$lookups_fail++;
			$last_err = $err;
			_cmsg(
				"\002[IPINFO]\002 Runtime error: $err",
				"\00305\002[IPINFO]\017 \00304Runtime error:\017 \00306$err\017"
			);
		}
		return;
	}
}

sub stats {
	my ($tok_st, $tok_note) = _ipinfo_token_state();
	if ($tok_st ne 'ok') {
		_cmsg(
			"[IPINFO] \002Config:\002 $tok_note",
			"\00305[IPINFO]\017 \00304\002Config:\017 \00306$tok_note\017"
		);
	}
	_cmsg(
		"[IPINFO] Successful/failed lookups: $lookups_ok / $lookups_fail",
		"\00305[IPINFO]\017 \00306Successful/failed lookups:\017 \00302$lookups_ok\017 \00306/\017 \00302$lookups_fail\017"
	);
	_cmsg(
		"[IPINFO] Cache hits: $cache_hits · TTL \002${CACHE_TTL_SEC}\002s · rate \002$LOCAL_BURST_LIMIT\002 / \002${LOCAL_BURST_WINDOW}\002s · HTTP \002${LOOKUP_TIMEOUT_SEC}\002s",
		"\00305[IPINFO]\017 \00306Cache hits:\017 \00302$cache_hits\017 \00306· TTL \00302\002${CACHE_TTL_SEC}\017\002s\00306 · rate \00302\002$LOCAL_BURST_LIMIT\017\002 / \00302\002${LOCAL_BURST_WINDOW}\017\002s\00306 · HTTP \00302\002${LOOKUP_TIMEOUT_SEC}\017\002s\00306\017"
	);
	if ($last_err ne '') {
		_cmsg(
			"[IPINFO] Last error: $last_err",
			"\00305[IPINFO]\017 \00306Last error:\017 \00304$last_err\017"
		);
	}
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
	main::provides("ipinfo");
	_ipinfo_apply_defender_config();
	$lookups_ok   = 0;
	$lookups_fail = 0;
	$last_err     = '';
	$cache_hits   = 0;
	@recent_lookup_times = ();
	%ip_cache = ();
	my ($tok_st, $tok_note) = _ipinfo_token_state();
	if ($tok_st ne 'ok') {
		warn "[ipinfo] $tok_note\n";
	}
}

1;
