#
# SPDX-License-Identifier: GPL-2.0-only
# Copyright (c) 2026 NetIRC Defender
#
# NetIRC Defender V3 - network security service

use warnings;
use IO::Select ();
use Socket ();
use Time::HiRes ();
use constant CC_MSG_BURST_SEC => 1.5;
use constant P10_POLL_WAIT_SEC => 0.20;
use constant MAX_P10_IN_LINE => 8192;
use constant MAX_P10_OUT_LINE => 8192;
use constant LIVE_WHOIS_TIMEOUT_SEC => 5;

sub _dispatch_scan {
	my ($mod, $method, @args) = @_;
	no strict 'refs';
	my $fq = "Modules::Scan::${mod}::${method}";
	return unless defined &{$fq};
	eval { &{$fq}(@args) };
	print $@ if $@;
}

sub _dispatch_verbose_first_hook {
	my ( $oldkilled, $method, @args ) = @_;
	if ( $KILLED eq $oldkilled ) {
		_dispatch_scan( 'verbose', $method, @args );
	}
	for my $mod (@modlist) {
		next if $mod eq 'verbose';
		next if $KILLED ne $oldkilled;
		_dispatch_scan( $mod, $method, @args );
	}
}

sub _dispatch_scan_user_signon {
	my ( $oldkilled, $ident, $host, $srv, $nick, $gecos, $print_always ) = @_;
	my %first = map { $_ => 1 } qw(verbose version);
	for my $mod (@modlist) {
		next unless $first{$mod};
		if ( $KILLED eq $oldkilled ) {
			_dispatch_scan( $mod, 'scan_user', $ident, $host, $srv, $nick, $gecos, $print_always );
		}
	}
	for my $mod (@modlist) {
		next if $first{$mod};
		if ( $KILLED eq $oldkilled ) {
			_dispatch_scan( $mod, 'scan_user', $ident, $host, $srv, $nick, $gecos, $print_always );
		}
	}
}

my %hosts = ();
my %nickhash = ();
my %rnickhash = ();
my %serverids = ();
my %info_channels_seen = ();
my %info_chans_by_server = ();
my %user_chans = ();

my %P10_B64;
{
	my @alph = split //, 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789[]';
	for my $i (0 .. $#alph) {
		$P10_B64{ $alph[$i] } = $i;
	}
}

sub _p10_n_ip_token_to_dotted {
	my ($tok) = @_;
	return undef unless defined $tok && $tok ne '';
	if ($tok =~ /^[A-Za-z0-9\[\]]+\z/) {
		my @ch = split //, $tok;
		return undef if !@ch;
		my $u = $P10_B64{ $ch[0] };
		return undef unless defined $u;
		for my $i (1 .. $#ch) {
			return undef unless defined $P10_B64{ $ch[$i] };
			$u = ($u << 6) + $P10_B64{ $ch[$i] };
		}
		$u &= 0xFFFFFFFF;
		return sprintf '%u.%u.%u.%u',
			($u >> 24) & 0xFF,
			($u >> 16) & 0xFF,
			($u >> 8) & 0xFF,
			$u & 0xFF;
	}
	my $len = length $tok;
	if ($len == 4) {
		return sprintf '%u.%u.%u.%u', unpack('C4', $tok);
	}
	if ($len == 16 && defined &Socket::inet_ntop) {
		my $af6 = eval { Socket::AF_INET6() };
		return Socket::inet_ntop($af6, $tok) if defined $af6;
	}
	return undef;
}

sub _uc_join {
	my ($nick_plain, $chan_plain, $chan_pfx) = @_;
	return unless defined $nick_plain && $nick_plain ne '';
	return unless defined $chan_plain && $chan_plain ne '';
	return unless $chan_plain =~ /^[#&+!]/;
	$chan_pfx //= '';
	my $ln = lc $nick_plain;
	my $lc = lc $chan_plain;
	$user_chans{$ln} ||= {};
	my $disp = $chan_pfx . $chan_plain;
	if ($chan_pfx eq '' && exists $user_chans{$ln}{$lc}) {
		return;
	}
	$user_chans{$ln}{$lc} = $disp;
}

sub _uc_part {
	my ($nick_plain, $chan_plain) = @_;
	return unless defined $nick_plain && $nick_plain ne '';
	return unless defined $chan_plain && $chan_plain ne '';
	my $ln = lc $nick_plain;
	my $lc = lc $chan_plain;
	return unless exists $user_chans{$ln};
	delete $user_chans{$ln}{$lc};
	delete $user_chans{$ln} if !keys %{$user_chans{$ln}};
}

sub _uc_drop_nick {
	my ($nick_plain) = @_;
	return unless defined $nick_plain && $nick_plain ne '';
	delete $user_chans{ lc $nick_plain };
}

sub _uc_nick_change {
	my ($old_plain, $new_plain) = @_;
	return unless defined $old_plain && $old_plain ne '' && defined $new_plain && $new_plain ne '';
	return if lc($old_plain) eq lc($new_plain);
	my $lo = lc $old_plain;
	return unless exists $user_chans{$lo};
	$user_chans{ lc $new_plain } = delete $user_chans{$lo};
}

sub _p10_away_sanitize {
	my ($s) = @_;
	return '' unless defined $s;
	$s =~ s/[\x00-\x1F\x7F]//g;
	$s = substr($s, 0, 400) if length($s) > 400;
	return $s;
}

sub _mark_user_activity {
	my ($nick_plain) = @_;
	return unless defined $nick_plain && $nick_plain ne '';
	my $lc = lc $nick_plain;
	return unless exists $hosts{$lc};
	$hosts{$lc}{last_activity_ts} = time;
}

my $p10_io_select;
my $inbound_batch_count = 0;
my $p10_readbuf = '';

sub _info_canonical_server_label {
	my ($lb) = @_;
	return '(unknown)' unless defined $lb && $lb ne '';
	if ($lb =~ /^\[([A-Za-z0-9\[\]]{2})\]$/) {
		my $sid = $1;
		for my $try ($sid, uc $sid, lc $sid) {
			return $serverids{$try} if exists $serverids{$try} && $serverids{$try} ne '';
		}
	}
	return $lb;
}

sub _srv_disp_from_assigned {
	my ($assigned_id, $intro_prefix) = @_;
	return '' unless defined $assigned_id && $assigned_id ne '';
	my $n = _sid_to_name($assigned_id);
	return $n if $n ne '';
	if (defined $intro_prefix && $intro_prefix ne '') {
		my $via = _sid_to_name($intro_prefix);
		return $via if $via ne '';
	}
	my $s2 = substr($assigned_id, 0, 2);
	return $s2 if length($s2) == 2;
	return '';
}

sub _p10_numeric_for_plain_lc {
	my ($lc) = @_;
	return undef unless defined $lc && $lc ne '';
	my $tok = $rnickhash{$lc};
	return $tok if defined $tok && length($tok) >= 2;
	for my $t (keys %nickhash) {
		next unless defined $nickhash{$t} && $nickhash{$t} ne '';
		return $t if lc( $nickhash{$t} ) eq $lc;
	}
	return undef;
}

sub _info_uplink_label {
	my ( $joining_nick_plain, $p10_numeric_token ) = @_;
	my $k = ( defined $joining_nick_plain && $joining_nick_plain ne '' ) ? lc($joining_nick_plain) : '';

	my $tok;
	if ( defined $p10_numeric_token && $p10_numeric_token ne '' && length($p10_numeric_token) >= 2 ) {
		$tok = $p10_numeric_token;
	}
	elsif ( $k ne '' ) {
		$tok = _p10_numeric_for_plain_lc($k);
	}
	else {
		$tok = undef;
	}

	if ( $k ne '' && defined $tok && length($tok) >= 2 ) {
		my $n = _sid_to_name($tok);
		return $n if $n ne '';
		if ( exists $hosts{$k} && defined $hosts{$k}{p10_intro} && $hosts{$k}{p10_intro} ne '' ) {
			my $via = _sid_to_name( $hosts{$k}{p10_intro} );
			return $via if $via ne '';
		}
		if ( exists $hosts{$k} && defined $hosts{$k}{server} && $hosts{$k}{server} ne '' ) {
			my $s = $hosts{$k}{server};
			return $s if length($s) > 2 || $s =~ /\./;
			if ( $s =~ /^[A-Za-z0-9\[\]]{2}$/ ) {
				my $sn = _sid_to_name($s);
				return $sn if $sn ne '';
				return '[' . $s . ']';
			}
		}
		return '[' . substr( $tok, 0, 2 ) . ']';
	}

	if ( $k ne '' ) {
		if ( exists $hosts{$k} && defined $hosts{$k}{p10_intro} && $hosts{$k}{p10_intro} ne '' ) {
			my $via = _sid_to_name( $hosts{$k}{p10_intro} );
			return $via if $via ne '';
		}
		if ( exists $hosts{$k} && defined $hosts{$k}{server} && $hosts{$k}{server} ne '' ) {
			my $s = $hosts{$k}{server};
			return $s if length($s) > 2 || $s =~ /\./;
			if ( $s =~ /^[A-Za-z0-9\[\]]{2}$/ ) {
				my $sn = _sid_to_name($s);
				return $sn if $sn ne '';
				return '[' . $s . ']';
			}
		}
	}

	if ( defined $tok && length($tok) >= 2 ) {
		my $n = _sid_to_name($tok);
		return $n if $n ne '';
		return '[' . substr( $tok, 0, 2 ) . ']';
	}
	return '(unknown)';
}

sub _info_note_channel {
	my ($chan_plain, $joining_nick_plain, $p10_numeric_token) = @_;
	return unless defined $chan_plain;
	$chan_plain =~ s/^\s+|\s+$|\r//g;
	return if $chan_plain eq '' || $chan_plain =~ /\s/;
	my $lc = lc($chan_plain);
	$info_channels_seen{$lc} = 1;
	my $srv = _info_uplink_label($joining_nick_plain // '', $p10_numeric_token);
	$info_chans_by_server{$srv}{$lc} = 1;
}

sub _p10_trailing_param {
	my ($buffer) = @_;
	return '' unless defined $buffer;
	chomp $buffer;
	$buffer =~ s/\r$//;
	return '' if $buffer eq '';
	if ($buffer =~ /^(.+)\s:([^\r\n]*)$/) {
		return $2;
	}
	return '';
}

sub _kill_source_display {
	my ($tok) = @_;
	return '' unless defined $tok && $tok ne '';
	my $nick = $nickhash{$tok};
	return $nick if defined $nick && $nick ne '';
	my $srv = _sid_to_name($tok);
	return $srv if $srv ne '';
	return $tok;
}

sub _sid_to_name {
	my ($id) = @_;
	return '' unless defined $id && $id ne '';
	if (exists $serverids{$id} && $serverids{$id} ne '') {
		return $serverids{$id};
	}
	return '' if length($id) < 2;
	my $s2 = substr($id, 0, 2);
	for my $try ($s2, uc $s2, lc $s2) {
		return $serverids{$try} if exists $serverids{$try} && $serverids{$try} ne '';
	}
	return '';
}

sub _expand_mode_param_nicks {
	my ($s) = @_;
	return $s unless defined $s && $s ne '';
	return join(' ', map {
		(defined $nickhash{$_} && $nickhash{$_} ne '') ? $nickhash{$_} : $_
	} split /\s+/, $s);
}

sub _fmt_idle_human {
	my ($sec) = @_;
	return 'n/a' unless defined $sec && $sec =~ /^\d+$/;
	$sec = 0 + $sec;
	return '0s' if $sec <= 0;
	my $d = int($sec / 86400); $sec %= 86400;
	my $h = int($sec / 3600);  $sec %= 3600;
	my $m = int($sec / 60);    $sec %= 60;
	my @p;
	push @p, "${d}d" if $d;
	push @p, "${h}h" if $h;
	push @p, "${m}m" if $m;
	push @p, "${sec}s" if $sec || !@p;
	return join ' ', @p;
}

sub _join_part_server_label {
	my ($plain_nick) = @_;
	return '' unless defined $plain_nick && $plain_nick ne '';
	my $tok = $rnickhash{lc($plain_nick)};
	return '' unless defined $tok && $tok ne '';
	my $name = _sid_to_name($tok);
	my $disp = ($name ne '') ? $name : substr($tok, 0, 2);
	return quotemeta($disp);
}

sub _register_server_numeric {
	my ($hostname, $payload) = @_;
	return unless defined $hostname && $hostname ne '' && defined $payload;
	my $njsid;
	my $map = sub {
		my ($tok) = @_;
		return unless defined $tok && $tok ne '';
		return if $tok =~ /^\+/;
		return if $tok =~ /^\d+$/;
		return unless $tok =~ /^[A-Za-z0-9\[\]]{2,20}$/;
		my $s2 = substr($tok, 0, 2);
		$serverids{$s2} = $hostname;
		$serverids{$tok} = $hostname if length($tok) > 2;
		$njsid //= $s2;
	};
	my @f = split(/\s+/, $payload);
	if (@f >= 6 && $f[4] =~ /^J\d+/i && defined $f[5] && $f[5] !~ /^\+/) {
		$map->($f[5]);
	}
	for my $i (0 .. $#f) {
		if (defined $f[$i] && $f[$i] =~ /^J\d+/i && defined $f[$i + 1]) {
			$map->($f[$i + 1]);
			last;
		}
	}
	for my $i (0 .. $#f) {
		if (defined $f[$i] && $f[$i] =~ /^P\d+/i && defined $f[$i + 1]) {
			$map->($f[$i + 1]);
			last;
		}
	}
	while ($payload =~ /(?:^|\s)(J\d{1,3})([A-Za-z0-9\[\]]{2,20})(?=\s|$|\+)/ig) {
		$map->($2);
	}
	for my $tok (@f) {
		next unless defined $tok;
		next if $tok =~ /^\+/;
		next if $tok =~ /^\d+$/;
		next unless $tok =~ /^[A-Za-z0-9\[\]]{5,6}$/o;
		$map->($tok);
	}
	return $njsid;
}

sub _refresh_hosts_for_sid {
	my ($sid2, $hostname) = @_;
	return unless defined $sid2 && $sid2 ne '' && length($sid2) == 2;
	return unless defined $hostname && $hostname ne '';
	for my $lc (keys %rnickhash) {
		my $tok = $rnickhash{$lc};
		next unless defined $tok && length($tok) >= 2;
		next unless substr($tok, 0, 2) eq $sid2;
		next unless exists $hosts{$lc};
		$hosts{$lc}{server} = $hostname;
	}
}

my $acknowledged = 0;
my $mychants = 0;
my %live_whois_pending;

my $servnumeric = $numeric;
my $parentserver = $numeric;

our $GLINE_STATS_INFLIGHT = 0;

sub link_init
{
        if (!main::depends("core-v1")) {
                print "This module requires NetIRC Defender with the core link API (core-v1).\n";
                exit(0);
        }
        main::provides("server","p10-server","native-gline","encoded");
	if ($numeric !~ /^[][A-Za-z0-9]{2}$/) {
		print "\n\nYour server numeric doesn't look quite right.\n";
		print "Edit your configuration again, and set your server\n";
		print "to an alphanumeric value of two characters in length\n";
		print "for example \"Ac\" or \"0t\".\n\n";
		exit(0);
	}
}

sub rawirc
{
	my $out = $_[0];
	$out = '' unless defined $out;
	$out =~ s/[\x00\r\n]//g;
	if (length($out) > MAX_P10_OUT_LINE) {
		$out = substr($out, 0, MAX_P10_OUT_LINE);
	}
	$out .= "\r\n";
	syswrite(SH, $out, length($out));
	print ">> $out\n" if $debug;
}

sub bot_numnick { return $servnumeric . 'AAA'; }


sub privmsg
{
	my $nick = $_[0];
	if ($nick !~ /^(#|&).+/) {
		$nick = $rnickhash{lc($nick)};
	}
	my $line = $servnumeric."AAA P $nick :$_[1]";
	&rawirc($line);
}


sub notice
{
	my $nick = $_[0];
	if ($nick !~ /^(#|&).+/) {
		$nick = $rnickhash{lc($nick)};
	}
	my $msg = $_[1];
	my $line = $servnumeric."AAA O $nick :$msg";
	&rawirc($line);
}

my $cc_prev_out_time;
my $inbound_dispatch_active = 0;

sub _control_channel_line_delay_ms {
	my $k = 'control_channel_line_delay_ms';
	my $v = $main::dataValues{$k} // '';
	if (defined $v && $v ne '' && $v =~ /^[0-9]+$/) {
		my $ms = 0 + $v;
		$ms = 0   if $ms < 0;
		$ms = 5000 if $ms > 5000;
		return $ms;
	}
	return 0;
}

sub _link_has_pending_input {
	my $fd = fileno(SH);
	return 0 unless defined $fd && $fd >= 0;
	my $rin = '';
	vec($rin, $fd, 1) = 1;
	my $n = select($rin, undef, undef, 0);
	return (defined $n && $n > 0) ? 1 : 0;
}

sub link_input_pending {
	return _link_has_pending_input() ? 1 : 0;
}

sub link_dispatch_batch_count {
	return $inbound_batch_count // 0;
}

sub _p10_buffer_has_line {
	return (index($p10_readbuf, "\n") >= 0) ? 1 : 0;
}

sub _p10_extract_line {
	my $idx = index($p10_readbuf, "\n");
	return undef if $idx < 0;
	my $line = substr($p10_readbuf, 0, $idx + 1, '');
	return $line;
}

sub _p10_next_line_nonblocking {
	my $line = _p10_extract_line();
	return $line if defined $line;
	return undef unless _link_has_pending_input();
	my $chunk = '';
	my $n = sysread(SH, $chunk, 8192);
	if (!defined $n) {
		return undef if $!{EAGAIN} || $!{EWOULDBLOCK} || $!{EINTR};
		return '__P10_EOF__';
	}
	return '__P10_EOF__' if $n == 0;
	$p10_readbuf .= $chunk;
	if (length($p10_readbuf) > (MAX_P10_IN_LINE * 8) && index($p10_readbuf, "\n") < 0) {
		$p10_readbuf = '';
		return undef;
	}
	return _p10_extract_line();
}

sub _pacing_wait_if_tight_burst {
	my $d_ms = _control_channel_line_delay_ms();
	if ($d_ms > 0 && defined $cc_prev_out_time) {
		my $age = Time::HiRes::time() - $cc_prev_out_time;
		if ($age < CC_MSG_BURST_SEC) {
			return if _link_has_pending_input();
			my $s = $d_ms / 1000.0;
			select(undef, undef, undef, $s) if $s > 0;
		}
	}
}

sub _mark_pacing_outbound_sent {
	$cc_prev_out_time = Time::HiRes::time();
}

sub _is_latency_critical_console_line {
	my ($line) = @_;
	return 0 unless defined $line && $line ne '';
	my $plain = $line;
	$plain =~ s/\x03(?:\d{1,2}(?:,\d{1,2})?)?//g;
	$plain =~ s/[\x02\x0F\x16\x1F]//g;
	$plain =~ s/^\s+|\s+$//g;
	return ($plain =~ /^Signed\s+(?:on|off)\s*:/i) ? 1 : 0;
}

sub message
{
	my $line = shift;
	my $is_critical = _is_latency_critical_console_line($line);
	_pacing_wait_if_tight_burst() if !$is_critical;
	$line = $servnumeric."AAA P $mychan :$line";
	&rawirc($line);
	_mark_pacing_outbound_sent();
}

sub globops
{
	my $msg = shift;
	_pacing_wait_if_tight_burst();
	&rawirc("$servnumeric WA :$msg");
	_mark_pacing_outbound_sent();
}

sub message_to
{
	my ($dest,$line) = @_;
	$dest = $rnickhash{lc($dest)};
	$line = $servnumeric."AAA P $dest :$line";
	&rawirc($line);
}

sub mode
{
	my ($dest,$line) = @_;
	$line = $servnumeric." M $dest :$line";
	&rawirc($line);
}

sub service_join
{
	my ($chan) = @_;
	return if $chan !~ /^[#&]/;
	my $t = time;
	&rawirc("$servnumeric AAA J $chan $t");
}

sub service_part
{
	my ($chan) = @_;
	return if $chan !~ /^[#&]/;
	&rawirc("$servnumeric AAA L $chan");
}

sub request_live_whois
{
	my ($requester_nick, $target_nick, $tag) = @_;
	return 0 unless defined $target_nick && $target_nick ne '';
	my $src = bot_numnick();
	return 0 unless defined $src && $src ne '';
	$tag = uc($tag // 'WHOIS');
	$tag = 'WHOIS' unless $tag =~ /^(WHOIS|SEEN)$/;
	my $dst = $rnickhash{lc($target_nick)} // $target_nick;
	$live_whois_pending{lc($target_nick)} = {
		requester => (defined $requester_nick ? $requester_nick : ''),
		ts        => time,
		target    => $target_nick,
		tag       => $tag,
		away_seen => 0,
	};
	&rawirc("$src W $dst :$target_nick");
	return 1;
}


sub killuser
{
	my ($nick,$reason) = @_;
	my ($host) = main::gethost($nick);
	if (main::depends("exempt") && Modules::Scan::exempt::hasexempt($host)) {
		&message("\002[EXEMPT]\002 Rejected killuser() for $nick for $reason");
        } else {
		$nick = $rnickhash{lc($nick)};
		&rawirc($servnumeric."AAA D $nick :$botnick ($reason)");
		main::register_defender_removal();
	}
}

sub gline
{
	my ($hostname,$duration,$reason) = @_;
	if (main::depends("exempt") && Modules::Scan::exempt::hasexempt($hostname)) {
		&message("\002[EXEMPT]\002 Rejected gline() for $hostname for $reason");
        } else {
		my $now = time;
		my $expire = $duration + $now + 20;
		&rawirc("$servnumeric GL * +$hostname $expire $now 0 :$reason");
		main::register_defender_removal();
	}
}

sub ungline
{
	my ($hostname) = @_;
	my $now = time;
	&rawirc("$servnumeric GL * -$hostname $now $now 0 :Removed by NetIRC Defender");
}

sub gethost
{
	my ($nick) = @_;
	return $hosts{lc($nick)}{host};
}

sub client_link_info
{
	my ($nick) = @_;
	return undef unless defined $nick && $nick ne '';
	my $lc = lc $nick;
	return undef unless exists $hosts{$lc};
	my $uh = $hosts{$lc}{host};
	return undef unless defined $uh && $uh ne '';

	my $tok  = $rnickhash{$lc};
	my $disp = (defined $tok && $tok ne '' && defined $nickhash{$tok} && $nickhash{$tok} ne '')
		? $nickhash{$tok}
		: $nick;

	my $chref = $user_chans{$lc};
	my @chans;
	if ($chref && ref $chref eq 'HASH') {
		@chans = sort { lc($a) cmp lc($b) } values %$chref;
	}

	my $intro_raw = $hosts{$lc}{p10_intro} // '';
	my $srv_plain = $hosts{$lc}{server}    // '';
	my $intro_disp = '';
	if ($intro_raw ne '') {
		my $via = _sid_to_name($intro_raw);
		if ($via ne '' && $srv_plain ne '' && lc($via) eq lc($srv_plain)) {
			$intro_disp = '';
		} elsif ($via ne '') {
			$intro_disp = ($via ne $intro_raw) ? "$via ($intro_raw)" : $via;
		} else {
			$intro_disp = $intro_raw;
		}
	}

	my $last_act = $hosts{$lc}{last_activity_ts};
	my $idle_sec;
	if (defined $last_act && $last_act =~ /^\d+$/) {
		$idle_sec = time - (0 + $last_act);
		$idle_sec = 0 if $idle_sec < 0;
	}

	return {
		nick               => $disp,
		userhost           => $uh,
		server             => $srv_plain,
		numnick            => ($tok // ''),
		isoper             => (($hosts{$lc}{isoper}    // 0) == 1) ? 1 : 0,
		isservice          => (($hosts{$lc}{isservice} // 0) == 1) ? 1 : 0,
		p10_intro          => $intro_raw,
		p10_intro_display  => $intro_disp,
		gecos              => ($hosts{$lc}{gecos}     // ''),
		client_ip          => ($hosts{$lc}{client_ip}  // ''),
		account            => ($hosts{$lc}{account}    // ''),
		signon_ts          => ($hosts{$lc}{signon_ts}  // undef),
		last_activity_ts   => (defined $last_act ? (0 + $last_act) : undef),
		idle_sec           => $idle_sec,
		away               => (($hosts{$lc}{away} // 0) == 1) ? 1 : 0,
		away_msg           => ($hosts{$lc}{away_msg}  // ''),
		channels           => \@chans,
	};
}

sub getmatching
{
	my @results = ();
	my ($re) = @_;
	foreach my $mask (keys %hosts)
	{
		if (defined($hosts{$mask}{host}))
		{
			if ($hosts{$mask}{host} =~ /$re/i)
			{
				push @results, $mask;
			}
		}
	}
	return @results;
}

sub network_info_snapshot {
	my %uniq_servers;
	for my $k (keys %serverids) {
		next unless length($k) == 2;
		my $n = $serverids{$k};
		next unless defined $n && $n ne '';
		$uniq_servers{$n} = 1;
	}
	my @servers = sort keys %uniq_servers;
	my @users   = sort keys %hosts;
	my @chans   = sort keys %info_channels_seen;
	my %by_srv;
	for my $ln (keys %hosts) {
		my $tok = $rnickhash{$ln};
		my $srv = _info_uplink_label($ln, $tok);
		my $can = _info_canonical_server_label($srv);
		$by_srv{$can}++;
	}
	my %users_by_srv_merged;
	$users_by_srv_merged{$_} = 0 for @servers;
	for my $k (keys %by_srv) {
		$users_by_srv_merged{$k} = $by_srv{$k};
	}
	my @users_by_server = map { [ $_, $users_by_srv_merged{$_} ] }
		sort {
			$users_by_srv_merged{$b} <=> $users_by_srv_merged{$a} || $a cmp $b
		} keys %users_by_srv_merged;
	my %chans_merged;
	for my $srv (keys %info_chans_by_server) {
		my $can = _info_canonical_server_label($srv);
		for my $c (keys %{ $info_chans_by_server{$srv} }) {
			$chans_merged{$can}{$c} = 1;
		}
	}
	my @chans_by_server = map { [ $_, scalar keys %{ $chans_merged{$_} } ] }
		sort {
			(scalar keys %{ $chans_merged{$b} }) <=> (scalar keys %{ $chans_merged{$a} })
			|| $a cmp $b
		} keys %chans_merged;
	my $def_srv = ( defined $servername && $servername ne '' ) ? $servername : '';
	return {
		servers           => \@servers,
		users             => \@users,
		chans             => \@chans,
		users_by_server   => \@users_by_server,
		chans_by_server   => \@chans_by_server,
		defender_server   => $def_srv,
	};
}

sub connect {
	$CONNECT_TYPE = "Server";

	$acknowledged = 0;

	print ("[P10] Creating socket...\n");
	socket(SH, PF_INET, SOCK_STREAM, getprotobyname('tcp')) || print "socket() failed: $!\n";
	if (defined($main::dataValues{"bind"}))
	{
		print "[P10] Bound to ip address: " . $main::dataValues{"bind"} . "\n";
		bind(SH, sockaddr_in(0, inet_aton($main::dataValues{"bind"})));
	} else {
		bind(SH, sockaddr_in(0, INADDR_ANY));
	}

	print ("[P10] Connecting to $server\:$port...\n");
	my $sin = sockaddr_in ($port,inet_aton($server));
	connect(SH,$sin) || print "[P10] Could not connect to server: $!\n";
	$p10_readbuf = '';

	print ("[P10] Logging in...\n");
	&rawirc("PASS :" . $password . "");
	my $now = time;
	&rawirc("SERVER $servername 1 $now $now J10 " . $servnumeric . "H]] +s :$serverdesc");
	$NETJOIN = 1;
}

sub reconnect
{
	$p10_io_select = undef;
	$p10_readbuf = '';
	close SH;
	&connect;
}

my $njtime = time+20;

sub checkmodes
{
	my ($nick,$modes) = @_;
	if ($modes =~ /^\+.*(o|A).*$/) 
	{
		$hosts{lc($nick)}{isoper} = 1;
	}
	elsif ($modes =~ /^-.*(o|A).*$/)
	{
		$hosts{lc($nick)}{isoper} = 0;
	}
	if ($modes =~ /^\+.*k.*$/)
	{
		$hosts{lc($nick)}{isservice} = 1;
	}
	elsif ($modes =~ /^-.*k.*$/)
	{
		$hosts{lc($nick)}{isservice} = 0;
	}
}

sub _modes_is_oper {
	my ($modes) = @_;
	return 0 unless defined $modes && $modes ne '';
	return ($modes =~ /(o|A)/) ? 1 : 0;
}

sub _modes_is_service {
	my ($modes) = @_;
	return 0 unless defined $modes && $modes ne '';
	return ($modes =~ /k/) ? 1 : 0;
}

sub isoper
{
	my ($nick) = @_;
	return ($hosts{lc($nick)}{isoper} == 1);
}

sub isservice
{
	my ($nick) = @_;
	return 0 unless defined $nick && $nick ne '';
	return (($hosts{lc($nick)}{isservice} // 0) == 1);
}

sub idle_timers {
	eval { main::maybe_flush_persistent_counters() };
	print "[idle_timers] maybe_flush_persistent_counters: $@" if $@;
	if (%live_whois_pending) {
		my $now = time;
		for my $k (keys %live_whois_pending) {
			my $r = $live_whois_pending{$k};
			next unless ref($r) eq 'HASH';
			my $ts = $r->{ts};
			next unless defined $ts && $ts =~ /^\d+$/;
			next if ($now - $ts) < LIVE_WHOIS_TIMEOUT_SEC;
			my $wn = $r->{target} // $k;
			my $tag = $r->{tag} // 'WHOIS';
			if ($tag eq 'WHOIS') {
				main::message("\00305\002[$tag]\017 \00306Live idle for\017 \00302\002$wn\017\00306:\017 \00304\002n/a\017 \00306(IRCd timeout)\017");
			}
			delete $live_whois_pending{$k};
		}
	}
	if (($::logger // '') eq 'Text') {
		eval { Modules::Log::Text::maybe_check() };
		print $@ if $@;
	}
	if ($INC{'Modules/Scan/flood.pm'}) {
		eval { Modules::Scan::flood::handle_expire() };
		print "[idle_timers] flood::handle_expire: $@" if $@;
	}
	if (defined &Modules::Scan::killchan::handle_expire) {
		eval { Modules::Scan::killchan::handle_expire() };
		print "[idle_timers] killchan::handle_expire: $@" if $@;
	}
}

sub poll {

	idle_timers();

	if (!$p10_io_select) {
		my $fd = fileno(SH);
		if (defined $fd && $fd >= 0) {
			$p10_io_select = eval { IO::Select->new(\*SH) };
			if (!$p10_io_select) {
				print "[P10] IO::Select->new(SH) failed: $@\n";
			}
		}
	}

	my $fd_sh = fileno(SH);
	my $have_vec = (defined $fd_sh && $fd_sh >= 0);

	if (!_p10_buffer_has_line()) {
		if ($p10_io_select) {
			my @ready = $p10_io_select->can_read(P10_POLL_WAIT_SEC);
			if (!@ready) {
				return 1;
			}
		} elsif ($have_vec) {
			my $rin = '';
			vec($rin, $fd_sh, 1) = 1;
			my $n = select($rin, undef, undef, P10_POLL_WAIT_SEC);
			return 0 unless defined $n;
			if ($n == 0) {
				return 1;
			}
		}
	}

	$inbound_batch_count = 0;
	while (1) {
		my $next = _p10_next_line_nonblocking();
		last unless defined $next;
		return 0 if $next eq '__P10_EOF__';
		$buffer = $next;
		if (length($buffer) > MAX_P10_IN_LINE) {
			print "[P10] Dropped oversized input line (" . length($buffer) . " bytes).\n";
			next;
		}
		chomp($buffer);
		$buffer =~ s/\r$//;
		$inbound_dispatch_active = 1;
		$inbound_batch_count++;
		my $oldkilled = $KILLED;

		idle_timers();

		print "<< $buffer\n" if $debug;
	        if ($buffer =~ /^(.+)\sK\s(.+?)\s(.+?)\s:(.+?)$/i)
	        {
				if ($3 eq ($servnumeric."AAA"))
				{
					my $now = time;
	                	        &rawirc($servnumeric."AAA J $mychan $now");
					&rawirc($servnumeric."AAA M $mychan +o " . $servnumeric . "AAA");
				}
	        }

		elsif ($buffer =~ /^(ERROR|Y)\s:(.+?)$/)
		{
			print "[P10] ERROR received from ircd: $2\n";
			print "[P10] You might need to check your C/N lines or link block on the ircd, or port number you are using.\n";
			exit(0);
		}

		elsif ($buffer =~ /^(.+?)\sREHASH\s(.+?)$/)
		{
			my $nick = $nickhash{$1};
			if ($2 eq $servnumeric)
			{
				&globops("Rehashing at the request of \002$nick\002");
				&rehash;
				foreach my $line (@rehash_data) 
				{
					notice($nick,$line);
				}
			}
		}

		elsif ($buffer =~ /^(.+?)\sN\s(.+?)\s[0-9]+$/)
		{
			my $token = $1;
			my $newnick_plain = $2;
			my $oldnick_plain = $nickhash{$token};
			if (defined $oldnick_plain && $oldnick_plain ne $newnick_plain) {
				$nickhash{$token} = $newnick_plain;
				delete $rnickhash{lc($oldnick_plain)};
				$rnickhash{lc($newnick_plain)} = $token;
				if (exists $hosts{lc($oldnick_plain)}) {
					$hosts{lc($newnick_plain)} = delete $hosts{lc($oldnick_plain)};
				}
				_uc_nick_change($oldnick_plain, $newnick_plain);
			} elsif (!defined $oldnick_plain) {
				$nickhash{$token} = $newnick_plain;
				$rnickhash{lc($newnick_plain)} = $token;
			}
			_dispatch_verbose_first_hook( $oldkilled, 'handle_nick', $oldnick_plain // '', $newnick_plain );
			_mark_user_activity($newnick_plain);
		}

		elsif ($buffer =~ /^.+?\sN\s(.+?)\s\d+\s\d+\s(.+?)\s(.+?)\s(.+?)\s(.+?)\s(.+?)\s:(.+?)$/)
		{
			my @regarray = split(/\s+/, $buffer);
			my $rindex;
			my $index = 0;
			foreach my $element(@regarray) 
			{
				if ($index eq 2) 
				{
					$thenick = $element;
				}
				elsif ($index eq 5)
				{
					$theident = $element;
				}
				elsif ($index eq 6) 
				{
					$thehost = $element;
				}
				elsif ($index eq 7) 
				{
					$themodes = $element;
				}
				else 
				{
					if ($element =~ /^:/) 
					{
						$rindex = $index;
						$rindex--;
						last;
					}
				}
				$index++;
			}
			next unless defined $rindex && $rindex >= 2;
			my $assigned_id = $regarray[$rindex--];
			my $base64 = $regarray[$rindex--];
			my $thegecos = _p10_trailing_param($buffer);
			my $clip = _p10_n_ip_token_to_dotted($base64);
			my $intro_prefix = (defined $regarray[0] && $regarray[0] ne 'N') ? $regarray[0] : '';
			my $theserver_id = substr($assigned_id,0,2);
			my $srv_disp = _srv_disp_from_assigned($assigned_id, $intro_prefix);
			$srv_disp = $theserver_id if $srv_disp eq '';
			main::register_signon() if !$NETJOIN;
			delete $hosts{lc($thenick)}{account};
			$hosts{lc($thenick)}{host} = "$theident\@$thehost";
			$hosts{lc($thenick)}{isoper} = _modes_is_oper($themodes);
			$hosts{lc($thenick)}{isservice} = _modes_is_service($themodes);
			$hosts{lc($thenick)}{server} = $srv_disp;
			$hosts{lc($thenick)}{p10_intro} = $intro_prefix if $intro_prefix ne '';
			$hosts{lc($thenick)}{gecos} = (defined $thegecos && $thegecos ne '') ? $thegecos : '';
			if (defined $regarray[4] && $regarray[4] =~ /^\d+$/) {
				$hosts{lc($thenick)}{signon_ts} = 0 + $regarray[4];
			} else {
				delete $hosts{lc($thenick)}{signon_ts};
			}
			if (defined $clip && $clip ne '') {
				$hosts{lc($thenick)}{client_ip} = $clip;
			} else {
				delete $hosts{lc($thenick)}{client_ip};
			}
			$hosts{lc($thenick)}{away} = 0;
			delete $hosts{lc($thenick)}{away_msg};
			$hosts{lc($thenick)}{last_activity_ts} = time;
			$nickhash{$assigned_id} = $thenick;
			$rnickhash{lc($thenick)} = $assigned_id;
			if ($debug) {
				my $rep = ("Assigned ".$assigned_id." in hash -> ".
					  (defined $thenick?$thenick:"")."!".
					  (defined $theident?$theident:"")."\@".
					  (defined $thehost?$thehost:"")." :".
					  (defined $thegecos?$thegecos:"").", on server ".
					  $srv_disp."\(SID=".
					  (defined $theserver_id?$theserver_id:"")."\)\n");
				print $rep;
			}
			_dispatch_scan_user_signon(
				$oldkilled,
				(defined $theident ? $theident : ""),
				(defined $thehost ? $thehost : ""),
				$srv_disp,
				(defined $thenick ? $thenick : ""),
				(defined $thegecos ? $thegecos : ""),
				0
			);
		}

		elsif ($buffer =~ /^(.+?)\sN\s(.+?)\s\d+\s\d+\s(.+?)\s(.+?)\s(.+?)\s(.+?)\s:(.+?)$/)
		{
			my $thenick = $2;
			my $theident = $3;
			my $thehost = $4;
			my $assigned_id = $6;
			my $thegecos = _p10_trailing_param($buffer);
			my $clip = _p10_n_ip_token_to_dotted($5);
			my $intro_prefix = $1;
			my $theserver_id = substr($assigned_id, 0, 2);
			my $srv_disp = _srv_disp_from_assigned($assigned_id, $intro_prefix);
			$srv_disp = $theserver_id if $srv_disp eq '';
			main::register_signon() if !$NETJOIN;
			delete $hosts{lc($thenick)}{account};
			$hosts{lc($thenick)}{host} = "$theident\@$thehost";
			$hosts{lc($thenick)}{isoper} = 0;
			$hosts{lc($thenick)}{isservice} = 0;
			$hosts{lc($thenick)}{server} = $srv_disp;
			$hosts{lc($thenick)}{p10_intro} = $intro_prefix if defined $intro_prefix && $intro_prefix ne '';
			$hosts{lc($thenick)}{gecos} = (defined $thegecos && $thegecos ne '') ? $thegecos : '';
			my @rN = split(/\s+/, $buffer);
			if (defined $rN[4] && $rN[4] =~ /^\d+$/) {
				$hosts{lc($thenick)}{signon_ts} = 0 + $rN[4];
			} else {
				delete $hosts{lc($thenick)}{signon_ts};
			}
			if (defined $clip && $clip ne '') {
				$hosts{lc($thenick)}{client_ip} = $clip;
			} else {
				delete $hosts{lc($thenick)}{client_ip};
			}
			$hosts{lc($thenick)}{away} = 0;
			delete $hosts{lc($thenick)}{away_msg};
			$hosts{lc($thenick)}{last_activity_ts} = time;
			$nickhash{$assigned_id} = $thenick;
			$rnickhash{lc($thenick)} = $assigned_id;
			if ($debug) {
				my $rep = ("Assigned ".$assigned_id." in hash -> ".
					  (defined $thenick?$thenick:"")."!".
					  (defined $theident?$theident:"")."\@".
					  (defined $thehost?$thehost:"")." :".
					  (defined $thegecos?$thegecos:"").", on server ".
					  $srv_disp."\(SID=".
					  (defined $theserver_id?$theserver_id:"")."\)\n");
				print $rep;
			}
			$thegecos = quotemeta($thegecos);
			$thenick = quotemeta($thenick);
			_dispatch_scan_user_signon(
				$oldkilled,
				(defined $theident ? $theident : ""),
				(defined $thehost ? $thehost : ""),
				$srv_disp,
				(defined $thenick ? $thenick : ""),
				(defined $thegecos ? $thegecos : ""),
				0
			);
		}

		elsif ($buffer =~ /^(.+?)\sM\s(.+)$/)
		{
			my $src_tok = $1;
			my $tail = $2;
			$tail =~ s/^\s+|\s+$//g;
			my ($thetarget, $params) = ('', '');
			if ($tail =~ /^(\S+)(?:\s+(.*))?$/) {
				$thetarget = $1;
				$params = defined $2 ? $2 : '';
			}
			$params =~ s/^://;
			$params = _expand_mode_param_nicks($params);
			my $mode_source = $nickhash{$src_tok};
			if (!defined $mode_source || $mode_source eq '') {
				$mode_source = _sid_to_name($src_tok);
			}
			if (!defined $mode_source || $mode_source eq '') {
				$mode_source = $src_tok;
			}
			if ($thetarget !~ /^[#&+!]/ && defined $nickhash{$thetarget}) {
				$thetarget = $nickhash{$thetarget};
			}
			if (defined $thetarget && $thetarget ne '' && $thetarget !~ /^[#&+!]/) {
				&checkmodes($thetarget,$params);
			}
			$mode_source = quotemeta($mode_source);
			$thetarget = quotemeta($thetarget);
			$params = quotemeta($params);
			foreach my $mod (@modlist) 
			{
				if ($KILLED eq $oldkilled)
				{
					_dispatch_scan($mod, 'handle_mode',
						$mode_source,
						(defined $thetarget ? $thetarget : ""),
						(defined $params ? $params : ""));
				}
			}
		}

		elsif ($buffer =~ /^(.+?)\sD\s(.+?)\s:(.+?)$/)
		{
			my $killedby = $1;
			my $killtok = $2;
			my $killreason = $3;
			my $our_pc = $servnumeric . 'AAA';
			if (lc($killedby) ne lc($our_pc)) {
				main::register_kill_other_seen();
			}
			my $killnick = $nickhash{$killtok};
			if (defined $killnick && lc($killnick) eq lc($botnick))
			{
				my $now = time;
				&rawirc("$servnumeric N $botnick 1 $now $botnick $domain +iok AAAAAA " . $servnumeric . "AAA :$botname");
				&rawirc($servnumeric."AAA J $mychan $now");
				&rawirc($servnumeric."AAA M $mychan +o " . $servnumeric . "AAA");
			}
			my $killer_plain = _kill_source_display($killedby);
			my $victim_plain = (defined $killnick && $killnick ne '') ? $killnick : $killtok;
			_dispatch_verbose_first_hook( $oldkilled, 'handle_kill', $killer_plain, $victim_plain, $killreason );
		}

		elsif ($buffer =~ /^(.+?)\sQ\s:(.*)$/)
		{
			my $token = $1;
			my $quitreason = $2;
			my $quitnick = $nickhash{$token};
			if (defined $quitnick) {
				my $qn = _sid_to_name($token);
				my $quitserver = ($qn ne '') ? $qn : substr($token, 0, 2);
				_dispatch_verbose_first_hook( $oldkilled, 'handle_quit', $quitnick, $quitreason, $quitserver );
				_uc_drop_nick($quitnick);
				delete $hosts{lc($quitnick)};
				delete $nickhash{$token};
				delete $rnickhash{lc($quitnick)};
			}
		}

		elsif ($buffer =~ /^(.+?)\sB\s(.+?)\s(.+?)\s+(.+?)$/)
		{
			my $thetarget = $2;
			my $chan_plain_b = $thetarget;
			$chan_plain_b =~ s/^\s+|\s+$|\r//g if defined $chan_plain_b;
			if (defined $chan_plain_b && lc($chan_plain_b) eq lc($mychan)) {
				$mychants = $3;
			}
			$thetarget = quotemeta($thetarget);
			my @regarray = split(/\s+/, $buffer);
			my $nicktail = @regarray ? $regarray[-1] : '';
			if ($nicktail !~ /,/ && @regarray >= 4) {
				for my $i (reverse 0 .. $#regarray) {
					next if $regarray[$i] eq 'B';
					next if $regarray[$i] =~ /^[#&+!]/;
					if ($regarray[$i] =~ /,/) {
						$nicktail = $regarray[$i];
						last;
					}
				}
			}
			my @nicklist = grep { length $_ } split(/,/, $nicktail);
			foreach my $nicktok (@nicklist) 
			{
				my $bursttok = $nicktok;
				$bursttok =~ s/\s:%(.+?)$//;
				$bursttok =~ s/\s:\^(.+?)$//;
				my $bsuf = '';
				if ($bursttok =~ s/:([^:]+)$//) {
					$bsuf = $1;
				}
				$bursttok = substr($bursttok, 0, 5);
				my $chanpfx = ($bsuf =~ /o/i) ? '@' : ($bsuf =~ /v/i) ? '+' : ($bsuf =~ /h/i) ? '%' : '';
				my $burstjoinnick = $nickhash{$bursttok} // "";
				_info_note_channel($chan_plain_b, $burstjoinnick, $bursttok);
				_uc_join($burstjoinnick, $chan_plain_b, $chanpfx) if $burstjoinnick ne '' && defined $chan_plain_b && $chan_plain_b ne '';
				my $join_srv = ($burstjoinnick ne '') ? _join_part_server_label($burstjoinnick) : '';
				$oldkilled = $KILLED;
				_dispatch_verbose_first_hook(
					$oldkilled,
					'handle_join',
					(defined $burstjoinnick ? $burstjoinnick : ""),
					(defined $thetarget ? $thetarget : ""),
					$join_srv
				);
			}
		}

		elsif ($buffer =~ /^(.+?)\s(C|J)\s(.+?)\s(\d+)\s*$/)
		{
			print "Detected channel join\n" if $debug;
			my $fromtok = $1;
			my $thenick_plain = $nickhash{$fromtok};
			my $thetarget = $3;
			if (defined $thetarget) {
				$thetarget =~ s/^\s+|\s+$|\r//g;
			}
			_info_note_channel($thetarget, $thenick_plain, $fromtok);
			_uc_join($thenick_plain, $thetarget) if defined $thenick_plain && $thenick_plain ne '' && defined $thetarget && $thetarget ne '';
			my $join_srv = (defined $thenick_plain && $thenick_plain ne '')
				? _join_part_server_label($thenick_plain) : '';
			$thetarget = quotemeta($thetarget);
			my $thenick = quotemeta($thenick_plain);
			_dispatch_verbose_first_hook(
				$oldkilled,
				'handle_join',
				(defined $thenick ? $thenick : ""),
				(defined $thetarget ? $thetarget : ""),
				$join_srv
			);
			_mark_user_activity($thenick_plain);
		}

		elsif ($buffer =~ /^(.+?)\sK\s(\S+)\s(\S+)/)
		{
			my $ch_k = $2;
			my $vic_tok = $3;
			$ch_k =~ s/^\s+|\s+$//g if defined $ch_k;
			my $vic_plain = $nickhash{$vic_tok};
			_uc_part($vic_plain, $ch_k)
				if defined $vic_plain && $vic_plain ne '' && defined $ch_k && $ch_k ne '';
		}

		elsif ($buffer =~ /^(.+?)\sT\s([#&+!][^\s]+)\s/)
		{
			my $thenick_plain = $nickhash{$1};
			my $thetarget     = $2;
			my $params        = _p10_trailing_param($buffer);
			$params = '' unless defined $params;
			my $thenick_q = defined $thenick_plain ? quotemeta($thenick_plain) : '';
			my $thetarget_q = quotemeta($thetarget);
			my $params_q = quotemeta($params);
			foreach my $mod (@modlist)
			{
				if ($KILLED eq $oldkilled)
				{
					_dispatch_scan($mod, 'handle_topic',
						$thenick_q,
						$thetarget_q,
						$params_q);
				}
			}
			_mark_user_activity($thenick_plain);
		}

		elsif ($buffer =~ /^(.+?)\sL\s(.+?)$/)
		{
			print "Detected channel part\n" if $debug;
			my $thenick_plain = $nickhash{$1};
			my $thetarget = $2;
			_uc_part($thenick_plain, $thetarget) if defined $thenick_plain && $thenick_plain ne '' && defined $thetarget && $thetarget ne '';
			my $part_srv = (defined $thenick_plain && $thenick_plain ne '')
				? _join_part_server_label($thenick_plain) : '';
			my $thenick = quotemeta($thenick_plain);
			$thetarget = quotemeta($thetarget);
			_dispatch_verbose_first_hook(
				$oldkilled,
				'handle_part',
				(defined $thenick ? $thenick : ""),
				(defined $thetarget ? $thetarget : ""),
				$part_srv
			);
			_mark_user_activity($thenick_plain);
		}

		elsif ($buffer =~ /^(\S+)\sAC\s(\S+)\s+(.+)$/)
		{
			my $utok = $2;
			my $rest = $3;
			$rest =~ s/^\s+//;
			my @acp = split(/\s+/, $rest);
			my $acct;
			if (@acp >= 2 && $acp[0] =~ /^[RrMm]$/) {
				$acct = $acp[1];
			} elsif (@acp >= 1) {
				$acct = $acp[0];
			}
			if (defined $acct) {
				$acct =~ s/^://;
			}
			next unless defined $acct && $acct ne '';
			my $un = $nickhash{$utok};
			if ( defined $un && $un ne '' && exists $hosts{ lc($un) } ) {
				$hosts{ lc($un) }{account} = $acct;
				_mark_user_activity($un);
			}
		}

		elsif ($buffer =~ /^(\S+)\sA(?:\s:(.*))?\s*$/)
		{
			my $awsrc = $1;
			my $awmsg = defined $2 ? $2 : '';
			my $thenick_plain = $nickhash{$awsrc};
			if (defined $thenick_plain && $thenick_plain ne '') {
				my $alc = lc $thenick_plain;
				if (exists $hosts{$alc}) {
					if (!defined $2) {
						$hosts{$alc}{away} = 0;
						delete $hosts{$alc}{away_msg};
					} else {
						$hosts{$alc}{away}     = 1;
						$hosts{$alc}{away_msg} = _p10_away_sanitize($2);
					}
				}
				print "Detected AWAY change for $thenick_plain\n" if $debug;
				my $thenick_q = quotemeta($thenick_plain);
				my $awmsg_q   = quotemeta($awmsg);
				foreach my $mod (@modlist) {
					_dispatch_scan($mod, 'handle_away', $thenick_q, $awmsg_q);
				}
				_mark_user_activity($thenick_plain);
			}
		}

		elsif ($buffer =~ /\s*:/ && $buffer =~ /^(?:[A-Za-z0-9\[\]]{2}\s+)?S(?:ERVER)?\s+/i)
		{
			my ($head, $desc) = split(/\s*:/, $buffer, 2);
			next unless defined $desc;
			next unless $head =~ /^(?:[A-Za-z0-9\[\]]{2}\s+)?S(?:ERVER)?\s+(.+)$/i;
			my $payload = $1;
			my @f = split(/\s+/, $payload);
			next unless @f >= 2;
			$NETJOIN = 1;
			my $njservername = $f[0];
			my $hops = ($f[1] =~ /^\d+$/) ? (0 + $f[1]) : 1;
			my $njsid = _register_server_numeric($njservername, $payload);
			$njsid = '?' unless defined $njsid;
			if ($njsid ne '?') {
				_refresh_hosts_for_sid($njsid, $njservername);
			}
			print "[P10] uplink \(".$njservername."\) is synching: ID=".$njsid."...\n";
			if ($hops == 1 && $njsid ne '?') {
				$parentserver = $njsid;
			}
			$njtime = time+80;
		}

		elsif ($buffer =~ /^(.+?) EB/)
		{
			my $theserver = $1;
			my $thesname = _sid_to_name($theserver);
			$thesname = $theserver if $thesname eq '';
			print "[P10] Server ".$thesname.": end of netburst.\n";
			if ($acknowledged == 0) 
			{
				my $now = time;
				print ("[P10] Introducing pseudoclient: ".$botnick."...\n");
				&rawirc("$servnumeric N $botnick 1 $now $botnick $domain +iok AAAAAA " . $servnumeric . "AAA :$botname");
				print ("[P10] Joining channel...\n");
				if ($mychants == 0) {
					$mychants = $now;
				}
				&rawirc("$servnumeric B $mychan $mychants +nst " . $servnumeric . "AAA:o");
				print "[P10] Acknowledging end of my own netburst\n" if $debug;
			        &rawirc("$servnumeric EB");
			        &rawirc("$servnumeric EA");
				$acknowledged = 1;
				my $gtgt = ($parentserver ne '' && $parentserver ne $numeric)
					? $parentserver : '*';
				$GLINE_STATS_INFLIGHT = time + 60;
				print "[P10] Querying network glines (STATS g $gtgt)...\n" if $debug;
				&rawirc("$servnumeric"."AAA R g $gtgt");
			}
			$NETJOIN = 0;
		}

		elsif ($buffer =~ /^(\S+)\sGL\s(.+)$/)
		{
			my $gl_src = $1;
			my $gl_rest = $2;
			my $gl_reason = '';
			if ($gl_rest =~ /^(.+?)\s:(.*)$/) {
				$gl_rest   = $1;
				$gl_reason = $2;
			}
			my @gf = split(/\s+/, $gl_rest);
			if (@gf >= 2) {
				my $gl_target = $gf[0];
				my $am        = $gf[1];
				my ($gl_action, $gl_mask) = ('+', $am);
				if ($am =~ /^([+\-!>])(.+)$/) {
					$gl_action = $1;
					$gl_mask   = $2;
				}
				my $gl_expire  = (defined $gf[2] && $gf[2] =~ /^\d+$/) ? 0 + $gf[2] : 0;
				my $gl_lastmod = (defined $gf[3] && $gf[3] =~ /^\d+$/) ? 0 + $gf[3] : 0;
				my $gl_src_disp = _kill_source_display($gl_src);
				$gl_src_disp = $gl_src if !defined $gl_src_disp || $gl_src_disp eq '';
				foreach my $mod (@modlist) {
					next if $KILLED ne $oldkilled;
					_dispatch_scan($mod, 'handle_gline',
						$gl_src_disp, $gl_action, $gl_mask,
						$gl_expire, $gl_lastmod, $gl_reason);
				}
			}
		}

		elsif ($buffer =~ /^(\S+)\s+247\s+\S+\s+(.+?)\s:(.*)$/)
		{
			my $stg_src    = $1;
			my $stg_middle = $2;
			my $stg_reason = $3;
			$stg_middle =~ s/\s+$//;
			my @sf = split(/\s+/, $stg_middle);
			if (@sf >= 3 && $sf[0] =~ /^[GgR]$/) {
				my $stg_type     = $sf[0];
				my $stg_mask     = $sf[1];
				my $stg_expire   = ($sf[2] =~ /^\d+$/) ? 0 + $sf[2] : 0;
				my $stg_lastmod  = (defined $sf[3] && $sf[3] =~ /^\d+$/) ? 0 + $sf[3] : 0;
				my $stg_flags    = (defined $sf[-1] && $sf[-1] !~ /^\d+$/) ? $sf[-1] : '';
				my $stg_inactive = ($stg_flags =~ /D/i) ? 1 : 0;
				if (uc($stg_type) eq 'G' && !$stg_inactive) {
					my $stg_src_disp = _kill_source_display($stg_src);
					$stg_src_disp = $stg_src if !defined $stg_src_disp || $stg_src_disp eq '';
					foreach my $mod (@modlist) {
						next if $KILLED ne $oldkilled;
						_dispatch_scan($mod, 'handle_gline',
							$stg_src_disp, '+', $stg_mask,
							$stg_expire, $stg_lastmod, $stg_reason);
					}
				}
			}
		}

		elsif ($buffer =~ /^(\S+)\s+219\s+\S+\s+(\S+)\s+:/)
		{
			my $eos_letter = $2;
			if (lc($eos_letter) eq 'g' && $GLINE_STATS_INFLIGHT) {
				$GLINE_STATS_INFLIGHT = 0;
				foreach my $mod (@modlist) {
					next if $KILLED ne $oldkilled;
					_dispatch_scan($mod, 'handle_gline_burst_done');
				}
			}
		}

		elsif ($buffer =~ /^(\S+)\s+317\s+(\S+)\s+(\S+)\s+(\d+)(?:\s+\d+)?\s+:(.*)$/)
		{
			my $rq = $2;
			my $wn = $3;
			my $idle = $4;
			my $bot = bot_numnick();
			if (defined $bot && $rq eq $bot && exists $live_whois_pending{lc($wn)}) {
				my $tag = ($live_whois_pending{lc($wn)}{tag} // 'WHOIS');
				if ($tag eq 'WHOIS') {
					my $idle_h = _fmt_idle_human($idle);
					main::message("\00305\002[$tag]\017 \00306Live idle for\017 \00302\002$wn\017\00306:\017 \00302\002$idle_h\017 \00306(IRCd clock)\017");
				}
			}
		}

		elsif ($buffer =~ /^(\S+)\s+301\s+(\S+)\s+(\S+)\s+:(.*)$/)
		{
			my $rq = $2;
			my $wn = $3;
			my $away_msg = defined $4 ? $4 : '';
			my $bot = bot_numnick();
			if (defined $bot && $rq eq $bot && exists $live_whois_pending{lc($wn)}) {
				my $ref = $live_whois_pending{lc($wn)};
				$ref->{away_seen} = 1 if ref($ref) eq 'HASH';
				my $wlc = lc($wn);
				if (exists $hosts{$wlc}) {
					$hosts{$wlc}{away} = 1;
					$hosts{$wlc}{away_msg} = $away_msg;
					_mark_user_activity($wn);
				}
				my $show = $away_msg;
				$show = substr($show, 0, 220) . '...' if length($show) > 220;
				$show = '(empty message)' if $show eq '';
				my $tag = ($ref->{tag} // 'WHOIS');
				main::message("\00305\002[$tag]\017 \00306Live away for\017 \00302\002$wn\017\00306:\017 \00302yes\017 \00310$show\017");
			}
		}

		elsif ($buffer =~ /^(\S+)\s+330\s+(\S+)\s+(\S+)\s+(\S+)\s+:(.*)$/)
		{
			my $rq   = $2;
			my $wn   = $3;
			my $acct = $4;
			my $bot  = bot_numnick();
			if (defined $bot && $rq eq $bot && exists $live_whois_pending{lc($wn)}) {
				if (defined $acct && $acct ne '') {
					$acct =~ s/^://;
					my $wlc = lc($wn);
					my $old_acct = '';
					if (exists $hosts{$wlc} && defined $hosts{$wlc}{account}) {
						$old_acct = $hosts{$wlc}{account};
					}
					if (exists $hosts{$wlc}) {
						$hosts{$wlc}{account} = $acct;
					}
					my $tag = ($live_whois_pending{lc($wn)}{tag} // 'WHOIS');
					if ($tag eq 'WHOIS' && ($old_acct eq '' || lc($old_acct) ne lc($acct))) {
						main::message("\00305\002[$tag]\017 \00306Live account for\017 \00302\002$wn\017\00306:\017 \00302\002$acct\017");
					}
				}
			}
		}

		elsif ($buffer =~ /^(\S+)\s+318\s+(\S+)\s+(\S+)\s+:/)
		{
			my $rq = $2;
			my $wn = $3;
			my $bot = bot_numnick();
			if (defined $bot && $rq eq $bot && exists $live_whois_pending{lc($wn)}) {
				my $ref = $live_whois_pending{lc($wn)};
				if (ref($ref) eq 'HASH' && !($ref->{away_seen} // 0)) {
					my $tag = ($ref->{tag} // 'WHOIS');
					my $wlc = lc($wn);
					if (exists $hosts{$wlc}) {
						$hosts{$wlc}{away} = 0;
						delete $hosts{$wlc}{away_msg};
					}
					main::message("\00305\002[$tag]\017 \00306Live away for\017 \00302\002$wn\017\00306:\017 \00302no\017");
				}
				delete $live_whois_pending{lc($wn)};
			}
		}

		elsif ($buffer =~ /^(.+?)\sO\s(.+?)\s:(.+?)$/)
		{
			if (defined $nickhash{$1}) {
				_mark_user_activity($nickhash{$1});
				$buffer = ":" . $nickhash{$1} . " NOTICE $2 :$3";
				&noticehandler($buffer);
			}
		}

		elsif ($buffer =~ /^(.+?)\sG\s(.+)\s(.+)\s(.+)$/)
		{
			print "Ping? Pong!\n" if $debug;
			&rawirc("$servnumeric Z $2 $3");
		}

		elsif ($buffer =~ /^(.+?)\sP\s(.+?)\s:(.+?)$/) 
		{
			if (defined $nickhash{$1}) {
				_mark_user_activity($nickhash{$1});
				$buffer = ":" . $nickhash{$1} . " PRIVMSG $2 :$3";
				&msghandler($buffer);
			}
		}

		elsif ($buffer =~ /^(.+?)\sW\s(.+?)\s:.+$/) 
		{
			my $source = $1;
			&rawirc("$servnumeric 311 $source $botnick $botnick $domain * :$botname");
			&rawirc("$servnumeric 312 $source $botnick $servername :$serverdesc");
			&rawirc("$servnumeric 313 $source $botnick :NetIRC Defender V3 - network security service");
			&rawirc("$servnumeric 317 $source $botnick 0 $START_TIME :seconds idle, signon time");
			&rawirc("$servnumeric 318 $source $botnick :End of /WHOIS list.");
		}

	}
	$inbound_dispatch_active = 0;
	$inbound_batch_count = 0;

	return 1;

}


sub shutdown {
	&rawirc($servnumeric."AAA Q :NetIRC Defender V3 - network security service (terminating)");
	print("Disconnecting from irc server (SIGINT)\n");
	&rawirc("$servnumeric SQ $servnumeric :$quitmsg");
	sleep(1);
	$p10_io_select = undef;
	$p10_readbuf = '';
	close SH;
	exit;
}

sub handle_alarm
{
}

1;
