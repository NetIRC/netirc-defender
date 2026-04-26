#
# SPDX-License-Identifier: GPL-2.0-only
# Copyright (c) 2026 NetIRC Defender
#
# NetIRC Defender V3 - network security service

use 5.010;
use Socket;
use Symbol qw(delete_package);

our $KILLED;
our $CONNECTS;
our $KILL_SEEN_OTHER;
our $CONNECTS_LIFE;
our $KILLED_LIFE;
our $KILL_SEEN_OTHER_LIFE;
our $PERSISTENT_COUNTERS_SINCE;
our $persistent_counters_enabled;
our $persistent_counters_dirty;
our $persistent_counters_last_flush;
our $START_TIME;
our $curdir;
our $ATTACK_MODE;
our $ATTACK_MODE_UNTIL;

our @provides = ();

sub depends
{
	print "Checking depends: @_\n" if $debug;
	foreach my $t (@_) {
		if ($t ne '') {
			my $satisfy = 0;
			foreach my $token (@provides) {
				if ($token eq $t) {
					$satisfy = 1;
				}
			}
			if (!$satisfy) {
				return 0;
			}
		}
	}
	return 1;
}

sub provides
{
	print "Adding provides: @_\n" if $debug;
	foreach my $t (@_) {
		if ($t ne '') {
			if (depends($t)) {
				print "\n\nERROR! Two modules are providing the same features (token: $t)\n";
				print "You probably have the same module loaded twice, or a feature conflict!\n";
				print "Bailing...\n";
				exit(0);
			}
			push @provides,$t;
		}
	}
}

sub general_init
{
	if ($0 =~ /(^\/.*?)[^\/]*$/){ $curdir=$1; }
	else { $0 =~ /(.*?)[^\/]*$/; $curdir=$ENV{PWD}."/".$1; }
	print "NetIRC Defender V3 - network security service $VERSION ($DATE) [P10] GPL\n";
	$START_TIME = time;
	$CONNECTS = 0;
	$KILLED     = 0;
	$KILL_SEEN_OTHER = 0;
	$persistent_counters_dirty = 0;
	$persistent_counters_last_flush = 0;
	$ATTACK_MODE = 0;
	$ATTACK_MODE_UNTIL = 0;
}

sub _attack_mode_auto_enabled {
	my $v = $dataValues{"attack_mode_auto"};
	return 1 if !defined $v || $v eq '';
	return ($v =~ /^(0|false|no|off)$/i) ? 0 : 1;
}

sub attack_mode_hold_sec {
	my $v = $dataValues{"attack_mode_hold_sec"};
	$v = 300 unless defined $v && $v =~ /^[0-9]+$/;
	$v = int($v);
	return 30 if $v < 30;
	return 86400 if $v > 86400;
	return $v;
}

sub is_attack_mode {
	if ($ATTACK_MODE && time() >= ($ATTACK_MODE_UNTIL // 0)) {
		$ATTACK_MODE = 0;
		$ATTACK_MODE_UNTIL = 0;
		eval { main::globops("[ATTACK_MODE] Automatic attack mode disabled; normal profile resumed.") };
		eval { main::message("\002[ATTACK_MODE]\002 Automatic attack mode disabled; normal profile resumed.") };
	}
	return $ATTACK_MODE ? 1 : 0;
}

sub enter_attack_mode {
	my ($reason, $hold_override) = @_;
	return unless _attack_mode_auto_enabled();
	my $hold = (defined $hold_override && $hold_override =~ /^[0-9]+$/)
		? int($hold_override)
		: attack_mode_hold_sec();
	$hold = 30 if $hold < 30;
	my $new_until = time() + $hold;
	my $was = is_attack_mode();
	$ATTACK_MODE = 1;
	$ATTACK_MODE_UNTIL = $new_until if $new_until > ($ATTACK_MODE_UNTIL // 0);
	$reason = 'triggered by policy' if !defined $reason || $reason eq '';
	$reason =~ s/[\x00\r\n]//g;
	$reason = substr($reason, 0, 180) if length($reason) > 180;
	if (!$was) {
		eval { main::globops("[ATTACK_MODE] Enabled for ${hold}s ($reason).") };
		eval { main::message("\002[ATTACK_MODE]\002 Enabled for ${hold}s ($reason).") };
	}
}

sub load_config
{
	print "Loading configuration file...\n";
	push @rehash_data, "Loading configuration file...";

        @provides = ();
        provides("core-v1");

	$cfg = "$curdir/defender.conf";
	$dir = $curdir;
	open my $cfh, '<', $cfg or die "Can't locate config file! ($cfg): $!\n";
	while (my $pair = <$cfh>) {
		chomp $pair;
		$pair =~ s/\r\z//;
		next if $pair =~ /^\s*$/;
		next if $pair =~ /^\s*#/;
		next unless $pair =~ /=/;
		my ($var, $val) = split /=/, $pair, 2;
		$var =~ s/^\s+|\s+$//g;
		$val = '' unless defined $val;
		$val =~ s/^\s+|\s+$//g;
		$val =~ s/%([0-9A-Fa-f]{2})/chr(hex($1))/ge;
		$dataValues{$var} = $val;
	}
	close $cfh;
	$domain = $dataValues{"domain"};
	$nspass = $dataValues{"nickserv"};
	$dir = $dataValues{"datadir"};
	$killurl = $dataValues{"url"};
	$killmail = $dataValues{"mail"};
	$server = $dataValues{"server"};
	$server_re = $dataValues{"servregexp"};
	$botnick = $dataValues{"botnick"};
	$mychan = $dataValues{"channel"};
	$quitmsg = $dataValues{"quitmsg"};
	$port = $dataValues{"port"};
	$paranoia = $dataValues{"paranoia"};
	$botname = $dataValues{"fullname"};
	$oname = $dataValues{"opername"};
	$opass = $dataValues{"operpass"};
	$password = $dataValues{"password"};
	$netname    = $dataValues{"networkname"};
	$servername = $dataValues{"servername"};
	$numeric    = $dataValues{"numeric"};
	$serverdesc = $dataValues{"serverdesc"};
	my $cfg_link = $dataValues{"linktype"} // "p10";
	if ($cfg_link ne "p10") {
		print "Note: linktype '$cfg_link' is ignored; this build only supports P10.\n";
	}
	$linkmodule = "p10";
	$logger = $dataValues{"logto"};
	$supportchannel = $dataValues{"supportchannel"};
	$OneWord = $dataValues{"OneWord"};
	$ugly = $dataValues{"ugly"};
	$version_verbose = $dataValues{"version_verbose"};
	$sid = $dataValues{"sid"};
	$gline_protect_nicks = $dataValues{"gline_protect_nicks"} // '';
	my $pc = $dataValues{"persistent_counters"};
	$persistent_counters_enabled = (defined $pc && $pc ne '') ? ($pc ne "0") : 1;
	load_persistent_counters();
}

sub _persistent_counters_path {
	return '' unless defined $dir && $dir ne '';
	return "$dir/defender_persistent_counters.v1";
}

sub load_persistent_counters {
	$CONNECTS_LIFE         = 0;
	$KILLED_LIFE           = 0;
	$KILL_SEEN_OTHER_LIFE  = 0;
	$PERSISTENT_COUNTERS_SINCE = undef;
	$persistent_counters_dirty = 0;
	$persistent_counters_last_flush = 0;
	return unless $persistent_counters_enabled;
	my $path = _persistent_counters_path();
	return unless $path ne '' && -f $path;
	my $read_since;
	my $had_since_line = 0;
	open my $fh, '<', $path or return;
	while (my $line = <$fh>) {
		chomp $line;
		$CONNECTS_LIFE        = $1        if $line =~ /^connects=(\d+)$/;
		$KILLED_LIFE          = $1        if $line =~ /^killed=(\d+)$/;
		$KILL_SEEN_OTHER_LIFE = $1        if $line =~ /^kill_seen_other=(\d+)$/;
		if ($line =~ /^since=(\d+)$/) {
			$read_since = $1;
			$had_since_line = 1;
		}
	}
	close $fh;
	if (defined $read_since && $read_since =~ /^\d+$/ && $read_since > 0) {
		$PERSISTENT_COUNTERS_SINCE = 0 + $read_since;
	} else {
		my @st = stat $path;
		$PERSISTENT_COUNTERS_SINCE = (@st) ? $st[9] : time;
	}
	if (!$had_since_line) {
		save_persistent_counters(1);
	}
}

sub _persistent_counters_flush_sec {
	my $v = $dataValues{"persistent_counters_flush_sec"};
	$v = 5 unless defined $v && $v =~ /^\d+$/;
	$v = int($v);
	return 1 if $v < 1;
	return 300 if $v > 300;
	return $v;
}

sub save_persistent_counters {
	my ($force) = @_;
	return unless $persistent_counters_enabled;
	$force = $force ? 1 : 0;
	my $now = time;
	if (!$force) {
		$persistent_counters_dirty = 1;
		my $iv = _persistent_counters_flush_sec();
		return if ($persistent_counters_last_flush && ($now - $persistent_counters_last_flush) < $iv);
	}
	my $path = _persistent_counters_path();
	return unless $path ne '';
	$PERSISTENT_COUNTERS_SINCE = time unless defined $PERSISTENT_COUNTERS_SINCE;
	my $tmp = "$path.tmp.$$";
	open my $fh, '>', $tmp or return;
	print $fh "v1\nsince=$PERSISTENT_COUNTERS_SINCE\nconnects=$CONNECTS_LIFE\nkilled=$KILLED_LIFE\nkill_seen_other=$KILL_SEEN_OTHER_LIFE\n";
	close $fh;
	rename $tmp, $path or unlink $tmp;
	$persistent_counters_last_flush = $now;
	$persistent_counters_dirty = 0;
}

sub maybe_flush_persistent_counters {
	return unless $persistent_counters_enabled;
	return unless $persistent_counters_dirty;
	save_persistent_counters(0);
}

sub register_signon {
	$CONNECTS++;
	return unless $persistent_counters_enabled;
	$CONNECTS_LIFE++;
	save_persistent_counters(0);
}

sub register_defender_removal {
	$KILLED++;
	return unless $persistent_counters_enabled;
	$KILLED_LIFE++;
	save_persistent_counters(0);
}

sub register_kill_other_seen {
	$KILL_SEEN_OTHER++;
	return unless $persistent_counters_enabled;
	$KILL_SEEN_OTHER_LIFE++;
	save_persistent_counters(0);
}

sub _call_scan_init {
	my ($mod) = @_;
	no strict 'refs';
	my $sym = "Modules::Scan::${mod}::init";
	return "No init() in Modules::Scan::$mod\n" unless defined &{$sym};
	local $@;
	eval { &{$sym}() };
	return $@;
}

sub reinit_modules
{
	&link_init;

	my @removed;
	my @added;
	my @unchanged;

	$modules = $dataValues{"modules"} // '';
	$modules =~ s/^\s+|\s+$//g;
	our @modlist = grep { length $_ } map { s/^\s+|\s+$//g; $_ } split /,/, $modules;
	
	foreach my $mod (@modlist) {
		my $added = 1;
		foreach my $old (@oldmods) {
			if ($old eq $mod) {
				$added = 0;
			}
		}
		if ($added == 1) {
			push @added, $mod;
		}
	}	

	foreach my $mod (@oldmods) {
		my $removed = 1;
		foreach my $new (@modlist) {
			if ($new eq $mod) {
				$removed = 0;
			}
		}
		if ($removed == 1) {
			push @removed, $mod;
		}
	}

	foreach my $mod (@modlist) {
		my $unchanged = 1;
		foreach my $n (@removed) {
			if ($mod eq $n) {
				$unchanged = 0;
			}
		}
		foreach my $n (@added) {
			if ($mod eq $n) {
				$unchanged = 0;
			}
		}
		if ($unchanged == 1) {
			push @unchanged, $mod;
		}
	}

	print "Rehashing.\nAdded: @added Removed: @removed Unchanged: @unchanged\n\n";

	foreach $mod (@removed) {
		print "Unloading: Modules/Scan/$mod.pm... ";
		push @rehash_data, "Unloading: Modules/Scan/$mod.pm... ";
		my $pkg = "Modules::Scan::" . $mod;
		my $pm = "$curdir/Modules/Scan/$mod.pm";
		local $@;
		eval { delete_package($pkg) };
		my $unload_err = $@;
		delete $INC{$pm};
		if ($unload_err) {
			print $unload_err;
			push @rehash_data, $unload_err;
			print "FAILED.\n";
		} else {
			print "OK!\n";
		}
	}

	foreach $mod (@added) {
		print ("Loading: Modules/Scan/$mod.pm... ");
		push @rehash_data, "Loading: Modules/Scan/$mod.pm... ";
		require "$curdir/Modules/Scan/$mod.pm";
		my $err = _call_scan_init($mod);
		if ($err) {
			print $err;
			push @rehash_data, $err;
			print "FAILED.\n";
		} else {
			print "OK!\n";
		}
	}

	foreach $mod (@unchanged) {
		print ("Re-initializing: Modules/Scan/$mod.pm... ");
		push @rehash_data, "Re-initializing: Modules/Scan/$mod.pm... ";
		my $err = _call_scan_init($mod);
		if ($err) {
			print $err;
			push @rehash_data, $err;
			print "FAILED.\n";
		} else {
			print "OK!\n";
		}
	}	
}

sub init_modules
{
	open(CHECK,"$curdir/Modules/Link/$linkmodule.pm") or &barf("Link",$linkmodule);
	close(CHECK);
	require "$curdir/Modules/Link/$linkmodule.pm";
	print ("Using $linkmodule connection module (loaded OK)...\n");
	&link_init;

	print ("\nLoading modules...\n");

	$modules = $dataValues{"modules"} // '';
	$modules =~ s/^\s+|\s+$//g;
	our @modlist = grep { length $_ } map { s/^\s+|\s+$//g; $_ } split /,/, $modules;
	foreach $mod (@modlist) {
	        print ("Loading: Modules/Scan/$mod.pm... ");
		open(CHECK,"$curdir/Modules/Scan/$mod.pm") or &barf("Scan",$mod);
		close(CHECK);
	        require "$curdir/Modules/Scan/$mod.pm";
		my $err = _call_scan_init($mod);
		if ($err) {
			print $err;
			print "FAILED.\n";
		} else {
			print ("OK!\n");
		}
	}

	open(CHECK,"$curdir/Modules/Log/$logger.pm") or &barf("Log",$logger);
	close(CHECK);
	require "$curdir/Modules/Log/$logger.pm";
	if (!$debug)
	{
		print "Switching to $logger logging method from now\n";
		no strict 'refs';
		my $loginit = "Modules::Log::${logger}::init";
		if (defined &{$loginit}) {
			eval { &{$loginit}() };
			print $@ if $@;
		}
	}
	else
	{
		print "Not enabling logging module because debugging is enabled\n";
		print "Will log to console.\n";
	}
}

sub rehash
{
	main::save_persistent_counters(1);
	chdir $dir;
	our @rehash_data = ();
	our @oldmods = @modlist;
	main::load_config;
	main::reinit_modules;
	chdir '/';
}

sub check_params
{
	use Getopt::Long;
	GetOptions("debug" => \$debug, "help" => \$help);

	if (defined($help))
	{
		print "usage: perl defender.pl [--debug] [--help]  (GPL v2)\n";
		exit(0);
	}
	if (defined($debug))
	{
		$debug = 1;
	}
	else
	{
		$debug = 0;
	}
}

sub writepid {
	$pidfile = "$curdir/defender.pid";
	open my $pfh, '>', $pidfile or return;
	print {$pfh} $$;
	close $pfh;
}

sub daemon
{
	use POSIX qw(setsid);

	if (!$debug)
	{
		chdir '/'                 or die "Can't chdir to /: $!";
		umask 0;
		open STDIN, '/dev/null'   or die "Can't read /dev/null: $!";
		open STDERR, '>/dev/null' or die "Can't write to /dev/null: $!";
		defined(my $pid = fork)   or die "Can't fork: $!";
		exit if $pid;
		setsid                    or die "Can't start a new session: $!";
	}

	$SIG{'INT'} = 'shutdown';
	$SIG{'HUP'} = 'rehash';

	main::writepid;
}

sub barf {
	my($type,$name) = @_;
	print <<EOSPAM;


ERROR: Cannot find the $type module you specified in your configuration 
file. It is possible that you specified the wrong name, or you edited 
your config file on windows then uploaded it to a unix machine and have 
a linefeed character in your filename because of it. If this is the 
case, edit your config file again from scratch on a unix (linux, freebsd etc)
machine where you are going to run the program.

Of course, it is equally possible that the filename you specified just
doesn't exist.

Specified $type module: $name

EOSPAM

	exit(0);
}

1;
