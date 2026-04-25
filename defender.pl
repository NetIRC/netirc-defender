#!/usr/bin/perl
#
# SPDX-License-Identifier: GPL-2.0-only
# Copyright (c) 2026 NetIRC Defender
#
# NetIRC Defender V3 - network security service

use strict;
use warnings;
use 5.010;
use IO::Socket;

use constant {
	VERSION => "3.0.0",
	DATE    => "Apr 2026"
};

require "./message.pl";
require "./Modules/Main.pm";

&general_init;
&check_params;
&load_config;
&init_modules;
&connect;
&daemon;
# poll() waits ≤1s with no data, runs idle_timers() before each wait and after each line.
while (1) {
	my $ok = poll();
	reconnect() if !$ok;
}
