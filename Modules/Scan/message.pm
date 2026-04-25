#
# SPDX-License-Identifier: GPL-2.0-only
# Copyright (c) 2026 NetIRC Defender
#
# NetIRC Defender V3 - network security service

package Modules::Scan::message;

use strict;
use warnings;

sub _dsp {
	my ($s) = @_;
	return '' unless defined $s;
	$s =~ s/\\(.)/$1/g;
	return $s;
}

my $tot_rant = 0;
my $tot_mesg = 0;
my %nicks;

sub handle_topic
{
}

sub stats {
	main::message("Unique users to message the bot:  \002$tot_rant\002");
	main::message("Total messages received:          \002$tot_mesg\002");
}


sub handle_join
{

}

sub handle_part
{

}

sub handle_mode
{

}

sub scan_user
{
	my ($ident,$host,$serv,$nick,$gecos,$print_always) = @_;
}

sub handle_notice
{
	my ($nick,$ident,$host,$chan,$notice) = @_;
}

sub handle_privmsg
{
        my ($nick,$ident,$host,$chan,$msg) = @_;
	my $chan_d = _dsp($chan);
	my $msg_d  = _dsp($msg);
	my $nick_d = _dsp($nick);
	if (($chan_d !~ /^[#&+]/) && ($msg_d !~ /^\001/))
	{
		if (!exists $nicks{$nick_d} || $nicks{$nick_d} ne '1') {
			main::notice($nick_d,"\002$main::netname\002 - \002$main::botname\002 Support: \002$main::supportchannel\002 (no PM support).");

			$nicks{$nick_d} = '1';
			$tot_rant++;
		}
		$msg_d =~ s/\003\d+|\002|\037//gi;
		main::message("Message: \002$nick_d\002 -> \"$msg_d\"");
		$tot_mesg++;
	}
}

sub init {

        if (!main::depends("core-v1")) {
                print "This module requires version 1.x of defender.\n";
                exit(0);
        }
        main::provides("message");

}

1;
