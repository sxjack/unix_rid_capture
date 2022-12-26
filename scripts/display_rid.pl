#!/usr/bin/perl -w
# -*- tab-width: 4; mode: perl; -*-
#
# A script that uses the Curses library to display the data 
# transmitted by rid_capture over UDP.
#
# ^C to exit.
#

use strict;
use IO::Socket;
use Curses qw(initscr endwin addstr clear refresh);
use JSON qw(decode_json);

my $rid_udp = IO::Socket::INET->new(Proto=>"udp",LocalPort=>32001)
    or die "Failed to create UDP server: $@";

my($datagram,$flags);
my($line,$text);
my($mac,$operator,$serial,$latitude,$longitude,$alt_msl,$heading,$speed,$unix_time);
my($loop_time);
my($next_row,$row,$col) = (1,0);
my($a,$op,$t);
my(%mac2row,%mac2time,%mac2op);
my($end_program) = (0);

initscr();
clear();
refresh();

$SIG{INT} = \&catch_int;

$line = '';

for (;!$end_program;) {
    
    $rid_udp->recv($datagram,256,$flags);
    $line .= $datagram;
    
    if ($line =~ m/\n/) {
 
        # print $line;
        $a = decode_json($line);
        $line = '';
 
        if ($mac = $$a{'mac'}) {

            $t         = $$a{'unix time'};
            $op        = $$a{'operator'};
            $latitude  = $$a{'uav latitude'};
            $longitude = $$a{'uav longitude'};
            $alt_msl   = $$a{'uav altitude'};
            $heading   = $$a{'uav heading'};
            $speed     = $$a{'uav speed'};

            if ($t) {
                $mac2time{$mac} = $t;
            }

            if ($op) {
                $mac2op{$mac} = $op;
            }

            $row = $mac2row{$mac};
        
            if (!$row) {
                $row = $mac2row{$mac} = $next_row++;
            }

            $op = ($mac2op{$mac}) ? $mac2op{$mac}: ''; 
        
            if ($latitude) {

                $text = sprintf("%-18s %-20s %-12.6f %-12.6f %4d %3d",
                                $mac,$op,$latitude,$longitude,$alt_msl,$heading);
                # print "$text\n";
                addstr($row,0,$text);
                refresh();
            }

        } elsif ($loop_time = $$a{'loop_time_us'}) {

            $row = 16;
            $text = sprintf("%7d us",$loop_time);
            # print "$row loop $loop_time us\n";
            addstr($row,0,$text);
            refresh();
        }
    }
}

endwin();

exit;

sub catch_int {

    $end_program = 1;
}

__END__
