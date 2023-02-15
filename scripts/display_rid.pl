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
use Curses qw(initscr endwin addstr clear refresh curs_set);
use JSON qw(decode_json);

#

my($end_program,$op_id) = (0,0);
my($log_dir,$log_file,$filename,$encoding) = ("tmp","rid_capture.json",'',':encoding(UTF-8)');
my($datagram,$flags);
my($line,$text);
my($mac,$operator,$id,$latitude,$longitude,$alt_msl,$heading,$speed,$registration);
my($hsecs,$unix_time,$m,$s);
my(@auth) = ('','');
my($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst);
my($loop_time,$debug,$max_udp);
my($row,$col) = (0,0);
my($next_row,$time_row,$debug_row) = (1,11,12);
my($loc_col,$ts_col) = (40,80);
my($a,$b,$op,$t,$t2,$reg,@values);
my(%mac2row,%mac2time,%mac2op,%mac2id,%mac2reg);

# UDP server

my $rid_udp = IO::Socket::INET->new(Proto=>"udp",LocalPort=>32001)
    or die "Failed to create UDP server: $@";

# log file

# mkdir($log_dir,0777);
# open(LOG,"> $encoding",$filename = "$log_dir/$log_file") or die "Failed to open \'$filename\': $@";

# Curses

initscr();
clear();
if ($op_id == 0) {
    $text = sprintf("%-18s %-20s ","MAC","ID");
} elsif ($op_id == 1) {
    $text = sprintf("%-18s %-20s ","MAC","operator");
} elsif ($op_id == 2) {
    $text = sprintf("%-18s %-20s ","ID","operator");
}
addstr(0,0,$text);
$text = sprintf("%-12s %-12s %-4s %7s",
                "latitude","longitude","alt.","heading");
addstr(0,$loc_col,$text);
addstr(0,$ts_col,"   timestamps");
refresh();
curs_set(0);

$SIG{INT} = \&catch_int;

$line = '';

for (;!$end_program;) {

    # Ensure that the length here is greater than the expected datagram size.

    $rid_udp->recv($datagram,512,$flags);
    $line .= $datagram;
    
    if ($line =~ m/\n/) {
 
        # print LOG $line;
        eval {
            $a = decode_json($line);
        };
        $line = '';
 
        if ($mac = $$a{'mac'}) {

            $t         = $$a{'unix time'};
            $t2        = $$a{'unix time (alt)'};
            $op        = $$a{'operator'};
            $reg       = $$a{'caa registration'};
            $id        = $$a{'uav id'};
            $latitude  = $$a{'uav latitude'};
            $longitude = $$a{'uav longitude'};
            $alt_msl   = $$a{'uav altitude'};
            $heading   = $$a{'uav heading'};
            $speed     = $$a{'uav speed'};
            $hsecs     = $$a{'seconds'};
            $max_udp   = $$a{'max udp len'};
            $auth[0]   = $$a{'auth page 0'};

            if ($t) {
                $mac2time{$mac} = $t;
            } elsif ($t2) {
                $mac2time{$mac} = $t2;
            }

            if ($op) {
                $mac2op{$mac} = $op;
            }

            if ($reg) {
                $mac2reg{$mac} = $reg;
            }

            if ($id) {
                $mac2id{$mac} = $id;
            }

            $row = $mac2row{$mac};
        
            if (!$row) {
                $row = $mac2row{$mac} = $next_row++;
            }

            $reg = ($mac2reg{$mac})  ? $mac2reg{$mac}:  ''; 
            $op  = ($mac2op{$mac})   ? $mac2op{$mac}:   ''; 
            $id  = ($mac2id{$mac})   ? $mac2id{$mac}:   ''; 
            $t   = ($mac2time{$mac}) ? $mac2time{$mac}: 0;

            if ($op_id == 0) {
                $text = sprintf("%-18s %-20s ",$mac,$id);
            } elsif ($op_id == 1) {
                $text = sprintf("%-18s %-20s ",$mac,$op);
            } elsif ($op_id == 2) {
                $text = sprintf("%-18s %-20s ",$id,$reg);
            }
            addstr($row,0,$text);

            if ($t) {

                ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) = gmtime($t);
                $text = sprintf("%2d-%02d-%02d %02d:%02d:%02d ",
                                $year % 100,$mon + 1,$mday,$hour,$min,$sec);
                addstr($row,$ts_col + 6,$text);
            }

            if ($latitude) { # We have a Location message.

                if ($hsecs) {
                    $m = int($hsecs / 60);
                    $s = int($hsecs % 60);
                }

                $text = sprintf("%-12.6f %-12.6f %4d   %3d   ",
                                $latitude,$longitude,$alt_msl,$heading);
                # print "$text\n";
                addstr($row,$loc_col,$text);
                if ($hsecs) {
                    $text = sprintf("%02d:%02d ",$m,$s);
                    addstr($row,$ts_col,$text);
                }
                refresh();
            }

            if ($b = $auth[0]) {
                if ($text = $$b{'text'}) {
                    addstr($debug_row,$loc_col,"Auth 0: \'$text\'");
                }
            }
        }

        if ($loop_time = $$a{'loop_time_us'}) {
            $text = sprintf("%7d us",$loop_time);
            # print "$row loop $loop_time us\n";
            addstr($time_row,0,$text);
            refresh();
        }

        if ($debug = $$a{'debug'}) {
            $text = sprintf("%-40s",$debug);
            # print "$row loop $loop_time us\n";
            addstr($debug_row,0,$text);
            refresh();
        }

        if ((0)&&($max_udp = $$a{'max udp len'})) {
            $text = sprintf("%7d bytes",$max_udp);
            addstr($debug_row + 1,0,$text);
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
