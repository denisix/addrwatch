#!/usr/bin/perl -w
use strict;
use Time::HiRes qw( usleep );
use Sys::Mmap qw( mmap PROT_READ MAP_SHARED );
use Socket qw ( inet_ntop AF_INET AF_INET6 );

my $WAIT_INTERVAL = 500;
my $magic = 0xc0decafe;
my $file = "addrwatch-shm-log";



my $buf;
open FH, "</dev/shm/$file";
mmap( $buf, 0, PROT_READ, MAP_SHARED, FH ) or die "mmap: $!";
close FH;

sub ether_ntoa($) {
  my $n = $_[0];
  return sprintf "%02x:%02x:%02x:%02x:%02x:%02x",
    vec($n, 0, 8), vec($n, 1, 8), vec($n, 2, 8),
    vec($n, 3, 8), vec($n, 4, 8), vec($n, 5, 8);
}

my $tmp;
do {
	usleep($WAIT_INTERVAL);
	$tmp = unpack 'L*', substr( $buf, 0, 4);
	#print "BUF: $tmp magic[$magic]\n";
} while ($tmp ne $magic);

print "OK, found!\n";

my ($m, $size, $last_idx) = unpack 'Q3', substr $buf, 0, 24;
#print "magic[$magic] m [$m] size[$size] last[$last_idx]\n";

my $pos = 23;
my $len = 56;
for(my $i = 0; $i < $last_idx; $i++) {
	my ($ts, $iface, $ip, $mac, $ip_len, $orig, $vlan) = unpack 'x1Lx3a16xZ16A8C1C1S1', substr($buf, $pos, $len);
	my $ip_str = ($ip_len == 16) ? inet_ntop(AF_INET6, $ip) : inet_ntop(AF_INET, $ip);
	my $mac_str = ether_ntoa($mac);
	$pos += $len; 

	# PROOF OF PARSED OUT:
	print "$i:\tts[$ts], iface[$iface], ip[$ip_str], mac[$mac_str], iplen[$ip_len], orig[$orig], vlan[$vlan]\n";
}
