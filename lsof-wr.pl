#!/usr/bin/perl
# wrapper around lsof to add peer information for Unix
# domain sockets. needs lsof, and superuser privileges.
# Copyright Stephane Chazelas 2015, public domain.
# example: sudo this-lsof-wrapper -aUc Xorg
use Socket;

open K, "<", "/proc/kcore" or die "open kcore: $!";
read K, $h, 8192 # should be more than enough
 or die "read kcore: $!";

# parse ELF header
my ($t,$o,$n) = unpack("x4Cx[C19L!]L!x[L!C8]S", $h);
$t = $t == 1 ? "L3x4Lx12" : "Lx4QQx8Qx16"; # program header ELF32 or ELF64
my @headers = unpack("x$o($t)$n",$h);

# read data from kcore at given address (obtaining file offset from ELF
# @headers)
sub readaddr {
  my @h = @headers;
  my ($addr, $length) = @_;
  my $offset;
  while (my ($t, $o, $v, $s) = splice @h, 0, 4) {
    if ($addr >= $v && $addr < $v + $s) {
      $offset = $o + $addr - $v;
      if ($addr + $length - $v > $s) {
        $length = $s - ($addr - $v);
      }
      last;
    }
  }
  return undef unless defined($offset);
  seek K, $offset, 0 or die "seek kcore: $!";
  my $ret;
  read K, $ret, $length or die "read($length) kcore \@$offset: $!";
  return $ret;
}

# create a dummy socketpair to try find the offset in the
# kernel structure
socketpair(Rdr, Wtr, AF_UNIX, SOCK_STREAM, PF_UNSPEC)
 or die "socketpair: $!";
$r = readlink("/proc/self/fd/" . fileno(Rdr)) or die "readlink Rdr: $!";
$r =~ /\[(\d+)/; $r = $1;
$w = readlink("/proc/self/fd/" . fileno(Wtr)) or die "readlink Wtr: $!";
$w =~ /\[(\d+)/; $w = $1;
# now $r and $w contain the socket inodes of both ends of the socketpair
die "Can't determine peer offset" unless $r && $w;

# get the inode->address mapping
open U, "<", "/proc/net/unix" or die "open unix: $!";
while (<U>) {
  if (/^([0-9a-f]+):(?:\s+\S+){5}\s+(\d+)/) {
    $addr{$2} = hex $1;
  }
}
close U;

die "Can't determine peer offset" unless $addr{$r} && $addr{$w};

# read 2048 bytes starting at the address of Rdr and hope to find
# the address of Wtr referenced somewhere in there.
$around = readaddr $addr{$r}, 2048;
my $offset = 0;
my $ptr_size = length(pack("L!",0));
my $found;
for (unpack("L!*", $around)) {
  if ($_ == $addr{$w}) {
    $found = 1;
    last;
  }
  $offset += $ptr_size;
}
die "Can't determine peer offset" unless $found;

my %peer;
# now retrieve peer for each socket
for my $inode (keys %addr) {
  $peer{$addr{$inode}} = unpack("L!", readaddr($addr{$inode}+$offset,$ptr_size));
}
close K;

# Now get info about processes tied to sockets using lsof
my (%fields, %proc);
open LSOF, '-|', 'lsof', '-nPUFpcfdn';
while (<LSOF>) {
  if (/(.)(.*)/) {
    $fields{$1} = $2;
    if ($1 eq 'n') {
      $proc{hex($fields{d})}->{"$fields{c},$fields{p}" .
      ($fields{n} =~ m{^([@/].*?)( type=\w+)?$} ? ",$1" : "")} = "";
    }
  }
}
close LSOF;

# and finally process the lsof output
open LSOF, '-|', 'lsof', @ARGV;
while (<LSOF>) {
  chomp;
  for my $addr (/0x[0-9a-f]+/g) {
    $addr = hex $addr;
    my $peer = $peer{$addr};
    if (defined($peer)) {
      $_ .= $peer ?
            sprintf(" -> 0x%x[", $peer) . join("|", keys%{$proc{$peer}}) . "]" :
            "[LISTENING]";
      last;
    }
  }
  print "$_\n";
}
close LSOF or exit(1);
