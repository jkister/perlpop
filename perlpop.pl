#!/usr/local/bin/perl

# perlpop: Copyright 2004 Jeremy Kister
# Released under Perl's Artistic License.
# Function: POP3 server w/ checkpassword compatible authentication
# Author: Jeremy Kister 
#  :set tabstop=3 in vi

use strict;
use IPC::Open3;
use IO::Multiplex;
use IO::Socket::INET;

my %chkpw;
my $DEBUG = $ENV{'DEBUG'} || 0;
my $chid = $ENV{'CHID'} || slowerr("missing CHID environment variable");
my $myname = $ENV{'MYNAME'} || 'perlpop.example.net';
my $ip = $ENV{'LISTEN_IP'} || '0.0.0.0';
if(exists($ENV{'CHKPW_PROG'})){
	$chkpw{pass} = $ENV{'CHKPW_PROG'};
	slowerr("cannot pipe to CHKPW_PROG: $chkpw{pass}") unless(-x $chkpw{pass});
}
my $pwd = $ENV{'PWD_PROG'} || slowerr("missing PWD_PROG environment variable");
if(exists($ENV{'APOP_PROG'})){
	# we'll keep apop separate for now
	$chkpw{apop} = $ENV{'APOP_PROG'};
	slowerr("cannot pipe to APOP_PROG: $chkpw{apop}") unless(-x $chkpw{apop});
}
my $interval = $ENV{'INTERVAL'} || 0;
unless(exists($chkpw{pass}) || exists($chkpw{apop})){
	slowerr("no authentication method available");
}
my %client;

slowerr("cannot pipe to PWD_PROG: $pwd") unless(-x $pwd);
my ($uid,$gid) = (getpwnam($chid))[2,3];
slowerr("cannot get info on CHID \(${chid}\)") unless($uid =~ /^\d+$/ && $gid =~ /^\d+$/);

my $oldsel=select();
select STDOUT;
$| = 1;
select $oldsel;

$SIG{ALRM} = sub {
	while(my($key,$value) = each %{$client{lasttime}}){
		if($value < (time() - ${interval})){
			print "DEBUG: removing lasttime value for $key (${value})\n";
			delete $client{lasttime}{$key};
		}
	}
	alarm(30);
};
alarm(30) if($interval > 0);

print "STARTING SERVER..\n" if($DEBUG);
chdir('/') || slowerr("cannot chdir /: $!");

my $mux = new IO::Multiplex;
my $server = IO::Socket::INET->new(Proto     => 'tcp',
                                   LocalAddr => $ip,
                                   LocalPort => 110,
                                   Listen    => 30,
                                   Reuse     => 1) ||
 slowerr("cannot set up socket: $!");

print "switching to ${uid}/${gid}\n" if($DEBUG);
$! = 0;
$( = $) = $gid;
slowerr("unable to chgid ${chid}: $!") if($!);
$! = 0;
$< = $> = $uid;
slowerr("unable to chuid ${chid}: $!") if($!);

$mux->listen($server);

$mux->set_callback_object(__PACKAGE__);
$mux->loop;

sub mux_connection {
	my $package = shift;
	my $mux = shift;
	my $fh = shift;

	my $peer = $fh->peerhost();
	$client{ip}{$fh} = $peer;
	$client{$peer} ++;

	my $total = $mux->handles;
	if(($total > 20) || ($client{$peer} > 3)){
		$mux->write($fh, "-ERR too many concurrent connections\r\n");
		$mux->shutdown($fh,1);

		print "Disconnected: $peer ([$client{$peer}/3] [${total}/20] connections)\n";
	}else{
		$client{banner}{$fh} = $$ . time() . "\@${myname}";
		$mux->write($fh, "+OK <$client{banner}{$fh}>\r\n");
		$mux->set_timeout($fh, 30);

		print "Connection from: $peer ([$client{$peer}/3] [${total}/20])\n";
	}
}

sub mux_timeout {
	my $package = shift;
	my $mux = shift;
	my $fh = shift;

	$mux->write($fh, "-ERR timeout\r\n");
	$mux->shutdown($fh,1);

	print "$client{ip}{$fh} -> timeout\n" if($DEBUG);
}

sub mux_eof {
   my $package = shift;
   my $mux = shift;
   my $fh = shift;

   $mux->set_timeout($fh, undef);
   print "$client{ip}{$fh} -> eof\n" if($DEBUG);
   $mux->shutdown($fh,1);
}


sub mux_close {
	my $package = shift;
	my $mux = shift;
	my $fh = shift;

	print "$client{ip}{$fh} -> close\n" if($DEBUG);
	$client{$client{ip}{$fh}} --;
  
	if($client{$client{ip}{$fh}} == 0){
		delete $client{$client{ip}{$fh}};
	}
	foreach('user','auth','ip','dele','mark','banner'){
		delete $client{$_}{$fh}
	}
	foreach('size','file'){
		delete $client{msgs}{$_}{$fh}
	}
	$mux->close($fh);
	my @handles = $mux->handles;
	my $total = @handles;
	print "STATUS: [${total}/20]\n";
	if($total > 0){
		foreach my $handle (@handles){
			my $peerhost = $handle->peerhost();
			if($peerhost =~ /^(\d{1,3}\.){3}\d{1,3}$/){
				print "Remaining host: [${peerhost}]\n" if($DEBUG);
			}else{
				# bug in IO::Multiplex ?
				print "Removing rouge handle: [${peerhost}]\n" if($DEBUG);
				$mux->close($handle);
			}
		}
	}
}


sub mux_input {
   my $package = shift;
   my $mux = shift;
   my $fh = shift;
   my $input = shift;

   $mux->set_timeout($fh, undef);
   $mux->set_timeout($fh, 30);
   $$input =~ s{^(.*)\n+}{  } or return;
   chop(my $line = $1);
   $$input = '';

   print "$client{ip}{$fh}: [${line}]\n";
   if(($line =~ /^USER\s(.+)/i) && (! exists($client{auth}{$fh}))){
		$mux->write($fh, "+OK\r\n");
		$client{user}{$fh} = $1;
	}elsif( (! exists($client{auth}{$fh})) &&
	        ((($line =~ /^(PASS)\s(.+)/i) && defined($chkpw{pass})) ||
	         (($line =~ /^(APOP)\s(\S+)\s(\S+)/i)) && exists($chkpw{apop})) ){
		# if client is not already authorized,
		# AND is trying to do PASS <pass> AND server is USER/PASS capable
		# OR is trying to do APOP <name> <digest> AND server is APOP capable
		my $method = lc($1);
		my($pass,$digest);
		if($method eq 'apop'){
			($client{user}{$fh},$digest) = ($2,$3);
		}elsif($method eq 'pass'){
			if(exists($client{user}{$fh})){
				$pass = $2;
			}else{
				$mux->write($fh, "-ERR USER first\r\n");
			}
		}else{
			slowerr("confuzzled \(line: ${line}\)");
		}
		my $pid = open3(\*W, \*R, \*E, "$chkpw{$method} $pwd 3<&0");
		if($pid =~ /^\d+$/){
			if($method eq 'apop'){
				print W "$client{user}{$fh}\0${digest}\0$client{banner}{$fh}\0";
			}else{
				print W "$client{user}{$fh}\0${pass}\0\0";
			}

			close W;
			while(<E>){
				warn $_;
			}
			close E;
			chop(my $maildir=<R>);
			$maildir .= '/Maildir' if($maildir);
			if(defined($maildir)){
				if(-d $maildir){
					my $delta = -1; # if he's never popped recently (or while daemon alive)
					if(exists($client{lasttime}{$client{user}{$fh}})){
						$delta = (time() - $client{lasttime}{$client{user}{$fh}});
						$delta++; #acommodate for a possible skew in clock so not to be overzelous
						print "$client{ip}{$fh} -> last successful POP was $delta seconds ago\n" if($DEBUG);
					}
					if((($interval == 0) || ($delta == -1)) || ($delta >= $interval)){
						# if interval is 0 OR hasnt popped recenty, dont calculate interval checks
						# OR the last time we popped is outside of the interval window
						print "$client{ip}{$fh} -> authentication success\n" if($DEBUG);
						if($interval > 0){
							$client{lasttime}{$client{user}{$fh}} = time();
						}
						$client{auth}{$fh} = $maildir; # says yes, good user + maildir
						delete $client{user}{$fh}; # waste of memory at this point
						delete $client{banner}{$fh}; # free memory
						$mux->write($fh, "+OK\r\n");
					}else{
						print "$client{ip}{$fh} -> disconnecting user for interval violation\n" if($DEBUG);
						$mux->write($fh, "-ERR POP less than once every $interval seconds \(your client POP'd $delta seconds ago\)\r\n");
						$mux->shutdown($fh, 1);
					}
					# used to set $client{lasttime} here, but failed terribly
				}else{
					print "$client{ip}{$fh} -> authentication failure\n" if($DEBUG);
					$mux->write($fh, "-ERR cannot open home dir\r\n");
					$mux->shutdown($fh, 1);
				}
			}else{
				sleep 5; # brute force attacks
				$mux->write($fh, "-ERR authorization failed\r\n");
				$mux->shutdown($fh, 1);
			}
		}else{
			$mux->write($fh, "-ERR could not check password\r\n");
			$mux->shutdown($fh, 1);
		}
	}elsif($line =~ /^QUIT$/i){
		while(my($key,$value) = each %{$client{dele}{$fh}}){
			unlink("$client{auth}{$fh}/${value}") || warn "could not unlink $client{auth}{$fh}/${value}: $!\n";
			if(exists($client{mark}{$fh}{$key})){
				delete $client{mark}{$fh}{$key};
			}
		}
		while(my($key,$value) = each %{$client{mark}{$fh}}){
			my $new = $value;
			$new =~ s#^new/#cur/#;
			$new .= ':2,S';
			rename("$client{auth}{$fh}/${value}","$client{auth}{$fh}/${new}") || warn "cannot rename $value: $!\n";
		}
		$mux->write($fh, "+OK\r\n");
		$mux->shutdown($fh, 1);
	}elsif($line =~ /^NOOP$/i){
		$mux->write($fh, "+OK\r\n");
	}elsif($line =~ /^LIST/i){
		if(exists($client{auth}{$fh})){
			$mux->write($fh, "+OK\r\n");
			getmsgs($fh,$client{auth}{$fh}) unless(exists($client{msgs}{size}{$fh}));
			foreach my $key (sort keys %{$client{msgs}{size}{$fh}}){
				$mux->write($fh, "${key} $client{msgs}{size}{$fh}{$key}\r\n");
			}
			$mux->write($fh, ".\r\n");
		}else{
			$mux->write($fh, "-ERR authorization first\r\n");
		}
	}elsif($line =~ /^RETR\s(\d+)/i){
		my $msg = $1;
		if(exists($client{auth}{$fh})){
			getmsgs($fh,$client{auth}{$fh}) unless(exists($client{msgs}{size}{$fh}));

			if(exists($client{msgs}{file}{$fh}{$msg})){
				if(open(F, "$client{auth}{$fh}/$client{msgs}{file}{$fh}{$msg}")){
					$mux->write($fh, "+OK $client{msgs}{size}{$fh}{$msg} octets\r\n");
					while(<F>){
						chomp;
						$mux->write($fh, "$_\r\n");
					}
					close F;
					$mux->write($fh, ".\r\n");
		
					if($client{msgs}{file}{$fh}{$msg} =~ /^new\//){
						$client{mark}{$fh}{$msg} = $client{msgs}{file}{$fh}{$msg};
					}
				}else{
					$mux->write($fh, "-ERR cannot open message $msg\r\n");
				}
			}else{
				$mux->write($fh, "-ERR no message number $msg\r\n");
			}
		}else{
			$mux->write($fh, "-ERR authorization first\r\n");
		}
	}elsif($line =~ /^STAT$/i){
		if(exists($client{auth}{$fh})){
			getmsgs($fh,$client{auth}{$fh}) unless(exists($client{msgs}{size}{$fh}));
		
			my $total=0;
			my $num=0;
			foreach my $key (keys %{$client{msgs}{size}{$fh}}){
				$num++;
				$total += $client{msgs}{size}{$fh}{$key};
			}
			$mux->write($fh, "+OK ${num} ${total}\r\n");
		}else{
			$mux->write($fh, "-ERR authorization first\r\n");
		}
	}elsif($line =~ /^UIDL(\s(\d+))?/i){
		my $msg = $2;
		if(exists($client{auth}{$fh})){
			getmsgs($fh,$client{auth}{$fh}) unless(exists($client{msgs}{size}{$fh}));
			if(defined($msg)){
				if(exists($client{msgs}{file}{$fh}{$msg})){
					my ($report) = $client{msgs}{file}{$fh}{$msg} =~ /\/([^:]+)/;
					$mux->write($fh, "+OK ${msg} ${report}\r\n");
					$mux->write($fh, ".\r\n");
				}else{
					$mux->write($fh, "-ERR no message number $msg\r\n");
				}
			}else{
				$mux->write($fh, "+OK\r\n");
				foreach my $key (sort keys %{$client{msgs}{file}{$fh}}){
					my ($report) = $client{msgs}{file}{$fh}{$key} =~ /\/([^:]+)/;
					$mux->write($fh, "${key} ${report}\r\n");
				}
				$mux->write($fh, ".\r\n");
			}
		}else{
			$mux->write($fh, "-ERR authorization first\r\n");
		}
	}elsif($line =~ /^DELE\s(\d+)/i){
		my $msg = $1;
		if(exists($client{auth}{$fh})){
			getmsgs($fh,$client{auth}{$fh}) unless(exists($client{msgs}{size}{$fh}));
			if(exists($client{msgs}{file}{$fh}{$msg})){
				$client{dele}{$fh}{$msg} = $client{msgs}{file}{$fh}{$msg};
				delete $client{msgs}{file}{$fh}{$msg};
				delete $client{msgs}{size}{$fh}{$msg};
				$mux->write($fh, "+OK\r\n");
			}else{
				$mux->write($fh, "-ERR no message number $msg\r\n");
			}
		}else{
			$mux->write($fh, "-ERR authorization first\r\n");
		}
	}elsif($line =~ /^RSET$/i){
		delete $client{dele}{$fh};
		$mux->write($fh, "+OK\r\n");
	}elsif($line =~ /^TOP\s(\d+)\s(\d+)/i){
		my($msg,$lines) = ($1,$2);
		if(exists($client{auth}{$fh})){
			getmsgs($fh,$client{auth}{$fh}) unless(exists($client{msgs}{size}{$fh}));
			if(exists($client{msgs}{file}{$fh}{$msg})){
				if(open(F, "$client{auth}{$fh}/$client{msgs}{file}{$fh}{$msg}")){
					my $outofheader=0;
					my $n=0;
					while(<F>){
						chomp;
						if($lines > 0){
							$n++ if(($n > 0) || $outofheader);
							last if ($n == $lines);
							$outofheader = 1 if(/^$/);
						}elsif($lines == 0){
							last if (/^$/);
						}
						$mux->write($fh, "$_\r\n");
					}
					close F;
				}else{
					$mux->write($fh, "-ERR cannot open msg $msg\r\n");
				}
			}else{
				$mux->write($fh, "-ERR no message number $msg\r\n");
			}
		}else{
			$mux->write($fh, "-ERR authorization first\r\n");
		}
	}else{
		$mux->write($fh, "-ERR unimplemented\r\n");
	}
}

sub getmsgs {
	my $fh = shift || die "getmsgs syntax error 0\n";
	my $maildir = shift || die "getmsgs syntax error 1\n";
	my $n = 1;
	foreach my $where ('cur','new'){
		if(opendir(D, "${maildir}/${where}/")){
			foreach my $file (grep {!/^\./} readdir D){
				$client{msgs}{file}{$fh}{$n} = "${where}/${file}";
				$client{msgs}{size}{$fh}{$n} = (stat("${maildir}/${where}/${file}"))[7];
				$n++;
			}
			closedir D;
		}else{
			warn "cannot opendir ${maildir}/${where}: $!\n";
			$mux->write($fh, "-ERR cannot open homedir\r\n");
		}
	}
}

sub slowerr {
	my $err = shift || die "slowerr syntax error\n";
	warn "${err}\n";
	sleep 10;
}
