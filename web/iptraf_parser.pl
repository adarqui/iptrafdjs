#!/usr/bin/perl
use Data::Dumper;
use Switch;
use Socket;
use Getopt::Long;

%config;
%hash;


# PARSE ARGUMENTS
$config{'condense'} 	= 0;
$config{'onlyip'} 		= 0;
$config{'debug'}		= 0;

# setup debug FH
open(OUT, ">", "/dev/null") or die "[x] Can't open /dev/null\n";
my $out = *OUT;


GetOptions (
	'in=s' => \$config{'in'},
	'out=s' => \$config{'out'},
	'condense' => \$config{'condense'},
	'onlyip' => \$config{'onlyip'},
	'iponly' => \$config{'iponly'},
	'help' => \$config{'help'},
	'h' => \$config{'help'},
	'debug' => \$config{'debug'},
	'd' => \$config{'debug'},
);


if($config{'debug'} > 0) {
	$out = *STDOUT;
}


print $out Dumper(\%config) . "\n";


if($config{'help'} > 0) {
	help();
}
elsif(!$config{'in'}) {
	help("Specify an input file (iptraf log)");
}


sub help {

	if($_){ 
		print
			"
			Specific error			:	$_
			";
	}

	print 
		"[+] Help:
				--in			:	IPTRAF input log file (From iptables -B -i interface)
				--out			:	Output file, stdout by default
				--condense		:	Condense traffic table
				--onlyip		:	Maximum condensed data, only keep track of src/dst ip pairs
				--debug			:	Print out debugging information	
				--help			:	This menu
		";

	exit(0);
}



my @icmp;
my @tcp;
my @udp;

my $input_fh;
open( $input_fh, "<", $config{'in'} ) || die "[x] Can't open iptraf.log: $!";	
my @lines = <$input_fh>;
@data{'raw'} = join('', @lines);

parse_line(@lines);

clean_results();
print_results();


sub compare_ip {
	my $src = $_[0];
	my $dst = $_[1];

	my $ip_src = inet_aton($src);
	my $ip_dst = inet_aton($dst);

	my $ip_src = (unpack "N", $ip_src);
	my $ip_dst = (unpack "N", $ip_dst);

	if($ip_src > $ip_dst) {
		return 1; 
	}
	else {
		return 0;
	}
}

sub parse_line {

	my @array = @_;

	foreach(@array) {

		my @sp = split(' ', $_);

		if(@sp[1] eq "IP") {
			parse_line_pcap(@sp);
		}
		else {
			parse_line_iptraf(@sp);
		}
	}
}


sub parse_line_pcap {
=begin
        1361083134.289546 IP 10.200.1.18.54601 > 10.200.1.1.22: tcp 64
        1361083134.289610 IP 10.200.1.1.22 > 10.200.1.18.54601: tcp 32
        1361083134.291162 IP 10.200.1.18.54601 > 10.200.1.1.22: tcp 0
        1361083137.706761 IP 10.200.1.10.54013 > 10.200.1.1.1514: UDP, length 233
        1361083137.706803 IP 10.200.1.10.54013 > 10.200.1.1.1514: UDP, length 249
        1361083139.709033 IP 10.200.1.10.54013 > 10.200.1.1.1514: UDP, length 257
        1361115505.014528 IP 10.200.1.1 > 10.200.1.6: ICMP echo request, id 3104, seq 4, length 64
        1361115505.041035 IP 10.200.1.6 > 10.200.1.1: ICMP echo reply, id 3104, seq 4, length 64
=end
=cut

	my @sp = @_;

#print Dumper(\@sp);

	$pkt{'bytes'} = @sp[@sp-1];
    $pkt{'src'} = @sp[2];
    $pkt{'dst'} = @sp[4];
    $pkt{'proto'} = uc(@sp[5]);
	$pkt{'proto'} =~ tr/[;:,]//d;

	$pkt{'dst'} =~ tr/[:;]//d;

     if($pkt{'proto'} == "udp" || $pkt{'proto'} == "tcp") {

            @asrcp = split('\.', $pkt{'src'});
            @adstp = split('\.', $pkt{'dst'});

#print Dumper(\@adstp) . $pkt{'src'} . $pkt{'dst'} . @asrcp . @adstp ;
#print $pkt{'src'} . " " . $pkt{'dst'} . ": " . @asrcp . @adstp . "\n";

            $pkt{'sport'} = @asrcp[4];
            $pkt{'dport'} = @adstp[4];

            $pkt{'src'} = @asrcp[0].".".@asrcp[1].".".@asrcp[2].".".@asrcp[3];
            $pkt{'dst'} = @adstp[0].".".@adstp[1].".".@adstp[2].".".@adstp[3];;
        }

	$pkt{'ts'} = @sp[0];

#   print Dumper(\%pkt) . "\n";
    parse_line_obj(%pkt);
}


sub parse_line_iptraf {

=begin
         Sat Feb  9 01:31:58 2013; ICMP; eth0; 76 bytes; from 192.168.1.50 to 68.123.143.121; time excd 
         Sat Feb  9 01:28:28 2013; UDP; eth0; 417 bytes; from 199.193.251.108:53648 to 192.168.1.50:1194 
         Sat Feb  9 01:29:14 2013; TCP; eth0; 84 bytes; from 192.168.1.50:22 to 192.168.1.101:36429; first

         Tue Feb 12 12:46:12 2013; TCP; eth0; 1281 bytes; from 199.193.251.107:80 to 192.168.1.50:54919; FIN sent; 123 packets, 181379 bytes, avg flow rate 1451.00 kbits/s 15 - packets sent * 17 - packet size
         

         Wed Feb 13 01:15:41 2013; TCP; Connection 192.168.56.100:443 to 141.212.121.40:54622 timed out, 0 packets, 0 bytes, avg flow rate 0.00 kbits/s; opposite direction 240 packets, 10320 bytes, avg flow rate 0.00 kbits/s"}]}
         * Wed Feb 13 02:04:09 2013; TCP; Connection 192.168.56.100:403 to 216.152.252.211:63668 timed out, 0 packets, 0 bytes, avg flow rate 0.00 kbits/s; opposite direction 342 packets, 17328 bytes, avg flow rate 0.00 kbits/
         * 6 - Connection
         * 25 - packet bytes
         * 28 - flow
=end
=cut

	my @sp = @_;
	my %pkt;

	$pkt{'bytes'} = @sp[7];
	$pkt{'src'} = @sp[10];
	$pkt{'dst'} = @sp[12];
	$pkt{'proto'} = uc(@sp[5]);

     if($pkt{'proto'} == "udp" || $pkt{'proto'} == "tcp") {

            @asrcp = split(':', $pkt{'src'});
            @adstp = split(':', $pkt{'dst'});

            $pkt{'sport'} = @asrcp[1];
            $pkt{'dport'} = @adstp[1];

            $pkt{'src'} = @asrcp[0];
            $pkt{'dst'} = @adstp[0];
        }

        $pkt{'src'} =~ tr/[:;]//d;
        $pkt{'dst'} =~ tr/[:;]//d;
        $pkt{'sport'} =~ tr/[:;]//d;
        $pkt{'dport'} =~ tr/[:;]//d;

		$pkt{'ts'} = @sp[0];
	
#	print Dumper(\%pkt) . "\n";
	parse_line_obj(%pkt);
}


sub parse_line_obj {

		my (%pkt) = @_;

#print Dumper(\%pkt);

		if($pkt{'proto'} ne 'ICMP' && $pkt{'proto'} ne 'TCP' && $pkt{'proto'} ne 'UDP') { 
			return 0;
		}

		my $cmp = compare_ip($pkt{'src'}, $pkt{'dst'});

		if($cmp < 1) { 
			$left = $pkt{'src'};
			$right = $pkt{'dst'};
			$leftp = $pkt{'sport'};
			$rightp = $pkt{'dport'};
		}
		else {
			$left = $pkt{'dst'};
			$right = $pkt{'src'};
			$leftp = $pkt{'dport'};
			$rightp = $pkt{'sport'};
		}


		$key = $pkt{'proto'} . "," . $left . "," . $leftp . "," .  $right . "," . $rightp;

		my $total_bytes = 0;
		my $first;

		my $hash_elm = $hash{$key};
		if($hash_elm) {

			$total_bytes = $hash{$key}{"total_bytes"} + $pkt{'bytes'};
			$hash{$key}{ "total_bytes" } =  $total_bytes ;
			$hash{$key}{ "ts_e" } = $pkt{'ts'};
		}
		else {
			$hash{$key}{ "total_bytes" } = $pkt{'bytes'};
			$hash{$key}{ "first_source" } = $pkt{'src'};
			$hash{$key}{ "src" } = $pkt{'src'};
			$hash{$key}{ "dst" } = $pkt{'dst'};
			$hash{$key}{ "sport" } = $pkt{'sport'};
			$hash{$key}{ "dport" } = $pkt{'dport'};
			$hash{$key}{ "ts_b" } = $pkt{'ts'};
		}


		$hash{$key}{'proto'} = $pkt{'proto'};

		$tx_to_src = $hash{$key}{"tx_to_src"};
		$tx_to_dst = $hash{$key}{"tx_to_dst"};

		if($pkt{'src'} eq $left) {
			$tx_to_dst = $tx_to_dst + $pkt{'bytes'};
			$hash{$key}{ "tx_to_dst"} = $tx_to_dst ;
		}
		else {
			$tx_to_src = $tx_to_src + $pkt{'bytes'};
			$hash{$key} {"tx_to_src" }= $tx_to_src ;
		}
}

# create unique string hashes of:
#  icmp: src,dst
#  tcp: src,sport,dst,dport
#  udp: src,sport,dst,dport
#
# values of each hash include:
#  bytes=> ...



sub clean_results {

%hash_new;

	foreach $key (keys %hash) {
		my $elm = $hash{$key};

		my @fields = split(',', $key);
		# proto,src,srcport,dst,dstport
		my $first_source = $hash{$key}{"first_source"};

		if($config{'condense'}) {
			if($first_source) {

				if($first_source eq @fields[1]) {
					@fields[2] = '0';
				}
				else {
					@fields[4] = '0';
				}

			}

			my $new_key = join ",", @fields;	

			my $hash_existing = $hash_new{$new_key};
			if($hash_existing) { 
				$hash_new{$new_key}{'total_bytes'} = $hash_new{$new_key}{'total_bytes'} + $hash{$key}{'total_bytes'};
				$hash_new{$new_key}{'tx_to_src'} = $hash_new{$new_key}{'tx_to_src'} + $hash{$key}{'tx_to_src'};
				$hash_new{$new_key}{'tx_to_dst'} = $hash_new{$new_key}{'tx_to_dst'} + $hash{$key}{'tx_to_dst'};
			}
			else {
				$hash_new{$new_key} = $elm;
			}

		}
		elsif ($config{'onlyip'}) {

			@fields[2] = ' ';
			@fields[4] = ' ';

			my $new_key = join ",", @fields;
			$hash_new{$new_key} = $elm;

		}
		else {
			$hash_new{$key} = $elm;
		}
	}

%hash = %hash_new;

}


sub print_results {

#	print Dumper(\%hash);

	foreach $key (keys %hash) {
		my $sport;
		my $dport;
		if($hash{$key}{'proto'} eq "TCP" || $hash{$key}{'proto'} eq "UDP") {
			$sport = "." . $hash{$key}{'sport'} . " ";
			$dport = "." . $hash{$key}{'dport'} . " ";
		}

		# 1361083139.709033 IP 10.200.1.10.54013 > 10.200.1.1.1514: UDP, length 257
		print "$hash{$key}{'ts_b'} IP $hash{$key}{'src'}$sport > $hash{$key}{'dst'}$dport $hash{$key}{'proto'} length $hash{$key}{'total_bytes'}\n";

		if($hash{$key}{'ts_e'}) {
			print "$hash{$key}{'ts_e'} IP $hash{$key}{'src'}$sport > $hash{$key}{'dst'}$dport $hash{$key}{'proto'} length 0\n";
		}
	}
}
