#!perl -w

use strict;
require 'pair.pl';
require 'twoproportiontest.pl';

sub lossrun {
require 'pair.pl';
require 'twoproportiontest.pl';
	my $file = shift; #"98.242.68.176.txt"
	my $probetype = shift; #"LIP_AP"
	my $probedir = shift;
	my $trial = shift;
	my $p_port = shift;
	my $a_port = shift;

	# NOTE: this function ignores small (< 6B) payloads,
	# which do not have seq+timestamp set
	my ($loref, $hiref, $loignored, $hiignored) 
		= getarrbyprobe($file, $probetype, $probedir, 
				$trial, $p_port, $a_port);

	my @aarr = @$loref;
	my @parr = @$hiref;
	for(my $c = 0; $c < @aarr; $c++)
	{
		my $line = $aarr[$c];
		my @obj = split(/\s+/, $line);
		$aarr[$c] = $obj[2];
	}
	for(my $c = 0; $c < @parr; $c++)
	{
		my $line = $parr[$c];
		my @obj = split(/\s+/, $line);
		$parr[$c] = $obj[2];
	}

	my ($p, $h, $ret, $plost, $ptot, $alost, $atot) 
		= twoproportiontest(\@aarr, \@parr, $loignored, $hiignored);
	return ($p, $h, $ret, $plost, $ptot, $alost, $atot);
};

sub proportionrun {
require 'twoproportiontest.pl';
	my $plost = shift;
	my $ptot = shift;
	my $alost = shift;
	my $atot = shift;

	my ($p, $h, $ret) = proportiontest($plost, $ptot, $alost, $atot);
	return ($p, $h, $ret);
};

sub pairedlossrun {
require 'pair.pl';
require 'twoproportiontest.pl';
	my $rcvfile = shift; #"98.242.68.176.txt"
	my $probetype = shift; #"LIP_AP"
	my $probedir = shift;
	my $trial = shift;
	my $p_port = shift;
	my $a_port = shift;
	my $sndfile = shift; #.sndts file

	# NOTE: this function ignores small (< 6B) payloads,
	# which do not have seq+timestamp set
	my ($rcvloref, $rcvhiref, $rcvloignored, $rcvhiignored) 
		= getarrbyprobe($rcvfile, $probetype, $probedir, 
				$trial, $p_port, $a_port);
	my ($sndloref, $sndhiref, $sndloignored, $sndhiignored) 
		= getarrbyprobe($sndfile, $probetype, $probedir, 
				$trial, $p_port, $a_port);

	my ($sndpairref) = pair($sndloref, $sndhiref, 0.1); #100ms pairs
	my @sndpairarr = @$sndpairref;
	my $n = @sndpairarr;
	my @sndseqs_A = ();
	my @sndseqs_P = ();

	my %seq_time_A = ();
	my %seq_time_P = ();

	my $acarry = my $pcarry = 0;
	my $aseq = my $pseq = -1;
	for(my $c = 0; $c < $n; $c++)
	{
		my $line = $sndpairarr[$c];
		chomp $line;
		my @obj = split(/\s+/, $line);
		my $as = $obj[1]; my $ps = $obj[3];

		$aseq = $as if $aseq == -1;
		$pseq = $ps if $pseq == -1;
		if($aseq - $as > 30000) #wrap-around
		{
			$acarry++;
		}
		if($pseq - $ps > 30000) #wrap-around
		{
			$pcarry++;
		}
		$aseq = $as;
		$pseq = $ps;

		push(@sndseqs_A, $aseq+65536*$acarry);
		push(@sndseqs_P, $pseq+65536*$pcarry);

		$seq_time_A{$aseq+65536*$acarry} = $obj[0];
		$seq_time_P{$pseq+65536*$pcarry} = $obj[2];
	}

	my @rcvseqs_A = ();
	my @rcvseqs_P = ();
	$acarry = $pcarry = 0;
	$aseq = $pseq = -1;
	my @rcvarr_A = @$rcvloref;
	my @rcvarr_P = @$rcvhiref;
	$n = @rcvarr_A;
	for(my $c = 0; $c < $n; $c++)
	{
		my $line = $rcvarr_A[$c];
		chomp $line;
		my @obj = split(/\s+/, $line);
		my $s = $obj[2];
		$aseq = $s if $aseq == -1;
		if($aseq - $s > 30000) #wrap-around
		{
			$acarry++;
		}
		$aseq = $s;
		push(@rcvseqs_A, $aseq+65536*$acarry);
	}
	$n = @rcvarr_P;
	for(my $c = 0; $c < $n; $c++)
	{
		my $line = $rcvarr_P[$c];
		chomp $line;
		my @obj = split(/\s+/, $line);
		my $s = $obj[2];
		$pseq = $s if $pseq == -1;
		if($pseq - $s > 30000) #wrap-around
		{
			$pcarry++;
		}
		$pseq = $s;
		push(@rcvseqs_P, $pseq+65536*$pcarry);
	}

	my $atot = @sndseqs_A;
	my $ptot = @sndseqs_P;
	my $alost = my $plost = 0;

	$n = @sndseqs_A;
	for(my $c = 0; $c < $n; $c++)
	{
		my $seq = $sndseqs_A[$c];
		if(grep(/^$seq$/, @rcvseqs_A) == 0)
		{
			$alost++;
			print STDERR "A $seq_time_A{$seq}\n";
		}
	}
	$n = @sndseqs_P;
	for(my $c = 0; $c < $n; $c++)
	{
		my $seq = $sndseqs_P[$c];
		if(grep(/^$seq$/, @rcvseqs_P) == 0)
		{
			$plost++;
			print STDERR "P $seq_time_P{$seq}\n";
		}
	}
print "$alost, $atot, $plost, $ptot\n";
	my ($p, $h, $ret) = proportiontest($plost, $ptot, $alost, $atot);
	return ($p, $h, $ret, $plost, $ptot, $alost, $atot);
};

1;

