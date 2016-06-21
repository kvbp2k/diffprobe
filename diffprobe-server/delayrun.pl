#!perl -w

use strict;
require 'pair.pl';
require 'entropytest.pl';
require 'percentiledifftest.pl';

sub minarrraw {
	my $ref = shift;
	my @arr = @$ref;
	my $min = 0xFFFFFFFF;
	foreach my $str (@arr)
	{
		chomp $str;
		#my @obj = split(/\s+/, $str);
		my $val = $str; #$obj[1];
		$min = $val if $min > $val;
	}
	return $min;
};

sub delayrun {
require 'pair.pl';
require 'entropytest.pl';
require 'percentiledifftest.pl';
	my $file = shift; #"98.242.68.176.txt"
	my $probetype = shift; #"LIP_A"
	my $probedir = shift; #0 - upstream, 1 - downstream
	my $trial = shift;
	my $p_port = shift;
	my $a_port = shift;

	my ($loref, $hiref, $loign, $hiign) 
			= getarrbyprobe($file, $probetype, $probedir, 
					$trial, $p_port, $a_port);
	my ($loref0, $hiref0, $loign0, $hiign0) 
			= getarrbyprobe($file, "BLP_P", $probedir, 
					$trial, $p_port, $a_port);

	my ($pairref) = pair($loref, $hiref, 0.001); #1ms pairs

	my $pmindelay = 0; #min(minarrraw($hiref), minarrraw($hiref0));
	my $amindelay = 0; #min(minarrraw($loref), minarrraw($loref0));

	my @arr = @$pairref;
	my @aarr = ();
	my @parr = ();
	for(my $c = 0; $c < @arr; $c++)
	{
		my $line = $arr[$c];
		my @obj = split(/\s+/, $line);
		push(@aarr, $obj[1]);#if $obj[1] > $amindelay+1;
		push(@parr, $obj[3]);#if $obj[3] > $pmindelay+1;

		#print "$line\n";
	}

	$pmindelay = minarrraw(\@parr);
	$amindelay = minarrraw(\@aarr);
	if(abs($pmindelay-$amindelay) < 1)
	{
		$amindelay = $pmindelay;
	}
	#print "$pmindelay $amindelay\n";

	for(@aarr) { $_ -= $amindelay; }
	for(@parr) { $_ -= $pmindelay; }

	my $diffres = my $diff = 0;
	my ($p, $h) = entropytest(\@aarr, \@parr);
	if($h == 1)
	{
		($diffres, $diff) = percentiledifftest(\@aarr, \@parr);
	}
	return ($p, $h, $diffres, $diff);
};

sub delayrun_wfqsp {
	require 'pair.pl';
	require 'entropytest.pl';
	require 'percentiledifftest.pl';
	my $file = shift; #"98.242.68.176.txt"
	my $probetype = shift; #"LIP_A"
	my $probedir = shift; #0 - upstream, 1 - downstream
	my $trial = shift;
	my $p_port = shift;
	my $a_port = shift;


	my ($loref, $hiref, $loign, $hiign) 
			= getarrbyprobe($file, $probetype, $probedir, 
					$trial, $p_port, $a_port);

	my ($pairref) = pairbydst($loref, $hiref, 0.01); #1ms pairs
	my @arr = @$pairref;
	my @parr = ();
	for(my $c = 0; $c < @arr; $c++)
	{
		my $line = $arr[$c];
		my @obj = split(/\s+/, $line);
		push(@parr, $obj[3]);
	}

	my @sparr = sort {$a <=> $b} @parr;
	print "@sparr\n";
	my $hmed = $sparr[floor(0.5+0.95*@sparr)];
	my $lmed = $sparr[floor(0.5+0.05*@sparr)];
	my $diff = $hmed - $lmed;

	return ($diff);
}

1;

