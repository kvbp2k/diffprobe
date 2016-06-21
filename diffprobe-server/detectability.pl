#!perl -w

use strict;

require 'pair.pl';
require 'entropytest.pl';
require 'percentiledifftest.pl';

### returns h=1 AND diffres=1 if detectable in LIP_P
sub detectiontest {
require 'pair.pl';
require 'entropytest.pl';
require 'percentiledifftest.pl';
	my $file = shift;
	my $probedir = shift; #0 - upstream, 1 - downstream
	my $trial = shift;
	my $p_port = shift;
	my $a_port = shift;

	my ($loref, $hiref) = getarrbyprobe($file, "BLP_P", $probedir, $trial,
						$p_port, $a_port);
	my @aarr_blp = @$loref;
	my ($loref2, $hiref2) = getarrbyprobe($file, "LIP_P", $probedir, $trial,
						$p_port, $a_port);
	my @aarr_lip = @$loref2;
	my $nblp = @aarr_blp;
	my $nlip = @aarr_lip;

	my %blparr = ();
	my %liparr = ();
	my $minblpdelay = my $minlipdelay = 0xFFFFFFFF;
	my $minblpts = my $minlipts = 0;
	my $blpstartts = -1;
	for(my $c = 0; $c < $nblp; $c++)
	{
		my $line = $aarr_blp[$c];
		next if $line =~ /^0\.[0]* /;
		my @obj = split(/\s+/, $line);
		$blparr{$obj[0]} = $obj[1];
		if($minblpdelay > $obj[1])
		{
			$minblpts = $obj[0];
			$minblpdelay = $obj[1];
		}
		$blpstartts = $obj[0] if $blpstartts == -1;
	}
	for(my $c = 0; $c < $nlip; $c++)
	{
		my $line = $aarr_lip[$c];
		next if $line =~ /^0\.[0]* /;
		my @obj = split(/\s+/, $line);
		$liparr{$obj[0]} = $obj[1];
		if($minlipdelay > $obj[1])
		{
			$minlipts = $obj[0];
			$minlipdelay = $obj[1];
		}
	}

	my $slope = ($minlipdelay - $minblpdelay)/($minlipts - $minblpts);

	my @blp = ();
	my @lip = ();
	foreach my $ts (sort {$a <=> $b} keys %blparr)
	{
		my $ydelta = $slope * ($ts - $blpstartts);
		my $owd = $blparr{$ts} - $ydelta;
		push(@blp, $owd);
	}
	foreach my $ts (sort {$a <=> $b} keys %liparr)
	{
		my $ydelta = $slope * ($ts - $blpstartts);
		my $owd = $liparr{$ts} - $ydelta;
		push(@lip, $owd);
	}

	my ($p, $h) = entropytest(\@blp, \@lip);
	my $diffres = my $diff = 0;
	if($h == 1)
	{
		($diffres, $diff) = percentiledifftest(\@blp, \@lip);
	}
	return ($p, $h, $diffres, $diff);
};

sub detectiontest2 {
require 'pair.pl';
require 'entropytest.pl';
require 'percentiledifftest.pl';
	my $file = shift;
	my $probedir = shift; #0 - upstream, 1 - downstream
	my $trial = shift;
	my $p_port = shift;
	my $a_port = shift;

	my ($loref, $hiref) = getarrbyprobe($file, "BLP_P", $probedir, $trial,
						$p_port, $a_port);
	my @aarr_blp = @$loref;
	my ($loref2, $hiref2) = getarrbyprobe($file, "LIP_P", $probedir, $trial,
						$p_port, $a_port);
	my @aarr_lip = @$loref2;
	my $nblp = @aarr_blp;
	my $nlip = @aarr_lip;

	my %blparr = ();
	my %liparr = ();
#	for(my $c = 0; $c < $nblp; $c++)
#	{
#		my $line = $aarr_blp[$c];
#		next if $line =~ /^0\.[0]* /;
#		my @obj = split(/\s+/, $line);
#		push(@blparr, $obj[1]);
#	}
#	for(my $c = 0; $c < $nlip; $c++)
#	{
#		my $line = $aarr_lip[$c];
#		my @obj = split(/\s+/, $line);
#		push(@liparr, $obj[1]);
#	}
	my $minblpdelay = my $minlipdelay = 0xFFFFFFFF;
	my $minblpts = my $minlipts = 0;
	my $blpstartts = -1;
	for(my $c = 0; $c < $nblp; $c++)
	{
		my $line = $aarr_blp[$c];
		next if $line =~ /^0\.[0]* /;
		my @obj = split(/\s+/, $line);
		$blparr{$obj[0]} = $obj[1];
		if($minblpdelay > $obj[1])
		{
			$minblpts = $obj[0];
			$minblpdelay = $obj[1];
		}
		$blpstartts = $obj[0] if $blpstartts == -1;
	}
	for(my $c = 0; $c < $nlip; $c++)
	{
		my $line = $aarr_lip[$c];
		next if $line =~ /^0\.[0]* /;
		my @obj = split(/\s+/, $line);
		$liparr{$obj[0]} = $obj[1];
		if($minlipdelay > $obj[1])
		{
			$minlipts = $obj[0];
			$minlipdelay = $obj[1];
		}
	}
	my $mindelay = ($minblpdelay > $minlipdelay) ? $minlipdelay : $minblpdelay;

	my $slope = ($minlipdelay - $minblpdelay)/($minlipts - $minblpts);

	my @blp = ();
	my @lip = ();
	foreach my $ts (sort {$a <=> $b} keys %blparr)
	{
		my $ydelta = $slope * ($ts - $blpstartts);
		my $owd = $blparr{$ts} - $ydelta;
		push(@blp, $owd);
	}
	foreach my $ts (sort {$a <=> $b} keys %liparr)
	{
		my $ydelta = $slope * ($ts - $blpstartts);
		my $owd = $liparr{$ts} - $ydelta;
		push(@lip, $owd);
	}

	my $blpowd = my $lipowd = 0;
	my $blpcdfref = kaplanmeiercdf(\@blp);
	my $lipcdfref = kaplanmeiercdf(\@lip);

	my %blpcdf = %$blpcdfref;
	my %arev = ();
	foreach my $avalue (keys %blpcdf)
	{
		$arev{$blpcdf{$avalue}} = $avalue;
	}
	my $found = 0;
	my $prevpercentile = 0;
	foreach my $apercentile (sort {$a <=> $b} keys %arev)
	{
		if($found == 1)
		{
			if($apercentile - 0.5 < 0.5 - $prevpercentile)
			{
				$blpowd = $arev{$apercentile};
			}
			else
			{
				$blpowd = $arev{$prevpercentile};
			}
			last;
		}
		if($apercentile > 0.5)
		{
			$prevpercentile = $apercentile;
			$found = 1;
		}
	}

	my %lipcdf = %$lipcdfref;
	%arev = ();
	foreach my $avalue (keys %lipcdf)
	{
		$arev{$lipcdf{$avalue}} = $avalue;
	}
	$found = 0;
	$prevpercentile = 0;
	foreach my $apercentile (sort {$a <=> $b} keys %arev)
	{
		if($found == 1)
		{
			if($apercentile - 0.90 < 0.90 - $prevpercentile)
			{
				$lipowd = $arev{$apercentile};
			}
			else
			{
				$lipowd = $arev{$prevpercentile};
			}
			last;
		}
		if($apercentile > 0.90)
		{
			$prevpercentile = $apercentile;
			$found = 1;
		}
	}

	my $p = 1;
	my $h = 0;
	my $diffres = 0;
	my $diff = $lipowd - $blpowd;
	if($lipowd/$blpowd >= 1.3)
	{
		$p = 0;
		$h = 1;
		$diffres = 1;
	}

	#return ($p, $h, $diffres, $diff);
	return ($lipowd-$mindelay, $blpowd-$mindelay);
};


1;

