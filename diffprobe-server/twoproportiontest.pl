#!perl -w

use strict;

my $sigma = 0.05;
my $minlost = 10;

sub getproportions {
	my $aref = shift;
	my $pref = shift;
	my $aignored = shift;
	my $pignored = shift;

	my @aarr = @$aref;
	my @parr = @$pref;
	my $an = @aarr;
	my $pn = @parr;

	my $asent = my $psent = 0;
	my $acarry = my $pcarry = 0;
	my $aseq = my $pseq = -1;
	for(my $c = 0; $c < $an; $c++)
	{
		$aseq = $aarr[$c] if $aseq == -1;
		if($aseq - $aarr[$c] > 30000) #wrap-around
		{
			$acarry++;
		}
		$aseq = $aarr[$c];
		$asent = $aseq+65536*$acarry+1 if $asent < $aseq+65536*$acarry+1;
	}
	$asent = $aseq+65536*$acarry+1 if $asent < $aseq+65536*$acarry+1;
	for(my $c = 0; $c < $pn; $c++)
	{
		$pseq = $parr[$c] if $pseq == -1;
		if($pseq - $parr[$c] > 30000) #wrap-around
		{
			$pcarry++;
		}
		$pseq = $parr[$c];
		$psent = $pseq+65536*$pcarry+1 if $psent < $pseq+65536*$pcarry+1;
	}
	$psent = $pseq+65536*$pcarry+1 if $psent < $pseq+65536*$pcarry+1;

	my $arecvd = $an + $aignored;
	my $precvd = $pn + $pignored;
	my $alost = $asent - $arecvd;
	my $plost = $psent - $precvd;
	return ($alost, $asent, $plost, $psent);
};

sub normcdf {
require 'erfc.pl';
	my $x = shift;
	my $mu = 0;
	my $sigma = 1;

	my $z = ($x-$mu)/$sigma;
	my $p = 0.5 * erfc(-$z/sqrt(2));
	return $p;
};

sub proportiontest {
	my $plost = shift;
	my $ptot = shift;
	my $alost = shift;
	my $atot = shift;
	my $p = 1.0;
	my $h = 0;
	my $ret = 0;

	if($alost < $minlost and $plost < $minlost)
	{
		$ret = -1;
		return ($p,$h,$ret);
	}
	if($alost + $plost == $atot + $ptot)
	{
		$ret = -1;
		return ($p,$h,$ret);
	}

	my $pa = $alost/$atot;
	my $pp = $plost/$ptot;

	my $r = ($alost + $plost)/($atot + $ptot);
	my $SE = sqrt($r*(1-$r)*(1.0/$atot+1.0/$ptot));
	my $z = abs(($pa - $pp)/$SE);

	$p = normcdf(-$z) + 1 - normcdf($z);
	$h = ($p <= $sigma) ? 1 : 0;

	return ($p,$h,$ret);
};

sub twoproportiontest {
	my $aref = shift;
	my $pref = shift;
	my $aignored = shift;
	my $pignored = shift;
	my $p = 1.0;
	my $h = 0;
	my $ret = 0;

	my ($alost, $atot, $plost, $ptot) = getproportions($aref, $pref, $aignored, $pignored);
	print "$alost, $atot, $plost, $ptot\n";

	($p,$h,$ret) = proportiontest($plost, $ptot, $alost, $atot);
	return ($p,$h,$ret, $plost, $ptot, $alost, $atot);
};

1;

