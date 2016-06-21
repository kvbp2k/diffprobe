#!perl -w

use strict;

my $alpha = 0.05;
my $nBOOTSTRAP = 200;
my $minSampleFrac = 0.01;

sub floor {
	my $x = shift;
	return ($x > 0) ? int($x) : int($x)-1;
};
sub rint {
	my $x = shift;
	return floor($x+0.5);
};
sub max {
	return ($_[0] >= $_[1]) ? $_[0] : $_[1];
};
sub min {
	return ($_[0] < $_[1]) ? $_[0] : $_[1];
};
sub maxarr {
	my $ref = shift;
	my @arr = @$ref;
	my @sarr = sort {$a <=> $b} @arr;
	my $ns = @sarr;
	return $sarr[$ns-1];
};
sub minarr {
	my $ref = shift;
	my @arr = @$ref;
	my @sarr = sort {$a <=> $b} @arr;
	my $ns = @sarr;
	return $sarr[0];
};
sub nInRange {
	my $ref = shift;
	my $lval = shift;
	my $uval = shift;
	my @arr = @$ref;
	my $n = @arr;
	my $count = 0;
	for(my $c = 0; $c < $n; $c++)
	{
		$count++ if $arr[$c] >= $lval and $arr[$c] < $uval;
	}
	return $count;
};
sub hist {
	my $ref = shift;
	my $eref = shift;
	my @arr = @$ref;
	my @edges = @$eref;
	my $n = @arr; my $en = @edges;
	my @ret = ();

	for(my $c = 0; $c < $n; $c++)
	{
		my $a = $arr[$c]; my $e = 0;
		for($e = 0; $e < $en-1; $e++)
		{
			$ret[$e] = 0 if !defined $ret[$e];
			if($a >= $edges[$e] and $a < $edges[$e+1])
			{
				$ret[$e]++;
				last;
			}
		}
		$ret[$en-2]++ if $e == $en-1;
	}
	for(my $e = 0; $e < $en; $e++)
	{
		$ret[$e] = 0 if !defined $ret[$e];
		$ret[$e] /= $n;
	}	
	return \@ret;
}

sub splitSample {
	my $ref = shift;
	my @arr = @$ref;
	my $tot = @arr;
	my @arr1 = ();
	my @arr2 = ();

	for(my $n = 0; $n < $tot; $n++)
	{
		if(rand() >= 0.5)
		{
			push(@arr1, $arr[$n]);
		}
		else
		{
			push(@arr2, $arr[$n]);
		}
	}

	return (\@arr1, \@arr2);
};

sub KLDivergence {
	my $pref = shift;
	my $qref = shift;
	my @P = @$pref;
	my @Q = @$qref;
	my $nP = @P;
	my $nQ = @Q;

	my @pq = (@P, @Q);
	my @pqsort = sort {$a <=> $b} @pq;
	my $pqn = @pqsort;
	my $iqr = $pqsort[rint($pqn*0.75)]-$pqsort[rint($pqn*0.25)];

	my $binWidth = 2*$iqr*($pqn**(-1/3));
	my $minSamplesP = max(1, $minSampleFrac*$nP);
	my $minSamplesQ = max(1, $minSampleFrac*$nQ);

	my @newbinEdges = ();
	#push(@newbinEdges, -0xFFFFFFFF);
	push(@newbinEdges, minarr(\@pq));

	my $allDone = 0;
	my $nloops = 0;
	my $sf = 1.0;
	my $sfm = 2.0;
	while(1)
	{
		my $nnb = @newbinEdges;
		push(@newbinEdges, $newbinEdges[$nnb-1]+$binWidth);

		while(1)
		{
			$nloops++;
			$nnb = @newbinEdges;
			my $lval = $newbinEdges[0];
			my $uval = $newbinEdges[$nnb-1];
			my $numP_inRange = nInRange(\@P, $lval, $uval);
			my $numQ_inRange = nInRange(\@Q, $lval, $uval);

			if($numP_inRange >= $nP)
			{
				$allDone = 1;
				last;
			}
			if($numQ_inRange >= $nQ)
			{
				$allDone = 1;
				last;
			}

			$lval = $newbinEdges[$nnb-2];
			$uval = $newbinEdges[$nnb-1];
			my $numP_inBin = nInRange(\@P, $lval, $uval);
			my $numQ_inBin = nInRange(\@Q, $lval, $uval);

			if($numP_inBin < $minSamplesP or 
			   $numQ_inBin < $minSamplesQ)
			{
				$newbinEdges[$nnb-1] += $binWidth*$sf;
				$sf *= $sfm;
				next;
			}
			$sf = 1;
			last;
		}
		last if $allDone == 1;
		$nloops++;
	}
	while(1)
	{
		$nloops++;
		my $nnb = @newbinEdges;
		last if $nnb < 2;
		my $lval = $newbinEdges[$nnb-2];
		my $uval = $newbinEdges[$nnb-1];
		my $numP_inBin = nInRange(\@P, $lval, $uval);
		my $numQ_inBin = nInRange(\@Q, $lval, $uval);

		if($numP_inBin < $minSamplesP or 
			$numQ_inBin < $minSamplesQ)
		{
			$newbinEdges[$nnb-2] = $newbinEdges[$nnb-1];
			pop(@newbinEdges);
		}
		else
		{
			last;
		}
	}
	my $k = @newbinEdges;
	return 0xFFFFFFFF if $k < 3; #TODO

	my $histpref = hist(\@P, \@newbinEdges);
	my @histp = @$histpref;
	my $histqref = hist(\@Q, \@newbinEdges);
	my @histq = @$histqref;

	my @distances = ();
	my $d = 0;
	$k = @histp;
	for(my $c = 0; $c < $k; $c++)
	{
		next if $histp[$c] == 0 or $histq[$c] == 0;
		my $s = $histp[$c]*log($histp[$c]/$histq[$c])/log(2);
		$d += $s;
		push(@distances, $s);
	}

	return $d; #\@distances
};

sub entropytest {
	my $sref = shift;
	my $rref = shift;
	my @S = @$sref;
	my @R = @$rref;

	my $p = 0;
	my $h = 1;

	if(!@S or !@R)
	{
		return ($p, $h);
	}

	srand(time);

	my $maxSample = max(maxarr($sref), maxarr($rref));
	my $minSample = min(minarr($sref), minarr($rref));
	my $range = $maxSample - $minSample;

	my @binEdges = ();
	for(my $c=$minSample; $c <= $maxSample; $c += $range/10.0)
	{
		push(@binEdges, $c);
	}
	push(@binEdges, 0xFFFFFFFF);

	my @KLarr = ();
	for(my $n = 0; $n < $nBOOTSTRAP; $n++)
	{
		my ($s1ref, $s2ref) = splitSample($sref);
		my @s1 = @$s1ref;
		my @s2 = @$s2ref;
		my $kldist1 = KLDivergence(\@s1, \@s2);
		push(@KLarr, $kldist1);#if $kldist1 != -0xFFFFFFFF;
		my $kldist2 = KLDivergence(\@s2, \@s1);
		push(@KLarr, $kldist2);#if $kldist2 != -0xFFFFFFFF;
	}

	my $dist = KLDivergence(\@S, \@R);
	my $kn = @KLarr;
	$p = nInRange(\@KLarr, $dist, 0xFFFFFFFF)/$kn;
	$h = ($p <= $alpha) ? 1 : 0;

	return ($p, $h);
};

1;

