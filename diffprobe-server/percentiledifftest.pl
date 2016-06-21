#!perl -w

use strict;
#use POSIX qw(floor);

my $MIN_PERCENTILE = 0.5;
my $MAX_PERCENTILE = 0.95;


### Kaplan-Meier estimate of ECDF
### we implement this as an 'i/n' CDF
### since the two are the same without censoring.
sub kaplanmeiercdf {
	my $ref = shift;

	my @arr = @$ref;
	my @sarr = sort {$a <=> $b} @arr;
	my $n = @sarr;
	my %cdf = ();

	my $estimate = 1.0;
	for(my $i = 0; $i < $n; $i++)
	{
		$estimate *= ($n - $i - 1)/($n - $i);
		$cdf{$sarr[$i]} = 1 - $estimate;
	}

	return \%cdf;
};

### returns result: 0 unknown, 2 A>P, 1 P>A
### and median difference in MIN_PERCENTILE+'s
sub getpercentilediff {
	my $acdfref = shift;
	my $pcdfref = shift;

	my %acdf = %$acdfref;
	my %pcdf = %$pcdfref;
	my %arev = ();
	my %prev = ();
	foreach my $avalue (keys %acdf)
	{
		$arev{$acdf{$avalue}} = $avalue;
	}
	foreach my $pvalue (keys %pcdf)
	{
		$prev{$pcdf{$pvalue}} = $pvalue;
	}

	my $firstflag = 1;
	my $prevdiff = 0;
	my @diffs = ();

	# assume P flow is higher rate than A
	foreach my $apercentile (sort {$a <=> $b} keys %arev)
	{
		next if $apercentile < $MIN_PERCENTILE or 
			$apercentile > $MAX_PERCENTILE;

		my $prev_ppercentile = 0;
		my $cur_ppercentile = 0;
		foreach my $ppercentile (sort {$a <=> $b} keys %prev)
		{
			$cur_ppercentile = $ppercentile;
			last if $ppercentile > $apercentile;
			$prev_ppercentile = $ppercentile;
		}

		my $pp = ($apercentile - $prev_ppercentile >
			  $cur_ppercentile - $apercentile) ?
	  		  $cur_ppercentile : $prev_ppercentile;
		my $diff = $prev{$pp} - $arev{$apercentile};

		if($firstflag == 0)
		{
			if($prevdiff*$diff < 0)
			{
				#print "unknown\n";
				return (0, -1);
			}
		}
		push(@diffs, $diff);
		$firstflag = 0 if $firstflag == 1;
		$prevdiff = $diff;
	}

	my $mediandiff = abs($diffs[floor(0.5+@diffs/2.0)]);
	return ($prevdiff > 0) ? (1, $mediandiff) #print "P > A\n" 
			       : (2, $mediandiff);#print "A > P\n";
};

sub percentiledifftest {
	my $aref = shift;
	my $pref = shift;

	my $acdfref = kaplanmeiercdf($aref);
	my $pcdfref = kaplanmeiercdf($pref);
	my ($result, $mediandiff) = getpercentilediff($acdfref, $pcdfref);
	return ($result, $mediandiff);
};

1;

