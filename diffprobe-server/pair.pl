#!perl -w

use strict;

#my $DELAY_THRESH = 0.001; #s

sub tsort {
	my $t1 = $a;
	my $t2 = $b;
	$t1 =~ s/ .*//;
	$t2 =~ s/ .*//;
	return $t1 <=> $t2;
}
sub getarrbyprobe {
	my $file = shift;
	my $probetype = shift;
	my $probedir = shift;
	my $trial = shift;
	my $LOPORT = shift; #P (4321)
	my $HIPORT = shift; #A (4322)

	my @loarr = ();
	my @hiarr = ();
	my $loport = $LOPORT;
	my $hiport = $HIPORT;
	if($probetype =~ /LIP_P/)
	{
		$loport = $HIPORT;
		$hiport = $LOPORT;
	}

	my $loignored = 0;
	my $hiignored = 0;
	my @loarrsort = ();
	my @hiarrsort = ();

	open(IN, $file) or die;
	if($probedir == 1) #downstream
	{
		while(my $line = <IN>)
		{
			last if $line =~ /^### DOWNSTREAM ###$/;
		}
	}
	while(my $line = <IN>)
	{
		last if $line =~ /^### TRIAL $trial ###$/;
	}
	while(my $line = <IN>)
	{
		last if $line =~ /^$probetype$/;
		return (\@loarrsort, \@hiarrsort, $loignored, $hiignored) 
		if $line =~ /^### TRIAL /; #should not happen
	}

	while(my $line = <IN>)
	{
		if($probedir == 0) #upstream
		{
			last if $line =~ /^### DOWNSTREAM ###$/;
		}
		last if $line =~ /^### TRIAL /;

		#last if $line =~ /^[A-Z]/;
		#if($line =~ / -1\.[0]* /)
		#{
		#	$loignored++ if $line =~ /\-$loport$/;
		#	$hiignored++ if $line =~ /\-$hiport$/;
		#	next;
		#}
		if($line =~ / $probetype /)
		{
			if($line =~ /^0\.[0]* /) #TODO: why do we get these?
			{
				$loignored++ if $line =~ /\-$loport$/;
				$hiignored++ if $line =~ /\-$hiport$/;
				next;
			}
			push(@loarr, $line) if $line =~ /\-$loport$/;
			push(@hiarr, $line) if $line =~ /\-$hiport$/;
		}
	}
	close IN;

	@loarrsort = sort tsort @loarr;
	@hiarrsort = sort tsort @hiarr;

	return (\@loarrsort, \@hiarrsort, $loignored, $hiignored);
};


sub pair {
my $lorateref = shift;
my $hirateref = shift;
my $DELAY_THRESH = shift;

my @lorate = @$lorateref;
my $nlo = @lorate;
my @hirate = @$hirateref;
my $nhi = @hirate;

my $chi1 = 0;
my $htime1 = -1;
my $howd1 = -1;
my $chi2 = 0;
my $htime2 = -1;
my $howd2 = -1;

my @pairedarr = ();

for(my $clo = 0; $clo < $nlo; $clo++)
{
	my $lline = $lorate[$clo];
	chomp $lline;
	my @obj = split(/\s+/, $lline);
	my $ltime = $obj[0];
	my $lowd = $obj[1];

	for(my $ct = $chi1; $ct < $nhi; $ct++)
	{
		my $hline = $hirate[$ct];
		chomp $hline;
		my @obj = split(/\s+/, $hline);
		my $htime = $obj[0];
		my $howd = $obj[1];

		if($htime < $ltime)
		{
			$chi1 = $ct;
			$htime1 = $htime;
			$howd1 = $howd;
		}
		else
		{
			$chi2 = $ct;
			$htime2 = $htime;
			$howd2 = $howd;

			#print "$ltime $lowd $htime1 $howd1 $htime2 $howd2\n";
			#my $t1 = ($ltime - $htime1);
			#my $t2 = ($htime2 - $ltime);
			#print "$t1 $t2\n";
			my $ldiff = $ltime - $htime1; my $rdiff = $htime2 - $ltime;
			if($ltime - $htime1 < $htime2 - $ltime)
			{
				if($ltime - $htime1 < $DELAY_THRESH) #ms
				{
					#print "$ltime $lowd $htime1 $howd1\n";
					push(@pairedarr, "$ltime $lowd $htime1 $howd1 diffs:$ldiff $rdiff otherowd:$howd2");
				}
			}
			else
			{
				if($htime2 - $ltime < $DELAY_THRESH) #ms
				{
					#print "$ltime $lowd $htime2 $howd2\n";
					push(@pairedarr, "$ltime $lowd $htime2 $howd2 diffs:$ldiff $rdiff otherowd:$howd1");
				}
			}
			last;
		}
	}
}

return \@pairedarr;
}

sub pairbydst {
my $lorateref = shift;
my $hirateref = shift;
my $DELAY_THRESH = shift;

my @lorate = @$lorateref;
my $nlo = @lorate;
my @hirate = @$hirateref;
my $nhi = @hirate;

my $chi1 = 0;
my $htime1 = -1;
my $howd1 = -1;
my $chi2 = 0;
my $htime2 = -1;
my $howd2 = -1;

my @pairedarr = ();

for(my $clo = 0; $clo < $nlo; $clo++)
{
	my $lline = $lorate[$clo];
	chomp $lline;
	my @obj = split(/\s+/, $lline);
	my $lowd = $obj[1];
	my $ltime = $obj[0] + 1e-3*$lowd;

	for(my $ct = $chi1; $ct < $nhi; $ct++)
	{
		my $hline = $hirate[$ct];
		chomp $hline;
		my @obj = split(/\s+/, $hline);
		my $howd = $obj[1];
		my $htime = $obj[0] + 1e-3*$howd;

		if($htime < $ltime)
		{
			$chi1 = $ct;
			$htime1 = $htime;
			$howd1 = $howd;
		}
		else
		{
			$chi2 = $ct;
			$htime2 = $htime;
			$howd2 = $howd;

			my $ldiff = $ltime - $htime1; my $rdiff = $htime2 - $ltime;
			if($ltime - $htime1 < $htime2 - $ltime)
			{
				if($ltime - $htime1 < $DELAY_THRESH) #ms
				{
					#push(@pairedarr, "$ltime $lowd $htime1 $howd1 diffs:$ldiff $rdiff otherowd:$howd2");
				}
			}
			else
			{
				if($htime2 - $ltime < $DELAY_THRESH) #ms
				{
					push(@pairedarr, "$ltime $lowd $htime2 $howd2 diffs:$ldiff $rdiff otherowd:$howd1");
				}
			}
			last;
		}
	}
}

return \@pairedarr;
}

1;

