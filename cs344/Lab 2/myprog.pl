#!/usr/bin/perl -w
use strict;
use warnings;
# Forces a flush after every write or print on the STDOUT
select STDOUT; $| = 1;
# Get the input line by line from the standard input.
# Each line contains an URL and some other information.
while (<>)
{
	my @parts = split;
	my $url = $parts[0];

	#check url is the url we want
	#if yes, redirect the user to the "STOP" sign page
	# if ($url =~ /www\.bbc\.com/) {
	# 	# URL Rewriting
	# 	print "http://upload.wikimedia.org/wikipedia/commons/b/bd/France_road_sign_AB4.svg\n";
	# }

	#if the url with extension of .gif, .jpg, or .png, this means it's an image
	#so we just swap this url with my url, and then the image will also be changed to my image
	if (($url =~ /(.*\.gif)/i) || ($url =~ /(.*\.jpg)/i) || ($url =~ /(.*\.png)/i)) {
		
	print "http://www.cis.syr.edu/~wedu/seed/img/setup_img.png\n";
	}
	else {
		# No Rewriting.
	print "\n";
	}
}