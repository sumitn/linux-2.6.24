#!/usr/bin/perl -w
# a perl script to help debug memory leaks.
# Erez Zadok <ezk@cs.sunysb.edu>, September 2003
#
# How to use:

# 0. change all yuor code so it uses the KMALLOC() and KFREE() macros!
#
# 1. compile your f/s with FIST_MALLOC_DEBUG.
#
# 2. run it without debugging, so you only see the memdebug printk's
#
# 3. when you're done with your test of the file system, unmount it and
#    unload the module: this will flush out a few more things which will
#    result in more kfree's to be called
#
# 4. Collect your log info from where the kernel puts in, usually /var/log/all
#
# 5. run this perl script on the log file: ./match-malloc.pl foo.log

# 6. Investigate each line of output from the script to see if it's really a
#    memory leak, then fix it.
#
# 7. Repeat this procedure until there are no memory leaks.
#

$debug = 0;
$counter = 0;

@bufs = ();

while (($line = <>)) {
    chop $line;
    printf(STDERR "LINE %s\n", $line) if $debug;
    if ($line =~ /KM:(\d+):([^:]+):/) {
	if ($counter + 1 != $1) {
	    printf(STDERR "COUNTER ORDER:%d:%s\n", $counter, $line);
	}
	$counter = $1;
	$addr = $2;
	printf(STDERR "KM ADDR %s\n", $addr) if $debug;
	if (defined($bufs{$addr})) {
	    printf(STDOUT "double alloc: %sr\n", $line);
	} else {
	    $bufs{$addr} = $line;
	}
	next;
    }
    if ($line =~ /KF:(\d+):([^:]+):/) {
	if ($counter + 1 != $1) {
	    printf(STDERR "COUNTER ORDER:%d:%s\n", $counter, $line);
	}
	$counter = $1;
	$addr = $2;
	printf(STDERR "KF ADDR %s\n", $addr) if $debug;
	if (defined($bufs{$addr})) {
	    $bufs{$addr} = undef;
	} else {
	    printf(STDOUT "unallocated free: %s\n", $line);
	}
	next;
    }
    printf(STDERR "SKIP %s\n", $line) if $debug > 1;
}
foreach $buf (keys %bufs) {
    next unless defined($bufs{$buf});
    printf(STDOUT "leaked: %s\n", $bufs{$buf})
}
