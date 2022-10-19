#!/usr/bin/perl
#
# SystemReport.pl    
#
# This script generates a report on the current operating Linux environment
# by dumping informaiton into an html document.
#
# The report described in this script is used to assess host configuration for 
# Unix-based platforms in support of security and systems management assessments.
#
# by: Tom Arnold, Principal
#     PSC
#
# Note: Major change in program structure. Subroutines beginning with DC_ are data 
#       collection routines.
#
# 3b: 	Activation of the -r (report) option
# 3c: 	Setup of the firewall test and preliminary view of resolv.conf and hosts files;
#	   	set -r as default on; enhance outbound network testing; enhance identification
#		of external IP address; several reporting enhancements; update patch management
#		testing; update FIM testing; increase ntp settings detection accuracy
# 3d:	Fix socket failure error; fix yum check-update issue with results; removed die statements
#       from data collection subroutines; fixed unusual race condition with external IP detection
# 3e:	Fix socket race condition from when system is not online
# 3e1:	Fixed performance issue and problem with output phase; resolved issue in nettest when not
#       on network or blocked by firewall
# 3e2:  Fixed several issues: chage not behaving properly, ntp detection for RHEL was missing new components
#       External IP detection raised false positive for system blocked by firewall, last known patch update
#       when date > 90-days ago should be flagged as a fail; and patch detection had invalid string for RHEL
# 3f:	Significant changes and improvements to the detection and evaluation of access controls. Major update to 
#		handling DAC authentication and detection of LDAP/AD integrated environments. Attempt to use heuristics
#		for evaluation of access control requirements. Deterministic detection methods for search of insecure 
#		services. Minor bug fix to resolve array boundaries.
# 3g: 	(1) Minor bug fix on the process show area and array handling.  (2)Improved handling of basic netowrk information
#		for CentOS environment and produce more reasonable messages, instead of blank values on report.
# 3h:   (1) Update for netstat to identify listeners and enhance several elements for reporting, also check listeners
#       for insecure services. (2) Setup new "proxy test": SystemReport get a known page from (e.g.) our website 
#		via HTTP. �If the known page doesn't match what is expected, then we can likely assume that the HTTP 
#		is going through a proxy and possibly returning a 200 page with a message like "This URL is not accessible 
#		through this proxy". (3) Resolved un-initialized value issue from Sun, HP and AIX; (4) various bug fixes;
#       (5) changes to authentication examination and added sshd_conf testing
# 3i	Bug fix for when run with -v option; review of security config permissions to verify that only root has 
#		access to change persmissions on security configurations; added capability to print some file times;  
#       fix yum criteria; add eval statement to ENV calls to prevent crashes on stupid OS versions; change to 
#       stop flagging sftp as an "insecure service or running process"
# 3j	Update with new CSS; fix PAM analysis sections; Fix login.defs section; update to sshd_conf evaluations
#	.1	Bug fix around $snmp variable setting and gethostby name issue
#	.2  Bug fix in the css portion of the report; update copyright
#   .3  Fixed output for local alarm to remove 'die' statements.
#
# 4a   	Establish updated forensic release of SystemReport. Expands the use of lsof, TZ data, and runs in verbose mode; Also, 
#       added enhancements to code line included by linq3 for BSD; added iptables -L -n command as well; Setup Force option to 
#       force program to run regardless who is signed in; setup additional capture of volatile data from system regarding log files 
# 		and location of possible log files. Added header to html = <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
# 4b	Bug fixes for solaris and UNIX. Update to the patch detection for SunOS
# 4c	Bug fixes in the networking area and other enhancements requested by PG. 
# 4c1	Bug fix related to inte-ntoa fail when host dns is blocked and can't resolve name
# 4c2	Bug fix related to solaris and some NIX logname and user. Set verbose as default.
# 4c3	Modifications to fix issues with AIX after testing on AIX platform. Porting to AIX and several smaller changes and fixes
# 4c4	Update to include lvdisplay -m in the linux portion and alter last command to use -i -F flags. Also to review btmp.
#		For remote root access, remove the test and automate findings as these create issues. Added NTP analysis. Included update 
#		to access control section to go after configuration files for RHEL sssd 
# 4c5	Reacted to issue caused by change at paysw.com server that resulted in 400 Bad Request response being generated during
#   	proxy text and network detection. This has been changed to detect any response from the server. Fixed malformed http req.
# 4c6	Fixed sssd detection in CentOS, repaired network detection due to API change at site, updated socket information
# 4c7   Major update in proxy test and network detection. Updated to use proper eval funcitons for error detection to speed up 
#       program and operations. Significant change to network testing error handling and detection.
# 4c8 	Fix issues with mac version, create include option, in forensic mode find and dump all bash_history, add testing for 
#       docker containers, fundamental change of ntp detectiopn, and numerous performance and tuning updates.
# 4c9   Addresses some changes in network testing to correct problems observed in forensic review of results; fixed access accounting
#       on AIX
#
# (c) Copyright 2013, 2014, 2015, 2016, 2017, 2018 PSC   All Rights Reserved
# The use of this tool by customer is licensed and governed by the terms and conditions of
# Client's agreement with PSC.
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
use strict;
use warnings;
use Getopt::Long qw( :config bundling bundling_override ignore_case_always );

#program variables
my $version="4c9";
our ($year, $time);
get_year();

#Global variables
# force set to do report
our $opt_debug=0;
our $opt_help=0;
our $opt_rpt=1;
our $opt_xml_only=0;
our $opt_version=0;
our $opt_verbose=1;
our $opt_short=0;
our $opt_forensic=0;
our $opt_Force=0;
our $opt_include=0;
our $OS;
our $hostname;
our $suFlag=0;
our $onNet=0;  #Flag to tell system report that the subject system is on a network. Set to false
our $ext_IP;
our @users; # populated in the dc_general, this is a list of users on the system, uses sub getUsers
our @userhomes; # populated by getUsers subroutine
our @interactivePW; # populated in the dc_general, this is a list of the /etc/password records for interactive user accts

# Global hashes
our %general;  # General target system data
our %bootloader;  # boot loader information from target system
our %Services;  # Service testing and general
our %InsecServices; # Test for insecure services in service listing
our %Processes; # process show testing
our %batchjobs; # batch job listing
our %logging;  # log and logging routines
our %ntp;  #NTP and time settings
# ntp and chrony flag Identify which is being found in process show
our ($ntpd, $chronyd, $timed);
our %ssh; # settings and configuration control for ssh
our %perms; # permission of critical security files and testing results key is file name and test result is array value
our %accesscontrol;   # Access control information
our %network;       #networking information
our %extProxyTest;  # network app or web proxy test
our %extIPtest;   # network test for external ip
our %extIPwhois;  # NIC information on external IP address
our %nettest_URL;  # network tests of egress rules and host scan
our %nettest_IP;  # network tests of egress rules and host scan
our %FIM;        #  file integrity monitoring information
our %patch;     # patching information
our %packages;  # listing of installed packages
our %include; # listing of data from include files
#our %containers; # listing of data from container files  ## Future use for container analysis

# Define subroutines and major processing

sub get_year {
	# Subroutine to set the year and time
	use Time::Local;
	my @abbr = qw(Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec);
	my @t = localtime(time);
	$year = $t[5];
	$year += 1900;
	$time = $t[3] . " " . $abbr[$t[4]] . " " . $year . " " . $t[2] . ":" . $t[1] . ":" . $t[0];
}

sub getUsers {
	# This subroutine is called by dc_general and puts a list of interactive user accounts from the system into @users
	if ($opt_debug) {print STDOUT "getUsers sub routine called ....\n";}
	my $uid_min=0;
	# @users is defined as a global variable for all for System Report to use
	
	if ($OS =~ m/darwin/i ) { 
		# It's a stupid Mac
		if ($opt_debug) {print STDOUT "inside its a mac portion\n";}
		my @macUsers=`dscl . list /Users UniqueID | grep -v '^_'` or die "Something is wrong with system call : $!\n";
		if ($opt_debug) { print STDOUT "@macUsers"; print STDOUT "\n";}
		foreach my $mu (@macUsers) {
			if ($opt_debug) { print STDOUT "@macUsers"; print STDOUT "\n";}
			my($uname,$uid)=split(/ /,$mu);
			push(@users, $uname);
		}
		
	} else {
		# It's the rest of NIX
		if ( -e "/etc/login.defs" ) {
			if ($opt_debug) { print STDOUT "    Found /etc/login.defs\n";}
			# Set the uid_min variable to know the threshhold of interactive user accounts
			open(my $conf, "< /etc/login.defs") or die "unable to open /etc/login.defs : !$\n";
			while(<$conf>) {
				if ($_ =~ m/^UID_MIN/ ) {
					my $line = $_;
					chomp($line);
					my $head;
					if ($opt_debug) {print STDOUT "Line is $line \n"; }
					($head,$uid_min)=split(/\s+/, $line);
					if ($opt_debug) {print STDOUT "inside read, uid_min is $uid_min\n"; }
				} else {
					next;
				}
			}
			close($conf);
			
		}
	}
	
	if ($opt_debug) { print STDOUT "UID_MIN = $uid_min\n";}
	
	if ($uid_min > 0) {
		# read and populate the array from etc/passwd
		open(my $pw, "< /etc/passwd");
		while(<$pw>) {
            # fix to collect distinct home directories when mounted or changed from defaults
			my($uname,$pw,$uid,$gid,$comment,$uhome,$therest)=split(/:/,$_);
			if ($uid >= $uid_min) {
				# Must be interactive user
				push(@users, $uname);
                push(@userhomes, $uhome);
				push(@interactivePW, $_);
			} else {
				next;
			}
		}
	}
	
	if ($opt_debug) {
		print STDOUT "Listing of Users found by getUsers:\n";
		foreach my $u (@userhomes) {
			print STDOUT "    $u\n";
		}
		print STDOUT ".... getUsers sub routine Finished\n";
	}
	return 0;
}

sub testPerms {
	# Argument is filename and Returns string with test results
	# Test the mode, uid and gid of the file for permission settings
	my $filename = shift;
	if ((!$filename) || (! -e $filename)) {
		return "200 [WARN] Unable to test $filename, does not exist or was not provided in argument\n";
	}
	my $mode = (stat($filename))[2];
	my $uid = (stat($filename))[4];
	my $gid = (stat($filename))[5];

	my $perms = sprintf "%04o", $mode & 07777;
	my ($d,$o,$g,$w);
	$d = substr($perms,0,1);
	$o = substr($perms,1,1);
	$g = substr($perms,2,1);
	$w = substr($perms,3,1);
	# Translation
	# 0 = '---'
	# 1 = '--x'
	# 2 = '-w-'
	# 3 = '-wx'
	# 4 = 'r--'
	# 5 = 'r-x'
	# 6 = 'rw-'
	# 7 = 'rwx'
	# owner
	if ($o =~ m/0/) {$o='---';}
	if ($o =~ m/1/) {$o='--x';}
	if ($o =~ m/2/) {$o='-w-';}
	if ($o =~ m/3/) {$o='-wx';}
	if ($o =~ m/4/) {$o='r--';}
	if ($o =~ m/5/) {$o='r-x';}
	if ($o =~ m/6/) {$o='rw-';}
	if ($o =~ m/7/) {$o='rwx';}
	# group
	if ($g =~ m/0/) {$g='---';}
	if ($g =~ m/1/) {$g='--x';}
	if ($g =~ m/2/) {$g='-w-';}
	if ($g =~ m/3/) {$g='-wx';}
	if ($g =~ m/4/) {$g='r--';}
	if ($g =~ m/5/) {$g='r-x';}
	if ($g =~ m/6/) {$g='rw-';}
	if ($g =~ m/7/) {$g='rwx';}
	# world
	if ($w =~ m/0/) {$w='---';}
	if ($w =~ m/1/) {$w='--x';}
	if ($w =~ m/2/) {$w='-w-';}
	if ($w =~ m/3/) {$w='-wx';}
	if ($w =~ m/4/) {$w='r--';}
	if ($w =~ m/5/) {$w='r-x';}
	if ($w =~ m/6/) {$w='rw-';}
	if ($w =~ m/7/) {$w='rwx';}
	
	my $owner="Unknown UID: $uid";
	my $group="Unknown GID: $gid";
	if (-e '/etc/passwd') {
		open(my $PW, '<', "/etc/passwd");
		while (<$PW>) {
			next if (! m/\:$uid\:/);
			($owner, my $therest) = split(/:/,$_, 2);
		}
		close($PW);
	}
	if (-e '/etc/group') {
		open (my $GR, '<', "/etc/group");
		while (<$GR>){
			next if (! m/\:$gid\:/);
			($group, my $therest) = split(/:/,$_, 2);
		}
		close($GR);
	}
	
	# Analyze results
	my $analysis;
	if (($gid =~ m/^0/) && ($w =~ m/w/)) {$analysis = "400 [FAIL] World writable with GID 0";}
	elsif (($uid =~ m/^0/) && ($w =~ m/w/)) {$analysis = "400 [FAIL] World writable owned by root";}
	elsif ($w =~ m/w/) {$analysis = "200 [FAIL] File is world writable";}
	else {$analysis = "000 [PASS] Permissions on $filename appear to limit write permissions. ACLs may need to be examined"}
	
	
	my $result;
	if ($analysis =~ m/FAIL/) {
		$result= "$analysis<br>Owner($owner) $o : Group($group) $g : World(everyone) $w\n";
	} else {
		$result= "$analysis<br>Owner($owner) $o : Group($group) $g : World(everyone) $w\n";
	}
	return $result;
}
	
sub getFileTimes {
	# Argument is filename and Returns string with test results
	my $filename = shift;
	if ((!$filename) || (! -e $filename)) {
		return "200 [WARN] Unable to test $filename, does not exist or was not provided in argument";
	}
	my($mtime,$atime);
	eval('require Time::gmtime'); # test if gmtime is installed
	if ($@) {
		use Time::localtime;
		$mtime = localtime((stat($filename))[8]);
		$atime = localtime((stat($filename))[9]);
	} else {
		use Time::gmtime;
		$mtime = gmctime((stat($filename))[8]);
		$atime = gmctime((stat($filename))[9]);
		$mtime .= ' UTC';
		$atime .= ' UTC';
	}
	my $result = "$filename Modify time: $mtime :: Access time: $atime";
	return $result;
}

sub by_number {
	if ( $a < $b ) { -1 }
	elsif ( $a > $b ) { 1 }
	else { 0 }
}

sub test_sudo {
	if ($opt_Force) {
		$suFlag=0; # not SU, but force running on any account
	} else {
		# Test for sudo and root login
		if ( $> == 0 ) {
			# Good to go. User has root privilege
			$suFlag=1;
		} else {
			print "User Error: Must run using sudo or as root.  $! \n\n";
			$opt_help = 1; # set help option to kill everything
		}
	}
}

sub version() {
	print STDOUT "SystemReport.pl Version: $version\n\n";
	print STDOUT "(c) Copyright $year Payment Software Company, Inc (d/b/a PSC) All Rights Reserved.\n";
	print STDOUT "The use of this tool by customer is licensed and governed by the terms and conditions of Client's agreement with PSC.\n";
	return 0;
}

sub dumpoptions() {
	print STDOUT "Debug: $opt_debug \n";
	print STDOUT "Help: $opt_help \n";
	print STDOUT "Report: $opt_rpt \n";
	print STDOUT "Version: $opt_version \n";
	print STDOUT "Short report: $opt_short \n";
	print STDOUT "Verbosity: $opt_verbose \n";
	print STDOUT "Forensic Mode: $opt_forensic \n";
	print STDOUT "XML only: $opt_xml_only \n";
	print STDOUT "Force run: $opt_Force \n";
	print STDOUT "Include file: $opt_include\n";
	return 0;
}

sub help() {
	print STDOUT "Usage: sudo $0 -[options]
	This program reads *NIX configuration files and collects 
	configuration file information from systems. Version: $version
	$0 must be run with root privilege. Either use sudo or run as root user. 
	The program will output a XML dump file. If the -r option is selected, 
	the program will use a default CSS present a report. 
	(c) Copyright 2008 - $year PSC   All Rights Reserved
	The use of this tool by customer is licensed and governed by the terms 
	and conditions of Client's agreement with PSC.
	
	Options:
	-d --debug    Print verbose messages during operation. Not for normal 
	              operation.
	-h --help     Print this help output and quit
	-r --report   (default on) This is a report mode and may be useful for a single server
	              Produces report of items examined and may highlight some issues
	-x --xml_only Produces only XML output and no html report
	-s --short    This will run tool in short mode and collect less details on target host
				  Short option is overridden if tool run in forensic mode
	-a --about    This will print information about the program and quit
	   --forensic Run in forensic data gathering mode - activates force mode as well\n
	   --include  Name of file to locate on system, read and include output. This must be
	              the full qualified path of the file, multiple files may be listed separated
	              by commas. Filenames with spaces will need to be properly escaped.\n";
	return 0;
}

sub DC_general() {
	#use Sys::Hostname;  Not supported in Centos 7
	
	if ($opt_debug) {
		print STDOUT "dc_general started .... \n";
		print STDOUT "    get kernel, runlevel, lh, los, lsb startup and fsf data\n";
	}
	my ($kernel, $RunLevel, $LH, $LOS, $lsb, $startup,$fsf);
	my $tmpLH = `hostname`;
	($LH, my $domain1, my $domain2) = split(/\./,$tmpLH);
	if ($opt_debug) { print STDOUT "        \$LH = $LH \n"; }
	chomp($LH);
	$LOS=`uname -s 2>/dev/null`;
	if ($opt_debug) { print STDOUT "        \$LOS = $LOS \n"; }
	chomp($LOS);
	if ($LOS =~ /AIX/) {
		$fsf = `df 2>/dev/null`;
	} else {
		$fsf = `df -h 2>/dev/null`;
	}
	chomp($fsf);
	if ($opt_debug) { print STDOUT "        \$fsf = $fsf \n"; }
	
	$kernel=`uname -a 2>/dev/null`;
	chomp($kernel);
	if ($opt_debug) { print STDOUT "        \$kernel = $kernel \n"; }
	if ($LOS eq "AIX") {  # Update for AIX
		my $rl=`who -r | awk {'print \$3'}`;
		if ($opt_debug) {print STDOUT "Runlevel is AIX level: $rl\n";}
		$RunLevel="$rl";
	} elsif ($LOS =~ m/darwin/i) {
		#This is running on a mac. No runlevel
		my $rl=`who -r | awk {'print \$3'}`;
		if ($opt_debug) {print STDOUT "Runlevel is Mac OSX level: $rl\n";}
		$RunLevel="$rl";
	} else {
		$RunLevel = `who -r | awk {'print \$1 " " \$2'} 2>/dev/null`;
	}
	chomp($RunLevel);
	if ($opt_debug) { print STDOUT "        \$RunLevel = $RunLevel \n"; }
	
	# Get release information if possible
	if ($opt_debug) { print STDOUT "    Get release information\n";}
	if ( -e "/usr/bin/lsb_release" ) {
		if ($opt_debug) { print STDOUT "        Found lsb_release\n";}
		$lsb .= `/usr/bin/lsb_release -a 2>/dev/null`;
		chomp($lsb);
	} elsif ( -f "/etc/redhat-release") {
		if ($opt_debug) { print STDOUT "        Found /etc/redhat-release\n";}
		open (my $RF, "< /etc/redhat-release");
		while(<$RF>){
			$lsb = $_;
		}
		close($RF);
		chomp($lsb);
		if ($opt_debug) { print STDOUT "            /etc/redhat-release says $lsb\n";}
	} elsif ( -e "/usr/bin/showrev") { # Added for unix where lsb_release command does not exist. Showrev in SunOS is similar
		$lsb .= `/usr/bin/showrev 2>/dev/null`;
		chomp($lsb);
	} elsif ( -e "/usr/bin/pkg" ) { # Added for SunOS 11 where lsb_release and showrev do not exist
		$lsb .= `/usr/bin/pkg info kernel 2>/dev/null`;
		chomp($lsb);
	} elsif ( $LOS =~ m/darwin/i ){
		$lsb .= "Model: " . `sysctl hw.model`;
		$lsb .= "Active CPU: " . `sysctl hw.activecpu`;
		$lsb .= `sw_vers`;
		chomp($lsb);
	} elsif ( $LOS =~ m/AIX/i ) {
		$lsb .= "System: $LOS \n";
		$lsb .= "OS Version & Maintenance Level: " . `oslevel -s`;
		if ( -x "/usr/sbin/prtconf" ) {
			$lsb .= `prtconf -c`;
			$lsb .= `prtconf -k`;
			$lsb .= `prtconf -L`;
			$lsb .= `prtconf -m`;
		}
		chomp($lsb);
	}
	
	# Query to find out timezone data
	my $tzdata = `date | awk '{print \$5}' 2>/dev/null`;
	chomp($tzdata);
		
	# get block device output if run with forensic flag
	if ($opt_debug) { print STDOUT "    get block device output if run with forensic flag\n"; }
	my ( $lsblk, $lvd, $mountdata, $logFiles, $logDirs );
	if ($opt_forensic) {
		if ( -e "/bin/lsblk" ) {
			$lsblk = `/bin/lsblk 2>/dev/null`;
			if ($lsblk) { chomp($lsblk); }
		} elsif ( $LOS =~ m/darwin/i ) {
			$lsblk = `diskutil list`;
			if ($lsblk) {chomp($lsblk);}
		}
		# get lvdisplay information if lvdisplay in /sbin
		if ( -e "/sbin/lvdisplay" ) {
			$lvd = `/sbin/lvdisplay -m 2>/dev/null`;
			if ($lvd) { chomp($lvd);}
		}
		# Get current timezone data
		if ($LOS =~ /AIX/) {
			$mountdata = `mount 2>/dev/null`;
		} else {
			$mountdata = `mount -v 2>/dev/null`;
		}
		if ($mountdata) { chomp($mountdata); }
		# Locate and list log files in var/log
		my $logdir = '/var/log';
		opendir( DIR, $logdir);
		while (my $f = readdir(DIR)) {
			next if ($f =~ m/^\./); # don't list any dot files
			if ( -d $f)  { # No directories in this listing
				$logDirs .= $f . "\n";
			} else {
				$logFiles .= $f . "\n";
			}
		}
		closedir(DIR);
		#$logFiles .= `find / -nowarn -type f -iregex '.*/log/.*' -printf '%M %i %p\n\tLast access: %Ac\n\tLast Status Change: %Cc\n\t' 2>/dev/null` ;
		#$logFiles .= `find / -nowarn -type f -iregex '.*\.log' -printf '%M %i %p\n\tLast access: %Ac\n\tLast Status Change: %Cc\n\t'  2>/dev/null` ;
		#$logFiles .= `find / -nowarn -type f -iregex '.*\_log' -printf '%M %i %p\n\tLast access: %Ac\n\tLast Status Change: %Cc\n\t'  2>/dev/null` ;
		#$logDirs = `find / -nowarn -type d -iregex '.*/log/.*' -printf '%M %i %p\n\tLast access: %Ac\n\tLast Status Change: %Cc\n' 2>/dev/null` ;
		if ($logFiles) { chomp($logFiles); }
		if ($logDirs) { chomp($logDirs); }

	}
	
	# Check and get names of startup programs from directories
	if ($opt_debug) { print STDOUT "   Check and get names of startup programs from directories\n ";}
	$startup = "Listing of startup files or configurations found on system. This is a dense listing and must be evaluated by Assessor. \n\n";
	  # using conditional expressions, list everything found
	  if ($LOS =~ m/AIX/) {
	  	if ( -f "/etc/inittab") { # found inittab in AIX
	  		$startup .= "/etc/inittab contents  Startup table\n";
	  		$startup .= "Field descriptions for entries\n";
	  		$startup .= " <ID> : <Runlevel> (default 2) : <Action> : <Script>\n";
			open (my $FP, "< /etc/inittab" ) ;
			while ( <$FP>) {
				next if /^(\s)*$/;
				next if /^:/; # skip comments which stat with a :
				$startup .= $_;
			}
			close ($FP);
		}
	  } elsif ($LOS =~ m/darwin/i ) {
	  	# List out the system startup items
	  	#$startup .= "System Launch Agents:\n" . `ls /System/Library/LaunchAgents` . "\n";
	  	$startup .= "Library Launch Agents: \n" . `ls /Library/LaunchAgents` . "\n";
	  	
	  	# Open directory of names for each user on the system
	  	# foreach user, list the launchagents for when that user logs in
	  	my $userDir = '/Users';
	  	opendir( DIR, $userDir) or die "Unable to open $userDir : $!";
		while (my $f = readdir(DIR)) {
			next if ($f =~ m/^\./); # don't list any dot files
			if ($opt_debug) {print STDOUT "    Launch agtent Users: $f\n"; }
			my $launchagents; 
			if ( -d "/Users/$f/Library/LaunchAgents" ) { $launchagents .= `ls /Users/$f/Library/LaunchAgents`;}
			if ($launchagents) {
				$startup .= "User $f launch agents (Note: These are user accounts that are identified in a directory structure and may not be active users): \n";
				$startup .= $launchagents;
			} else {
				$startup .= "User $f launch agents: \n" . "No launch agents found or defined.\n";
			}
		}
		closedir(DIR);
		if ($startup) {chomp($startup);}
	  } else {
		if ( -f "/etc/initd.conf") {
			$startup .= '/etc/initd.conf contents  Upstart process management daemon\n';
			open (my $FP, "< /etc/initd.conf" ) ;
			while ( <$FP>) {
				next if /^(\s)*$/;
				next if /^#/; # skip comments
				$startup .= $_;
			}
			close ($FP);
		}
		if ( -f "/etc/xinetd.conf") {
			$startup .= '/etc/xinetd.conf contents Extended Internet Service daemon\n';
			open (my $FP, "< /etc/xinetd.conf" ) ;
			while ( <$FP>) {
				next if /^(\s)*$/;
				next if /^#/; # skip comments
				$startup .= $_;
			}
			close ($FP);
		}
		if ( -d "/etc/init.d") {
			$startup .= "/etc/init.d contents:\n";
			my $dir = "/etc/init.d";
			opendir( DIR, $dir);
			#$batchjobs{'cron.daily Directory Listing'} = "Note: this is a listing of named scripts in /etc/cron.daily only. Run $0 with -v for more details \n";
			while (my $f = readdir(DIR)) {
				next if ($f =~ m/^\./); # don't list any dot files
				$startup .= $f . "\n";
			}
			closedir(DIR);
		}
	  }
	$startup .= 'End of startup listing';
	
	# Check for presence of systemctl and list enabled and disabled services
	my $systemctlList;
	my $systemctlUnits;
	my $systemctlSockets;
	my $systemctlJobs;
	if (( -x "/usr/bin/systemctl" ) || ( -x "/bin/systemctl" )) {
		if ($opt_debug) {
			print STDOUT "    found systemctl on platform\n";
			print STDOUT "    running Command string: systemctl -r list-unit-files --no-pager | grep -ai \"abled\"\n";
		}
		$systemctlList = "Command string: systemctl -r list-unit-files --no-pager | grep -ai \"abled\"\n";
		$systemctlList .= `systemctl -r list-unit-files --no-pager | grep -ai "abled"`;
		chomp($systemctlList);
		if ($opt_forensic) { # in forensic mode list units systemd has currently running in memory
			$systemctlUnits = "Command string: systemctl list-units --no-pager \n";
			$systemctlUnits .= `systemctl list-units --no-pager`;
			chomp($systemctlUnits);
			$systemctlSockets = "Command string: systemctl list-sockets --all --show-types --no-pager \n";
			$systemctlSockets .= `systemctl list-sockets --all --show-types --no-pager`;
			chomp($systemctlSockets);
			$systemctlJobs = "Command string: systemctl list-jobs --all --no-pager \n";
			$systemctlJobs .= `systemctl list-jobs --all --no-pager`;
			chomp($systemctlJobs);
		}
	}
	
	# Test for docker (aka. containers ) installation  # Ver 4c8 only will examine linux platforms at this time
	my $docker;
	our $dockerInstalled = 0;  # flag used to aqctivate container testing if true
	if ($LOS =~ m/linux/i) {
		if ($opt_debug) { print STDOUT "Testing for docker containers...\n"; }
		if (( -x "/usr/bin/docker-containerd") || ( -x "/usr/bin/dockerd" )) { # due to CentOS 6 and early 7, removed test for ( -x "/usr/bin/docker" )
			# docker binary found
			if ($opt_debug) { print STDOUT "    Found /usr/bin/dockerd or /usr/bin/docker-containerd installed\n"; }
			# docker installed but test for compliant system
			$docker = "docker found installed. Testing and dumping /etc/default/docker and docker configuration files to confirm this is an actual install\n";
			$dockerInstalled = 1; # docker is clearly installed on this platform
			if ( -f "/etc/default/docker" ) {
				if ($opt_debug) { print STDOUT "    Found /etc/default/docker found\n"; }  
				$docker.= "Reading /etc/default/docker configuration file\n";
				open(my $DF, "< /etc/default/docker");
				while(<$DF>){
					$docker .= $_;
				}
				close($DF);
			} else {
				$docker.= "Reading /etc/default/docker configuration file\n";
				$docker.= "    Unable to read from /etc/default/docker\n";
			}
		} else {
			# none of the above
			$docker.= "(test for /usr/bin/docker) Unable to validate if docker installed on this platform. May require manual verification with system admin to \n check if installed in different location.\n";
		}
		if (-f "/etc/docker") {
			if ($opt_debug) { print STDOUT "    Found /etc/docker found\n"; }
			$docker.= "Reading /etc/docker configuration file \n";
			open(my $DF, "< /etc/docker");
			while(<$DF>){
				$docker .= $_;
			}
			close($DF);
		} else {
			# none of the above
			$docker.= "Reading /etc/docker configuration file \n";
			$docker.= "    The standard configuration file in /etc/docker cannot be found. This will need to be manually checked\n";
		}
		if ($dockerInstalled) {  # only execute if the /etc/default/doccker file is present on the platform (this is where flag is set) Work around for CentOS/RHEL
			$docker.= "docker version check running docker -v 2>/dev/null (If empty, docker may not be fully configured or in use).\n";
			$docker .= `docker -v 2>/dev/null`;
			$docker .= "\n";
			$docker.= "Running docker ps (If empty, docker may not be fully configured or in use). \n";
			$docker .= `docker ps`;
			$docker .= "\n";
		}
	}
	
	my $vpd;
	if ( $LOS =~ m/AIX/i ) {
		if ( -x "/usr/sbin/lscfg" ) {
			$vpd .= "Configuration, diagnostic, and vital product data\n" . `lscfg -vps`;
			chomp($vpd);
		}
	}
		
	%general = (
		Hostname => $LH,
		OS => $LOS,
		Kernel => $kernel,
		RunLevel => $RunLevel,
		MountedFS => $fsf);
		
	if ($lsb) { $general{'Product Release Info'} = $lsb; }
	if ($lsblk) { $general{'BlockLS (lsblk)'} = $lsblk;}
	if ($lvd) { $general{'Logical Volume Map (lvdisplay -m)'} = $lvd; }
	if ($tzdata) { $general{'Time Zone Setting'} = $tzdata;}
	if ($mountdata) { $general{'Mount Data (mount -v)'} = $mountdata;}
	if ($docker) { 
		chomp($docker);
		$general{'Docker Containers'} .= $docker; 
	}
	if ($vpd) { $general{'AIX Vital Product Data'} .= $vpd;  }
	
	if ($logFiles) { $general{'Possible Log Files Found in /var/log'} = $logFiles; }
	if ($logDirs) { $general{'Possible Log Directories Found in /var/log'} = $logDirs; }
	if ($startup) { $general{'Startup services and software'} = $startup; }
	if ($systemctlList) { $general{'systemd list of enabled or disabled services'} =  $systemctlList; }
	if ($systemctlUnits) { $general{'systemd units currently in memory'} = $systemctlUnits; }
	if ($systemctlSockets) { $general{'systemd socket units in current memory'} = $systemctlSockets; }
	if ($systemctlJobs) { $general{'systemd jobs listing'} = $systemctlJobs; }
	
	# set a couple of global variables
	$OS = $general{'OS'};
	$hostname = $general{'Hostname'};
	
	# Create array of interactive user accounts on system if this is forensic mode
	if ($opt_forensic) {
		# in forensic mode, populate the interactive list of user accounts from systems
		getUsers();
	}
	
	# debug output
	if ($opt_debug) {
		print STDOUT "... dc_general completed.\n";
	}
	return 0;
}

sub DC_nettest() {
	# Perform security testing
	# Fetch local IP addresses
	use IO::Socket;
	
	if ($opt_debug) {
		print STDOUT "dc_nettest started .... \n";
	}
	
	# Test for presence of outbound Application Control or proxy server using paysw.com as target
	my $proxyPresent; # flag for presence of websense or proxy server
	my $url = 'www.paysw.com';  # Primary test site     # changed to use google
	#my $url = 'www.google.com';  # Alternative site
	
	# Run test on host URL
	undef $@;
	alarm(0);
	
	# Set a default value for the response array that there is no outbound connection
	$extProxyTest{'Application or Web proxy'} = "000 [PASS] Unable to reach outside IP Address or detect presence of outbound proxy.";
	my $evStatus;
	
	# Test for IO::Socket::SSL. If present, run proxy test. 
	eval "use IO::Socket::SSL";
	if ($@) {
		# no capability for use of SSL; Just test if on-line
		# Set the output
		$extProxyTest{'Application or Web proxy'} = "200 [WARN] Unable to test for outbound proxy given support for perl SLL not found";
		if ($opt_debug) {print STDOUT "... IO:Socket::SSL module not found. Just checking for connectivity.\n";}
		$evStatus = eval {   # Added alarm for disconnected system and trap if socket cannot be opened
			local $SIG{ALRM} = sub { print STDOUT "Time out Alarm in outbound network connection test and firewall verification. \n"};
			alarm 1;
			my $sock = new IO::Socket::INET (
				PeerHost => $url, 
				# Use straight http
				PeerPort => 80, 
				) or die "Alarm: Unable to open external socket connection. System may be offline or blocked by ACL. QSA may manually test for external connection capability from this host.\n";
			if ( $sock ) {
				$sock->autoflush();
				printf $sock ("GET / HTTP/1.1\r\n");
				printf $sock ("Host: $url\r\n");
				printf $sock ("Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8 \r\n");
				printf $sock ("User-Agent: PSC_SystemReport/4\r\n");
				printf $sock ("Connection: close\r\n");
				printf $sock ("\r\n\r\n");
				$sock->autoflush();
				my ($two, $three, $four);
				my $psc; #flags for test
				#if ($opt_debug) { print STDOUT "Reading from socket:\n"; }
				while (<$sock>) {
					my $line = $_;
					#if ($opt_debug) { print STDOUT "$line\n"; }
					if ($line =~ m/200 OK/) {$two = 1;}
					if ($line =~ m/30[0-5] /) {$three = 1; }
					if ($line =~ m/40[0-5] Bad/) {$four = 1; }
					if (($line =~ m/Payment Software/) || (($line =~ m/meta content=/))) {
						$psc = 1;
						last;
					}
				}
				$sock->close();
				alarm(0);
				
				if (($two) && ($psc)) {
					$onNet=1; # This is  an on-line system with access to outside world
				} 
				
				if (($two) && (!$psc)) {
					$onNet=1; # This is  an on-line system with access to outside world
				}
				if (($three) && ($psc)) {
					$onNet=1; # This is  an on-line system with access to outside world
				} 
				
				if (($three) && (!$psc)) {
					$onNet=1; # This is  an on-line system with access to outside world
				}
				if (($four) && ($psc)) {
					$onNet=1; # This is  an on-line system with access to outside world
				} 
				
				if (($four) && (!$psc)) {
					$onNet=1; # This is  an on-line system with access to outside world
				}
				if ((!$two) && (!$three) && (!$four)) {
					if ($opt_debug) {
						print STDOUT "Inside not two, three, or four\n";
						print STDOUT "    Value of \$two: $two\n";
						print STDOUT "    Value of \$three: $three\n";
						print STDOUT "    Value of \$four: $four\n";
					}
					$onNet=0; # System is not able to reach the internet
				}
				if ($opt_debug) { print STDOUT "Value for onNet after proxy test, before alarm evaluation: $onNet \n"; }
			}
		}
	} else {
		# Found IO::Socket::SSL -- Setup and try to open SSL socket
		$evStatus = eval {   # Added alarm for disconnected system and trap if socket cannot be opened
			if ($opt_debug) {print STDOUT "...Inside first eval testing for internet proxy.\n";}
			local $SIG{ALRM} = sub { print STDOUT "Time out Alarm in outbound network connection test and firewall verification. \n"};
			alarm 1;
			my $sock = new IO::Socket::SSL (
				PeerHost => $url, 
				PeerPort => "https", 
				#Proto => tcp,
				) or die "Alarm: Unable to open external socket connection. System may be offline or blocked by ACL. QSA may manually test for external connection capability from this host.\n";
			if ( $sock ) {
				$sock->autoflush();
				printf $sock ("GET / HTTP/1.1\r\n");
				printf $sock ("Host: $url\r\n");
				printf $sock ("Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8 \r\n");
				printf $sock ("User-Agent: PSC_SystemReport/4\r\n");
				printf $sock ("Connection: close\r\n");
				printf $sock ("\r\n\r\n");
				$sock->autoflush();
				my ($two, $three, $four);
				my $psc; #flags for test
				#if ($opt_debug) { print STDOUT "Reading from socket:\n"; }
				while (<$sock>) {
					my $line = $_;
					#if ($opt_debug) { print STDOUT "$line\n"; }
					if ($line =~ m/200 OK/) {$two = 1;}
					if ($line =~ m/30[0-5] /) {$three = 1; }
					if ($line =~ m/40[0-5] Bad/) {$four = 1; }
					if (($line =~ m/Payment Software/) || (($line =~ m/meta content=/) && ($line =~ m/Google/i))) {
						$psc = 1;
						last;
					}
				}
				$sock->close();
				alarm(0);
				
				if (($two) && ($psc)) {
					# No proxy, reached PSC
					$extProxyTest{'Application or Web proxy'} = "000 [PASS] No app or web proxy detected. Received 200 OK with magic from $url. Outside network access is still available to this host.";
					$onNet=1; # This is  an on-line system with access to outside world
					if ( $opt_debug ) { print STDOUT "Good & Magic: onNet = $onNet\n"; }
				} 
				
				if (($two) && (!$psc)) {
					$extProxyTest{'Application or Web proxy'} = "200 [WARN] An oubound proxy may have responded. 200 OK received but no magic from $url server. Outside network access is still available to this host.";
					$onNet=1; # This system reached the outside world
					if ( $opt_debug ) { print STDOUT "Good & No Magic: onNet = $onNet\n"; }
				}
				if (($three) && ($psc)) {
					# No proxy, reached PSC
					$extProxyTest{'Application or Web proxy'} = "000 [PASS] No app or web proxy detected. Received 3XX (redirect) detected with magic from $url. Outside network access is still available to this host.";
					$onNet=1; # This system reached the outside world
					if ( $opt_debug ) { print STDOUT "Good & No Magic: onNet = $onNet\n"; }
				} 
				
				if (($three) && (!$psc)) {
					$extProxyTest{'Application or Web proxy'} = "200 [WARN] An oubound proxy may have responded. 3XX (redirect) detected but no magic from $url server. Outside network access is still available to this host";
					$onNet=1; # This system reached the outside world
					if ( $opt_debug ) { print STDOUT "Good & No Magic: onNet = $onNet\n"; }
				}
				if (($four) && ($psc)) {
					# No proxy, reached PSC
					$extProxyTest{'Application or Web proxy'} = "200 [WARN] No app or web proxy detected. Received 4XX (bad request) from target server detected with magic from $url. Outside network access is still available to this host";
					$onNet=1; # This system reached the outside world
					if ( $opt_debug ) { print STDOUT "Good & No Magic: onNet = $onNet\n"; }
				} 
				
				if (($four) && (!$psc)) {
					$extProxyTest{'Application or Web proxy'} = "200 [WARN] An oubound proxy may have responded. 4XX (bad request) from target server detected but no magic from $url server. Outside network access is still available to this host.";
					$onNet=1; # This system reached the outside world
					if ( $opt_debug ) { print STDOUT "Good & No Magic: onNet = $onNet\n"; }
				}
				if ((!$two) && (!$three) && (!$four)) {
					if ($opt_debug) {
						print STDOUT "Inside not two, three, or four\n";
						print STDOUT "    Value of \$two: $two\n";
						print STDOUT "    Value of \$three: $three\n";
						print STDOUT "    Value of \$four: $four\n";
					}
					$extProxyTest{'Application or Web proxy'} = "000 [PASS] Unable to reach outside IP Address or detect presence of outbound proxy.";
					$onNet=0; # System is not able to reach the internet
					if ( $opt_debug ) { print STDOUT "No Good & No  Magic: onNet = $onNet\n"; }
				}
				if ($opt_debug) { print STDOUT "Value for onNet after SSL proxy test, before alarm evaluation: $onNet \n"; }
			}
		};  # end eval statement
		
		if ($evStatus) {
			if ($evStatus =~ m/Alarm/i ) { #an alarm has timed out on external IP detection. let's do something and get out of here
				$extProxyTest{'Application or Web proxy'} = "000 [PASS] $evStatus";
				# if ($opt_debug) {print STDOUT "Inside proxy test timeout alarm\n";}
				$onNet=0; # System is not able to reach the outside world
			}
		} elsif ($@) {  # Error condition but evstatus not set.... Possible timeout
			if ($@ =~ m/Alarm/) {
				$extProxyTest{'Application or Web proxy'} = "000 [PASS] $@";
				# if ($opt_debug) {print STDOUT "Inside proxy test timeout alarm\n";}
				$onNet=0; # System is not able to reach the outside world
			}
		}
	} # test for IO::Socket::SSL
	
	if ($opt_debug) {
		# print STDOUT "...Proxy test:  $extProxyTest{'Application or Web proxy'}\n";
		print STDOUT "...Value of \$onNet: $onNet \n";
	}
	alarm(0); # Added to avoid race condition
	
	if ( $onNet > 0 ) { # System can get to the outside network so do the test

		$url = 'www.ip-adress.eu';
		# $url = 'ipaddress.com' ## no longer working and only supporting https connections
		# $url = 'testip.edpsciences.org';  # Uses redirect to SSL for site. Changed 5-10-17. Does not speak the truith
		# my $ext_IP;  # note: Reset to a global value so that yum check-updates can be optimized
		if ($evStatus) {
			undef $evStatus;   # prepare for timer and timeout conditions
		}
		# Run test on host URL
		
		# try dig before going to outside address
		if (( -e "/usr/bin/dig") || (-e "/bin/dig") || (-e "/usr/sbin/dig") || ( -e "/sbin/dig")) {  
			my $dig_result = `dig +short myip.opendns.com \@resolver1.opendns.com 2>/dev/null`;
			chomp($dig_result);
			if ( $dig_result =~ /\b(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/ ) {
				$ext_IP = $dig_result;
				if ($opt_debug) { print STDOUT "Dig found external IP is: $ext_IP\n"; }
			}
			
		} elsif ( ! $ext_IP) {
		
			$evStatus = eval {   # Added alarm for disconnected system
				if ($opt_debug) {print STDOUT "...Inside second eval working to find external IP address.\n";}
				local $SIG{ALRM} = sub { print STDOUT "...Time out alarm external IP test on host URL\n"};
				alarm(2);
				my $sock = new IO::Socket::INET (
					PeerAddr => $url, 
					PeerPort => 'http(80)', 
					Proto => 'tcp',
					) or die "Alarm: Unable to open socket for external for external IP identification";
				if ( $sock ) {
					printf $sock ("GET / HTTP/1.1\r\n");
					printf $sock ("Host: $url\r\n");
					printf $sock ("Accept: */*\r\n");
					printf $sock ("User-Agent: PSC-SystemReport/$version\r\n");
					printf $sock ("Connection: keepalive\r\n");
					printf $sock ("\r\n\r\n");
					$sock->autoflush();
					while (<$sock>) {
						#next if ($_ !~ m/My IP/);  # the line starts with the text "My IP", throw all else away # causes API change problem find IP and do last command - TA 12-26-17
						if ( $_ =~ /\b(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/ ) {
							$ext_IP = $&;
							if ($opt_debug) { print STDOUT " External IP is: $ext_IP\n"; }
							last;
						}
						
						if (( $_ =~ /50[0-4]/)|| ( $_ =~ /40[0-5]/)) {
							#if ($opt_debug) { print STDOUT "200 [WARN] Network server for IP detection reports $_.\n"; }
							$extIPtest{'External IP Address detection'} = "200 [WARN] Network server for IP detection reports $_. Must be manually validated by Assessor.\n"; 
							last;
						}
					}
					$sock->close();
					
					alarm(0);
				} else {
					# no outside IP connection. Unable to open either socket and detected within timer. Let's get out of here
					$extIPtest{'External IP Address detection'} = "000 [WARN] No external IP Address identified or unable to detect. QSA should manually validate";
					# Setup passing site results
					if ($opt_debug) { print STDOUT "No external IP's"; }
					my @tmp_site = ("www.bankofengland.co.uk",
						"www.google.com",
						"www.cbr.ru",
						"www.symantec.com",
						"www.mcafee.com",
						"www.microsoft.com",
						"windowsupdate.microsoft.com",
						"msdn.microsoft.com",
						"www.kaspersky.com",
						"us.archive.ubuntu.com",
						"mirrors.fedoraproject.org",
						"www.oracle.com",
						"www.facebook.com");
					foreach my $s (@tmp_site) {
						$nettest_URL{$s}="000 [PASS] Unable to connect from this server.";
					}
					$nettest_IP{'Arbitrary IP Connection'}="000 [PASS] Unable to connect to arbitrary IP address on Public Internet.";
					$nettest_URL{'Arbitrary URL Connection'}="000 [PASS] Unable to connect to arbitrary URL on Public Internet.";
					alarm(0);
					
					return 0; # exit this subroutine
				}
			}; #eval statement
		
		}
	}
	
	if ($ext_IP) {
		$onNet=1; # set the onNet flag to true that system is on a network
		# External IP Address found. Set for failure and collect whois data on connection
		$extIPtest{'External IP Address detection'} = "200 [FAIL] External IP Address identified: $ext_IP";
		my $output_APNIC;
		my $output_ARIN;

		# Test APNIC to get whois data on external IP
		my $EOL = "\015\012"; # Special for APNIC
		my $blank = $EOL x 2;  #Terminater for APNIC
		$url = 'whois.apnic.net';
		if ($opt_debug) {print STDOUT "    ...External IP found: $ext_IP. Going to Apnic for report info.\n";}
		undef $evStatus;
		
		my $evStatus = eval {   # Added alarm for disconnected system
			if ($opt_debug) {print STDOUT "...Inside eval query to apnic.\n";}
			local $SIG{ALRM} = sub { print STDOUT "Alarm in APNIC results\n"};
			alarm(2);
			my $sock = new IO::Socket::INET (PeerAddr => $url, PeerPort => 43, Proto => 'tcp') or die "Alarm: Unable to open socket for APNIC test";
			if ( !$sock ) {
				$extIPwhois{'APNIC Results'} = "Whois APNIC $ext_IP: 000 Unable to open socket connection.\n";
			} else {
				$sock->autoflush();
	
				printf $sock ("$ext_IP $blank");
				$sock->autoflush();
	
				while (<$sock>) {
					$output_APNIC .= $_;
				}
			
				if ($output_APNIC ){					
					$extIPwhois{'APNIC Results'} = "200 [FAIL] Connected to APNIC and returned following results\n" . $output_APNIC;
				} else {
					$extIPwhois{'APNIC Results'} = "200 [FAIL] Attempt to connect to APNIC seems to have succeeded. No data returned.\n";
				}
				$sock->close();
				alarm(0);
			}
		}; # End of eval statement
		alarm(0); #avoid race condition
		
		if ($evStatus =~ m/Alarm/i ) { #an alarm has timed out on external IP detection. let's do something and get out of here
			$extIPwhois{'APNIC Results'} = "200 [WARN] $evStatus\n" 
		}
		
		# Test ARIN to get whois data on external IP
		$url = 'whois.arin.net';
		if ($opt_debug) {print STDOUT "    ...External IP found. Going to ARIN for report info.\n";}
		
		undef $evStatus;
		$evStatus = eval {   # Added alarm for disconnected system
			if ($opt_debug) {print STDOUT "...Inside eval query to apnic.\n";}
			local $SIG{ALRM} = sub { print STDOUT "Alarm in ARIN whois check\n"};
			alarm(15);
			my $sock = new IO::Socket::INET (PeerAddr => $url, PeerPort => 43, Proto => 'tcp') or die "Alarm: Unable to open socket for ARIN test";
			if ( !$sock ) {
				$extIPwhois{'ARIN Results'} =  "Whois ARIN $ext_IP: 000 [PASS] Unable to open socket connection.\n";
			} else {
				$sock->autoflush();
	
				printf $sock ("$ext_IP \r\n");
				$sock->autoflush();
	
				while (<$sock>) {
					$output_ARIN .= $_;
				}
				if ($output_ARIN) {
					$extIPwhois{'ARIN Results'} = "200 [FAIL] Connected to ARIN and returned following results \n" . $output_ARIN;
				} else {
					$extIPwhois{'ARIN Results'} = "200 [FAIL] Attempt to connect to APNIC seems to have succeeded. No data returned.\n";
				}
				$sock->close();
				alarm(0); 
			}
		}; # End of eval statement
		alarm(0); #avoid race condition
		
		if ($evStatus =~ m/Alarm/i ) { #an alarm has timed out on external IP detection. let's do something and get out of here
			$extIPwhois{'ARIN Results'} = "100 [INFO] $evStatus\n" 
		}
	}

	if ($ext_IP) {	# This is not optimal ... inet_ntoa will fail hard if gethostbyname returns scalar 0
		if ($opt_debug) {print STDOUT "...Testing firewall filters on URL.\n";}
		# Test for outboud connections
		my @site = ("www.bankofengland.co.uk",
			"www.google.com",
			"www.cbr.ru",
			"www.symantec.com",
			"www.mcafee.com",
			"www.microsoft.com",
			"us.archive.ubuntu.com",
			"mirrors.fedoraproject.org",
			"www.oracle.com",
			"www.facebook.com");

		my %siteIP;
	
		foreach my $si (@site) {
     	  my $r = scalar gethostbyname($si) or do {
     	  	if ($opt_debug) {print STDOUT "... gethostbyname failed. Setting warninings and moving on.\n";}
     	  	$nettest_IP{'Arbitrary IP Connection'}="200 [WARN] Unable to resolve DNS name for IP address. DNS possibly blocked. QSA should examine firewall rules and whether this system is appropriately protected.";
			$nettest_URL{'Arbitrary URL Connection'}="200 [WARN] Unable to connect to arbitrary URL on Public Internet. DNS possibly blocked. QSA should examine firewall rules and whether this system is appropriately protected.";
			return 0; # exit this entire subroutine
     	  };
     	  # Problem. Test that value for $r exist and is not zero
     	  if (($r) || ($r !~ m/0/)) {
     	  	$siteIP{$si} = inet_ntoa($r);
     	  }
      
		}
			
		foreach my $s (keys %siteIP) {
			my $IP = $siteIP{$s};
			my $site_Key = "$s :: $siteIP{$s}";   # Clean reference for report
			chomp($site_Key);
			# my $failed = 0; #flag to fail transactions
			# Run test on host URL
			my $sock = new IO::Socket::INET (PeerAddr => $s, PeerPort => 80, Proto => 'tcp');
			if ( !$sock ) {
				$nettest_URL{$site_Key}="000 [PASS] Unable to connect from this server.";
				next;
			}
			printf $sock ("GET / HTTP/1.0\r\n");
			printf $sock ("Host: $s\r\n");
			printf $sock ("Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n");
			printf $sock ("User-Agent: PSC-SystemReport/$version\r\n");
			printf $sock ("Connection: keepalive\r\n");
			printf $sock ("\r\n\r\n");
			$sock->autoflush();
			while (<$sock>) {
				if(($_=~ m/200 OK/i) || ($_=~ m/301 Moved/i) || ($_=~ m/302 Found/i)) {
					$nettest_URL{$site_Key}="400 [FAIL] Outside URL reached. Responded with 200 or redirct.";
					last;
				} elsif (( $_ =~ /50[0-4]/)|| ( $_ =~ /40[0-5]/)) {
					# if ($opt_debug) { print STDOUT "200 [FAIL] Network server responded with $_. Site is reachable.\n"; }
					$nettest_URL{$site_Key}="200 [FAIL] Network server for IP detection reports $_."; 
					last;
				} else {
					$nettest_URL{$site_Key}="200 [WARN] Site may be reachable. Should be manually validated by Assessor";
				}
			}
			$sock->close();
		
			# Run test on IP address
			#if ($opt_debug) {print STDOUT "...Testing firewall filters on External IP addresses.\n";}
			my $sock2 = new IO::Socket::INET (PeerAddr => $IP, PeerPort => 80, Proto => 'tcp');
			if ( !$sock2 ) {
				$nettest_IP{$site_Key}="000 [PASS} Unable to open socket connection from this server to $IP. Network connection may not be available.";
				next;
			}
			printf $sock2 ("GET / HTTP/1.0\r\n");
			printf $sock2 ("Host: $IP \r\n");
			printf $sock2 ("Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n");
			printf $sock2 ("User-Agent: PSC-SystemReport/$version\r\n");
			printf $sock2 ("Connection: keepalive\r\n");
			printf $sock2 ("\r\n\r\n");
			$sock2->autoflush();
			while (<$sock2>) {
				if(($_=~ m/200 OK/i) || ($_=~ m/301 Moved/i) || ($_=~ m/302 Found/i)) {
					$nettest_IP{$site_Key}="400 [FAIL] Outside IP address reached. $IP responded with 200 or redirct.";
					last;
				} elsif (( $_ =~ /50[0-4]/)|| ( $_ =~ /40[0-5]/)) {
					#if ($opt_debug) { print STDOUT "200 [FAIL] Network server responded with $_. Site is reachable.\n"; }
					$nettest_IP{$site_Key}="200 [FAIL] Network server for IP detection reports $_."; 
					last;
				} else {
					$nettest_IP{$site_Key}="200 [WARN] Site may be reachable. Should be manually validated by Assessor";
				}
			}
			$sock2->close();
		}
	} else {     # end of having public IP address available
		$nettest_IP{'Arbitrary IP Connection'}="000 [PASS] Unable to connect to arbitrary IP address on Public Internet.";
		$nettest_URL{'Arbitrary URL Connection'}="000 [PASS] Unable to connect to arbitrary URL on Public Internet.";
	}
	
	if ($opt_debug) {
		print STDOUT "Finished Nettest\n";
	}
	
	return 0;
	
}
		
sub DC_bootloader() {
	#future
	#%bootloader = (
	#
	#	);
	return 0;
}

sub DC_services() {
	# debug output and do something with services
	if ($opt_debug) { print STDOUT "dc_services check started ... \n" }
	
	if ($opt_debug) { print STDOUT "...  Testing for snmp.conf\n" }
	my $snmp;
	if (( -e "/etc/snmp.conf") || (-e "/etc/snmp/snmp.conf")) {
		# found snmp configured
		if ( -e "/etc/snmp.conf" ) {
			open (my $FP, "< /etc/snmp.conf");
			while ( <$FP> ) {
				next if /^(\s)*$/;  # skip blank lines
				next if /^#/;      # Remove comments if not set for verbose
				if ( $_ =~ m/community/i ) {
					$snmp .= $_;
				}
			}
			close ($FP);
			if ($snmp) {
				chomp($snmp);
				if ($snmp =~ m/public/i ) {
					$Services{'SNMP Settings'} = "200 [FAIL] Default setting detected for SNMP community string \n" . $snmp;
				} else {
					$Services{'SNMP Settings'} = "000 [INFO] Setting for SNMP detected. Does not appear to be default. \n" . $snmp;
				}
			} else {
				$Services{'SNMP Settings'} = "000 [INFO] No community string detected in snmp.conf. Some other authentication method must be in use. Recommend manual validation";
			}
		} elsif ( -e "/etc/snmp/snmp.conf" ) {
			open (my $FP, "< /etc/snmp/snmp.conf");
			while ( <$FP> ) {
				next if /^(\s)*$/;  # skip blank lines
				next if /^#/;      # Remove comments if not set for verbose
				if ( $_ =~ m/community/i ) {
					$snmp .= $_;
				}
			}
			close ($FP);
			if ($snmp) {
			chomp($snmp);
				if ($snmp =~ m/public/i ) {
					$Services{'SNMP Settings'} = "200 [FAIL] Default setting detected for SNMP community string \n" . $snmp;
				} else {
					$Services{'SNMP Settings'} = "000 [INFO] Setting for SNMP detected \n" . $snmp;
				}
			} else {
				$Services{'SNMP Settings'} = "000 [INFO] No community string detected in snmp.conf. Some other authentication method must be in use. Recommend manual validation";
			}
		} else {
			$Services{'SNMP Settings'} = "000 [INFO] No community string detected in snmp.conf. Some other authentication method must be in use. Recommend manual validation";
		}
	}
	
	# Test for list of insecure, common services
	if ($opt_debug) { print STDOUT "... Testing for insecure services in process show and services \n" }
	my @tmp_insec_services = ( "authd",
		"echo",
		"discard",
		"daytime",
		"chargen",
		"ftp",
		"vsftp", 
		"ftp-data",
		"finger", 
		"httpd", 
		"identd", 
		"netdump", 
		"netdump_server", 
		"nfsd", 
		"rwhod", 
		"sendmail", 
		"smb", 
		"telnet",
		"yppasswdd", 
		"ypserv", 
		"ypxfrd",
		"webmin",
		"Navicat");

	my $ps_cmd = 'ps -ef';
	
	# Incorporated change from Linq3
	# If FreeBSD, use "ps -ax" instead:
	if ($OS =~ "FreeBSD") {
		$ps_cmd = 'ps -ax';
	}
	if ($OS =~ /AIX/) {
		$ps_cmd = 'ps ax';
	}
	
	my @ps=`$ps_cmd 2> /dev/null`;

	if (!@ps) {
		@ps=`ps aux 2> /dev/null`;
		$ps_cmd = 'ps aux';
	}
	
	my $svcs_cmd = 'none';
	
	my @svcsloaded;
	if ( -e "/bin/systemctl" ) {
		@svcsloaded = `systemctl -a --no-legend 2> /dev/null`;
		$svcs_cmd = 'systemctl -a --no-legend';
	} 
	if ((-e "/usr/bin/service") && (!@svcsloaded)) { # no prior load of services and found services
		@svcsloaded = `/usr/bin/service --status-all 2> /dev/null`;
		$svcs_cmd = '/usr/bin/service --status-all';
	} 
	if ((-e "/sbin/service") && (!@svcsloaded))  {
		@svcsloaded = `/sbin/service --status-all 2> /dev/null`;
		$svcs_cmd = '/sbin/service --status-all';
	} 
	if ((-e "/usr/bin/svcs") && (!@svcsloaded)) {
		@svcsloaded = `/usr/bin/svcs 2> /dev/null`;
		$svcs_cmd = '/usr/bin/svcs';
	} 
	if ((-e "/sbin/svcs") && (!@svcsloaded)) {
		@svcsloaded = `/sbin/svcs 2> /dev/null`;
		$svcs_cmd = '/sbin/svcs';
	} 
	if ((-e "/usr/sbin/service") && (!@svcsloaded)) {
		@svcsloaded = `/usr/sbin/service -e 2> /dev/null`;
		$svcs_cmd = '/usr/sbin/service';
	} 
	
	if ( $OS =~ m/AIX/i ) {
		@svcsloaded = `lssrc -a | grep active 2>/dev/null`;
		$svcs_cmd = 'lssrc -a | grep active';
	}
	
	if ( $OS =~ m/darwin/i ) {
		# For Mac, loaded services will be identified by an int in the first position of launchctl list operation
		# If character is a '-', the service is not loaded or running
		@svcsloaded = `launchctl list | grep -vi '-' 2>/dev/null`;
		$svcs_cmd = "launchctl list | grep -vi '-'";
	}
	
	# check for insecure services in process show
	# Preload hash with passing values for each service
	foreach my $i (@tmp_insec_services) {
		$Processes{$i} = "000 [PASS] $i service not detected in process show ($ps_cmd)";
	}
	
	# note: Added test for ntpd and chronyd to help with time verification. 
	
	if (@ps) {
		foreach my $l (@ps) {
			if ( $l =~ m/chronyd/i ) {
				$chronyd = 1;
				chomp($l);
				$ntp{'chronyd process found'} .= $l;
			}
			if ( $l =~ m/ntpd/i ) {
				$ntpd = 1;
				chomp($l);
				$ntp{'ntpd process found'} .= $l;
			}
			if ( $l =~ m/timed/i ) {
				$ntpd = 1;
				chomp($l);
				$ntp{'timed process found'} .= $l;
			}
			
			if ( $l =~ m/telnet/i ) { 
				$Processes{'telnet'} = "400 [FAIL] Telnet service potentially detected in process show ($ps_cmd)\n" . $l; 
			} 
			if (( $l =~ m/ftp/i )  && ( $l !~ m/sftp/i )) { 
				$Processes{'ftp'} = "200 [FAIL] ftp service potentially detected in process show ($ps_cmd). Validation required to confirm condition.\n" . $l; 
			} 
			if ( $l =~ m/vsftp/i ) { 
				$Processes{'vsftp'} = "200 [FAIL] vsftp service potentially detected in process show ($ps_cmd). Validation required to confirm condition.\n" . $l; 
			}
			if ( $l =~ m/ftp-data/i ) { 
				$Processes{'ftp-data'} = "400 [FAIL] ftp-data service potentially detected in process show ($ps_cmd)\n" . $l; 
			} 
			if ( $l =~ m/echo/i ) { 
				$Processes{'echo'} = "400 [FAIL] echo service potentially detected in process show ($ps_cmd)\n" . $l; 
			} 
			if ( $l =~ m/discard/i ) { 
				$Processes{'discard'} = "400 [FAIL] discard service potentially detected in process show ($ps_cmd)\n" . $l; 
			} 
			if ( $l =~ m/daytime/i ) { 
				$Processes{'daytime'} = "400 [FAIL] daytime service potentially detected in process show ($ps_cmd)\n" . $l; 
			} 
			if ( $l =~ m/chargen/i ) { 
				$Processes{'chargen'} = "400 [FAIL] chargen service potentially detected in process show ($ps_cmd)\n" . $l; 
			} 
			if ( $l =~ m/httpd/i ) { 
				$Processes{'http'} = "400 [FAIL] httpd service potentially detected in process show ($ps_cmd)\n" . $l; 
			} 
			if ( $l =~ m/finger/i ) { 
				$Processes{'finger'} = "400 [FAIL] finger service potentially detected in process show ($ps_cmd)\n" . $l; 
			} 
			if ( $l =~ m/authd/i ) { 
				$Processes{'authd'} = "400 [FAIL] authd service potentially detected in process show ($ps_cmd)\n" . $l; 
			} 
			if ( $l =~ m/identd/i ) { 
				$Processes{'identd'} = "400 [FAIL] identd service potentially detected in process show ($ps_cmd)\n" . $l; 
			} 
			if ( $l =~ m/netdump/i ) { 
				$Processes{'netdump'} = "400 [FAIL] netdump service potentially detected in process show ($ps_cmd)\n" . $l; 
			} 
			if ( $l =~ m/netdump_server/i ) { 
				$Processes{'netdump_server'} = "400 [FAIL] netdump_server service potentially detected in process show ($ps_cmd)\n" . $l; 
			}
			if ( $l =~ m/nfs/i ) { 
				$Processes{'nfs'} = "400 [FAIL] nfs service potentially detected in process show ($ps_cmd)\n" . $l; 
			} 
			if ( $l =~ m/rwhod/i ) { 
				$Processes{'rwhod'} = "400 [FAIL] rwhod service potentially detected in process show ($ps_cmd)\n" . $l; 
			} 
			if ( $l =~ m/sendmail/i ) { 
				$Processes{'sendmail'} = "400 [FAIL] sendmail service potentially detected in process show ($ps_cmd)\n" . $l; 
			}
			if ( $l =~ m/smb/i ) { 
				$Processes{'smb'} = "400 [FAIL] smb service potentially detected in process show ($ps_cmd)\n" . $l; 
			}
			if ( $l =~ m/yppasswdd/i ) { 
				$Processes{'yppasswdd'} = "400 [FAIL] yppasswdd service potentially detected in process show ($ps_cmd)\n" . $l; 
			}
			if ( $l =~ m/ypserv/i ) { 
				$Processes{'ypserv'} = "400 [FAIL] ypserv service potentially detected in process show ($ps_cmd)\n" . $l; 
			}
			if ( $l =~ m/ypxfrd/i ) { 
				$Processes{'ypxfrd'} = "400 [FAIL] ypxfrd service potentially detected in process show ($ps_cmd)\n" . $l; 
			}
			if ( $l =~ m/webmin/i ) { 
				$Processes{'webmin'} = "200 [WARN] Webmin service potentially detected in process show ($ps_cmd)\n" . $l; 
			}
			if ( $l =~ m/navicat/i ) { 
				$Processes{'navicat'} = "200 [WARN] Navicat service potentially detected in process show ($ps_cmd)\n" . $l; 
			}
		}
	} else { # No Processes read - reset values as non detected
		foreach my $i (@tmp_insec_services) {
			$Processes{$i} = "200 [WARN] Unable to detect or read process show ($ps_cmd). Detection of insecure services must be manually performed.";
		}
		
	}
	
	# Check for insecure services if not IBM AIX or some other platforms.
	if ( $OS !~ m/AIX/i ) {  # test for crap unix platform
		# Preset InsecServices Hash
		foreach my $is (@tmp_insec_services) {
			$InsecServices{$is} = "000 [PASS] $is service not detected in service listing ($svcs_cmd)";
		}
		if (@svcsloaded) {
			foreach my $l (@svcsloaded) {
				if ( $l =~ m/telnet .* running/i ) { 
					$InsecServices{'telnet'} = "400 [FAIL] Telnet service potentially detected in service listing ($svcs_cmd)\n" . $l; 
				} 
				if (( $l =~ m/ftp .* running/i )  && ( $l !~ m/sftp/i )) { 
					$InsecServices{'ftp'} = "400 [FAIL] ftp service potentially detected in service listing ($svcs_cmd). Validation required.\n" . $l; 
				} 
				if ( $l =~ m/vsftpd .* running/i ) { 
					$InsecServices{'vsftp'} = "200 [FAIL] vsftp service potentially detected in service listing ($svcs_cmd). Validation required to confirm condition.\n" . $l; 
				}
				if ( $l =~ m/ftp-data .* running/i ) { 
					$InsecServices{'ftp-data'} = "400 [FAIL] ftp-data service potentially detected in service listing ($svcs_cmd)\n" . $l; 
				} 
				if ( $l =~ m/echo .* running/i ) { 
					$InsecServices{'echo'} = "400 [FAIL] echo service potentially detected in service listing ($svcs_cmd)\n" . $l; 
				} 
				if ( $l =~ m/discard .* running/i ) { 
					$InsecServices{'discard'} = "400 [FAIL] discard service potentially detected in service listing ($svcs_cmd)\n" . $l; 
				} 
				if ( $l =~ m/daytime .* running/i ) { 
					$InsecServices{'daytime'} = "400 [FAIL] daytime service potentially detected in service listing ($svcs_cmd)\n" . $l; 
				} 
				if ( $l =~ m/chargen .* running/i ) { 
					$InsecServices{'chargen'} = "400 [FAIL] chargen service potentially detected in service listing ($svcs_cmd)\n" . $l; 
				} 
				if ( $l =~ m/httpd .* running/i ) { 
					$InsecServices{'http'} = "400 [FAIL] http service potentially detected in service listing ($svcs_cmd)\n" . $l; 
				} 
				if ( $l =~ m/finger .* running/i ) { 
					$InsecServices{'finger'} = "400 [FAIL] finger service potentially detected in service listing ($svcs_cmd)\n" . $l; 
				} 
				if ( $l =~ m/authd .* running/i ) { 
					$InsecServices{'authd'} = "400 [FAIL] authd service potentially detected in service listing ($svcs_cmd)\n" . $l; 
				} 
				if ( $l =~ m/identd .* running/i ) { 
					$InsecServices{'identd'} = "400 [FAIL] identd service potentially detected in service listing ($svcs_cmd)\n" . $l; 
				} 
				if ( $l =~ m/netdump .* running/i ) { 
					$InsecServices{'netdump'} = "400 [FAIL] netdump service potentially detected in service listing ($svcs_cmd)\n" . $l; 
				} 
				if ( $l =~ m/netdump_server .* running/i ) { 
					$InsecServices{'netdump_server'} = "400 [FAIL] netdump_server service potentially detected in service listing ($svcs_cmd)\n" . $l; 
				}
				if ( $l =~ m/nfs .* running/i ) { 
					$InsecServices{'nfs'} = "400 [FAIL] nfs service potentially detected in service listing ($svcs_cmd)\n" . $l; 
				} 
				if ( $l =~ m/rwhod .* running/i ) { 
					$InsecServices{'rwhod'} = "400 [FAIL] rwhod service potentially detected in service listing ($svcs_cmd)\n" . $l; 
				}	 
				if ( $l =~ m/sendmail .* running/i ) { 
					$InsecServices{'sendmail'} = "400 [FAIL] sendmail service potentially detected in service listing ($svcs_cmd)\n" . $l; 
				}
				if ( $l =~ m/smb .* running/i ) { 
					$InsecServices{'smb'} = "400 [FAIL] smb service potentially detected in service listing ($svcs_cmd)\n" . $l; 
				}
				if ( $l =~ m/yppasswdd .* running/i ) { 
					$InsecServices{'yppasswdd'} = "400 [FAIL] yppasswdd service potentially detected in service listing ($svcs_cmd)\n" . $l; 
				}
				if ( $l =~ m/ypserv .* running/i ) { 
					$InsecServices{'ypserv'} = "400 [FAIL] ypserv service potentially detected in service listing ($svcs_cmd)\n" . $l; 
				}
				if ( $l =~ m/ypxfrd .* running/i ) { 
					$InsecServices{'ypxfrd'} = "400 [FAIL] ypxfrd service potentially detected in service listing ($svcs_cmd)\n" . $l; 
				}
				if ( $l =~ m/webmin .* running/i ) { 
					$InsecServices{'webmin'} = "200 [WARN] Webmin service potentially detected in service listing ($svcs_cmd)\n" . $l; 
				}
				if ( $l =~ m/navicat.* running/i ) { 
					$InsecServices{'navicat'} = "200 [WARN] Navicat service potentially detected in service listing ($svcs_cmd)\n" . $l; 
				}
			}
		} else {
			foreach my $is (@tmp_insec_services) {
				$InsecServices{$is} = "200 [WARN] Unable to detect or read services ($svcs_cmd). Detection of insecure services must be manually performed.";
			}
		}
	} else { # AIX system check
		$InsecServices{'AIX Detected'} = "<pre>200 [WARN] Due to nature of service output listing, unable to analyze for insecure services ($svcs_cmd). Must be manually performed.\n";
		$InsecServices{'AIX Detected'} .= "\n";
		$InsecServices{'AIX Detected'} .= "Service Listing:\n";
		foreach my $s (@svcsloaded) {
			$InsecServices{'AIX Detected'} .= "$s";
		}
		$InsecServices{'AIX Detected'} .= "</pre>\n";
	}
	
	# General backup information on services
	if ($opt_verbose) {
		if (@ps) {
			foreach my $p (@ps) {
				next if ($p =~ m/^(\s)*$/);
				$Services{'Process Show for all running processes'} .= $p;
			}
		}
	} else {
		$Services{'Process Show for all running processes'} = "If you wish to see the full list of detected processes in the process show, please rerun without '-s' option";
	}
	
	if (@svcsloaded) {
		if ($opt_forensic) {
			$Services{'Services defined and detected'} = "Command run for test: $svcs_cmd\n";
			foreach my $s (@svcsloaded) {
				next if ($s =~ m/^(\s)*$/);
				$Services{'Services defined and detected'} .= $s;
			}
		} else {
			$Services{'Services defined and detected'} = "If you wish to see the full list of detected services, please rerun with '--forensic' option";
		}
	} else {
		$Services{'Services defined and detected'} = "200 [INFO] Unable to identify the running services on $hostname";
	}
	
	# forensic pstree execution
	if ($opt_forensic) {
		if ( -x "/usr/bin/pstree" ) {
			my $pt = `pstree`;
			chomp($pt);
			$Services{'Process Tree (pstree)'} = $pt;
		} elsif ( -x "/usr/bin/proctree" )  {  # AIX enhancement
			my $pt = `proctree`;
			chomp($pt);
			$Services{'Process Tree (proctree)'} = $pt;
		}else {
			$Services{'Process Tree'} = '200 [INFO] Unable to execute pstree on this host.';
		}
	}
	
		
	# debug output
	if ($opt_debug) {
		print STDOUT "... dc_services check completed \n"
	}
	return 0;
}

sub DC_batchjobs() {
	# debug output
	if ($opt_debug) {
		print STDOUT "dc_batchjobs started .... \n"
	}
	# Anacron
	if (-f "/etc/anacrontab") {
		my $anacrontab;
		open (my $FP, "< /etc/anacrontab");
		while ( <$FP> ) {
			next if /^(\s)*$/;  # skip blank lines
			# if (!$opt_verbose) {next if /^#/; }      # Remove comments if not set for verbose
			$anacrontab .= $_;   # append to scaler
		}
		close ($FP);
		chomp($anacrontab);  # remove final \n
		$batchjobs{'Anacrontab'} = $anacrontab;
	}
	
	# Cron
	if (-e "/etc/crontab") {
		my $crontab;
		open (my $FP, "< /etc/crontab");
		while ( <$FP> ) {
			next if /^(\s)*$/;  # skip blank lines
			# if (!$opt_verbose) {next if /^#/; }      # Remove comments if not set for verbose
			$crontab .= $_;   # append to scaler
		}
		close ($FP);
		chomp($crontab);  # remove final \n
		$batchjobs{'Crontab'} = $crontab;
	} 
	
	if ( $OS =~ /AIX/) {
		my $crontab = `crontab -l 2>/dev/null`;
		chomp($crontab);
		$batchjobs{'Crontab'} = $crontab;
	}
	
	if ( -d "/etc/cron.daily" ) {
		if ($opt_verbose) {
			my $dir = '/etc/cron.daily';
			opendir( DIR, $dir);
			#$batchjobs{'cron.daily Directory Listing'} = "Note: this is a listing of named scripts in /etc/cron.daily only. Run $0 with -v for more details \n";
			while (my $f = readdir(DIR)) {
				next if ($f =~ m/^\./); # don't list any dot files
				$batchjobs{'cron.daily Directory Listing'} .= $f;
			}
			closedir(DIR);	
		} else {
			$batchjobs{'cron.daily Directory Listing'} = "cron.daily directory found. If you wish to see the directory listing of cron.daily, rerun without '-s' option";
		}
	}
	
	if ( -d "/etc/cron.hourly" ) {
		if ($opt_verbose) {
			my $dir = '/etc/cron.hourly';
			opendir( DIR, $dir);
			#$batchjobs{'cron.hourly Directory Listing'} = "Note: this is a listing of named scripts in /etc/cron.daily only. Run $0 with -v for more details \n";
			while (my $f = readdir(DIR)) {
				next if ($f =~ m/^\./); # don't list any dot files
				$batchjobs{'cron.hourly Directory Listing'} .= $f;
			}
			closedir(DIR);	
		} else {
			$batchjobs{'cron.hourly Directory Listing'} = "cron.hourly directory found. If you wish to see the directory listing of cron.hourly, rerun without '-s' option";
		}
	}
	
	if ( -d "/etc/cron.weekly" ) {
		if ($opt_verbose) {
			my $dir = '/etc/cron.weekly';
			opendir( DIR, $dir);
			#$batchjobs{'cron.weekly Directory Listing'} = "Note: this is a listing of named scripts in /etc/cron.daily only. Run $0 with -v for more details \n";
			while (my $f = readdir(DIR)) {
				next if ($f =~ m/^\./); # don't list any dot files
				$batchjobs{'cron.weekly Directory Listing'} .= $f;
			}
			closedir(DIR);	
		} else {
			$batchjobs{'cron.weekly Directory Listing'} = "cron.weekly directory found. If you wish to see the directory listing of cron.weekly, rerun without '-s' option";
		}
	}
	
	if ( -d "/etc/cron.monthly" ) {
		if ($opt_verbose) {
			my $dir = '/etc/cron.monthly';
			opendir( DIR, $dir);
			#$batchjobs{'cron.weekly Directory Listing'} = "Note: this is a listing of named scripts in /etc/cron.daily only. Run $0 with -v for more details \n";
			while (my $f = readdir(DIR)) {
				next if ($f =~ m/^\./); # don't list any dot files
				$batchjobs{'cron.monthly Directory Listing'} .= $f;
			}
			closedir(DIR);	
		} else {
			$batchjobs{'cron.monthly Directory Listing'} = "cron.monthly directory found. If you wish to see the directory listing of cron.monthly, rerun without '-s' option";
		}
	}
	
	# Listing of other cron batch files
	
	if (-d "/etc/cron"){
		if ($opt_verbose) {
			my $dir = '/etc/cron';
			opendir( DIR, $dir);
			while (my $f = readdir(DIR)) {
				next if ($f =~ m/^\./); # don't list any dot files
				$batchjobs{'etc/cron Directory Listing'} .= $f . "\n";
			}
			closedir(DIR);	
		} else {
			$batchjobs{'etc/cron Directory Listing'} = "/etc/cron directory found. If you wish to see the directory listing of /etc/cron, rerun without '-s' option";
		}
	}
	
	# AT and atq
	if (-e "/usr/bin/atq") {
		my $at=`atq 2>/dev/null`;
		chomp($at);
		if ($at) {
			$batchjobs{'AT-atq'} = "atq found. Listing of at jobs:\n" . $at;
		}
	} 
	#  Setup to find and dump /var/spool/cron/atjobs 01-2015
	my $atjobs = "/var/spool/cron/atjobs";
	if ( -e $atjobs ) {
        # check to verify running with su before proceeding or place warning in response
        if (!$suFlag){
            # $suFlag is off so this is not running with su
            $batchjobs{'at Jobs found at /var/spool/cron/atjobs'} = "200 [WARN] Directory exists but cannot be read without su permissions.";
        } else {
            my $at;
            if ( -f $atjobs ) {
                open(FP, "<", "/var/spool/cron/atjobs");
                while(<FP>) {
                    $at .= $_;
                }
                close(FP);
            } elsif ( -d $atjobs ) {
                opendir( DIR, $atjobs);
                while (my $f = readdir(DIR)) {
                    next if ($f =~ m/^\./); # don't list any dot files
                    if ($f) {
                        $at .= $f . "\n"; # Only output stuff if there is something to output
                    }
                }
                closedir(DIR);
            }
            if ($at) {
                $batchjobs{'at Jobs found at /var/spool/cron/atjobs'} = "File listing:\n" . $at;
            } else {
                $batchjobs{'at Jobs found at /var/spool/cron/atjobs'} = "Directory does not exist or appears empty. This may need to be verified.\n";
            }
        }
	}
	
	
	# Lets look at batch jobs on a mac. Examine all of the jobs in the/usr/lib/cron/tabs/* area
	if ( $OS =~ m/darwin/i ) {  
		# It's a Mac
		#
		my @user = `dscl . list /Users | grep -v '_'`;
		my $count = 1;
		my $lctl;
		$batchjobs{'OSX Mac Batch Jobs'} .= "Crontab listing by system users from (dscl . list /Users)\n";
		foreach my $u (@user) {
			chomp($u);
			$lctl=`crontab -u $u -l 2>/dev/null`;
			$count += 1;
			$batchjobs{'OSX Mac Batch Jobs'} .= "User: $u\n";
			if ($lctl) {
				chomp($lctl);
				$batchjobs{'OSX Mac Batch Jobs'} .= $lctl;
				undef($lctl);
			} else {
				$batchjobs{'OSX Mac Batch Jobs'} .= "    No jobs defined\n";
			}
		}
	} 
		
	# debug output
	if ($opt_debug) {
		print STDOUT "dc_batchjobs completed \n";
	}
	return 0;
}

sub DC_logging() {
	# debug output
	if ($opt_debug) {
		print STDOUT "dc_logging started ... \n"
	}
	# Syslog configuration info
	my $syslogfile;
	if ( -f "/etc/rsyslog.conf" ) {
		$syslogfile="/etc/rsyslog.conf";
	} elsif ( -f "/etc/syslog.conf"){
		$syslogfile="/etc/syslog.conf";
	} elsif ( -f "/etc/sysklog.conf") {
		$syslogfile="/etc/sysklog.conf";
	} else {
		$syslogfile="none\n";
	}
	
	if ($opt_debug) {
		print STDOUT "syslog configuration file found: $syslogfile\n";
	}
	if ($syslogfile !~ m/none/) {
		(my $wopath = $syslogfile) =~ s!^.*/!!;
		my $sys="<LogConfigFile name=\'$wopath\'>\n";
		open (my $FP, "< $syslogfile" ) ;
		while ( <$FP>) {
			next if /^(\s)*$/;
			#next if /^#/; # skip comments
			$sys .= $_;
		}
		close ($FP);
		$sys .= "</LogConfigFile>";
		$logging{'syslog Configuration file'}= $sys;
	} 
	
	if ($opt_verbose) {
		# travers and dump all config files in /etc/rsyslog.d if directory exists
		if ( -d "/etc/rsyslog.d" ) {
			my @files = </etc/rsyslog.d/*.conf>;
			foreach my $file (@files) {
					(my $wopath = $file) =~ s!^.*/!!;
					my $sys="<LogConfigFile name=\'$wopath\'>\n";
					open (my $FP, "< $file");
					while ( <$FP> ) {
						next if /^(\s)*$/;
						$sys .= $_;
					}
					close ($FP);
					$sys .= "\n</LogConfigFile>";
					$logging{$wopath}= $sys;
			}
		}
	} 
	
	# get the current NTP settings in to %ntp
	# dump current system date and time note: this is set when get_year() is run.
	$ntp{'Current System Date Time'} = $time;
	
	# NTP configuration
	# Future upgrade, extract server information and verify (1) server is reachable, and (2) internal to the network
	if ((-f "/etc/ntp.conf") && (-f "/etc/cron.daily/ntpdate")) {
		my $nt; 
		my $source = 'none';  # note $source is a flag as to whether or not ntp.conf has a server defined
		open (my $FP, "< /etc/ntp.conf");
		while ( <$FP> ) {
			next if /^(\s)*$/;  # skip blank lines
			next if /^#/; # Skip comment lines
			if (m/^server/i) {
				$source = 'OK';
				$nt .= $_;   # append to scaler for server records
			} # Check if the line defines a server	
		}
		close ($FP);
		chomp($nt);  # remove final \n
		if ($source =~ m/OK/) {
			$ntp{'NTP Configuration (ntp.conf) '} = $nt;
		} else {
			# No server source identified in ntp.conf file
			$ntp{'NTP Configuration (ntp.conf) '} = "200 [FAIL] No server defined as time source in ntp.conf \n";
		}
		undef $nt;
		open ($FP, "< /etc/cron.daily/ntpdate");
		while (<$FP>) {
			next if /^(\s)*$/;  # skip blank lines
			$nt .= $_;   # append to scaler
		}
		close ($FP);
		chomp($nt);
		$ntp{'NTP Configuration in cron.daily (ntpdate)'} = $nt;
	} elsif (-f "/etc/cron.daily/ntpdate") {
    	my $nt;
    	open (my $FP, "< /etc/cron.daily/ntpdate");
		while (<$FP>) {
			next if /^(\s)*$/;  # skip blank lines
			# if (!$opt_verbose) {next if /^#/; }      # Remove comments if not set for verbose
			$nt .= $_;   # append to scaler
		}
		close ($FP);
		chomp($nt);
		$ntp{'NTP Configuration in cron.daily (ntpdate)'} = $nt;
	# Test for configuration of the RHEL chrony.conf file in etc as an alternative method for setting time.
    } 
    
    if ( $chronyd ) { #
    	my $nt; 
		my $source = 'none';  # note $source is a flag as to whether or not ntp.conf has a server defined
		if ( -f "/etc/chrony.conf" ) {
			open (my $FP, "< /etc/chrony.conf");
			while ( <$FP> ) {
				next if /^(\s)*$/;  # skip blank lines
				next if /^#/; # Skip comment lines
				if (m/^server/i) {
					$source = 'OK';
					$nt .= $_;   # append to scaler for server records
				} # Check if the line defines a server	
			}
			close ($FP);
			chomp($nt);  # remove final \n
			if ($source =~ m/OK/) {
				$ntp{'NTP Configuration (chrony.conf) '} = "Important note: even though servers have been found as time sources, QSA for PCI must verify these are internal systems.\n";
				$ntp{'NTP Configuration (chrony.conf) '} .= $nt;
			} else {
				$ntp{'NTP Configuration (chrony.conf) '} = "400 [FAIL] found chrony.conf but unable to identify location of time server. Manually validate.\n";
			}
		} else {
			$ntp{'NTP Configuration (chrony.conf) '}  = "200 [WARN] Identified chronyd running, but unable to locate configuration file. Must be manually validated.\n";
		}
    } 
    
    if ( $ntpd ) {
    	if (( -f "/etc/inet/ntp.conf" ) || (-f "/etc/ntp.conf")) {
			my $ntpfile = "/etc/ntp.conf" if ( -f "/etc/ntp.conf" );
			$ntpfile = "/etc/inet/ntp.conf" if ( -f "/etc/inet/ntp.conf" );  # The solaris file location and version
			my $nt; 
			my $source = 'none';  # note $source is a flag as to whether or not ntp.conf has a server defined
			open (my $FP, "< $ntpfile");
			while ( <$FP> ) {
				next if /^(\s)*$/;  # skip blank lines
				next if /^#/; # Skip comment lines
				if (m/^server/i) {
					$source = 'OK';
					$nt .= $_;   # append to scaler for server records
				} # Check if the line defines a server	
			}
			close ($FP);
			chomp($nt);  # remove final \n
			if ($source =~ m/OK/) {
				$ntp{'NTP Configuration (ntp.conf) '} = "Important note: even though servers have been found as time sources, QSA for PCI must verify these are internal systems.\n";
				$ntp{'NTP Configuration (ntp.conf) '} .= $nt;
			} else {
				# No server source identified in ntp.conf file
				$ntp{'NTP Configuration (ntp.conf) '} .= "400 [FAIL] No server defined as time source in $ntpfile for ntpd\n" . $nt;
			}
	    } else {
	    	$ntp{'NTP Configuration'} .= "200 [WARN] ntpd found in process show. Unable to detect or locate ntp configuration data in common locations";
	    }
    }
    
    if ( $timed ) {
    	if (( -f "/etc/inet/ntp.conf" ) || (-f "/etc/ntp.conf")) {
			my $ntpfile = "/etc/ntp.conf" if ( -f "/etc/ntp.conf" );
			$ntpfile = "/etc/inet/ntp.conf" if ( -f "/etc/inet/ntp.conf" );  # The solaris file location and version
			my $nt; 
			my $source = 'none';  # note $source is a flag as to whether or not ntp.conf has a server defined
			open (my $FP, "< $ntpfile");
			while ( <$FP> ) {
				next if /^(\s)*$/;  # skip blank lines
				next if /^#/; # Skip comment lines
				if (m/^server/i) {
					$source = 'OK';
					$nt .= $_;   # append to scaler for server records
				} # Check if the line defines a server	
			}
			close ($FP);
			chomp($nt);  # remove final \n
			if ($source =~ m/OK/) {
				$ntp{'timed Configuration (ntp.conf) '} = "Important note: even though servers have been found as time sources, QSA for PCI must verify these are internal systems.\n";
				$ntp{'timed Configuration (ntp.conf) '} .= $nt;
			} else {
				# No server source identified in ntp.conf file
				$ntp{'timed Configuration (ntp.conf) '} .= "400 [FAIL] No server defined as time source in $ntpfile for timed\n" . $nt;
			}
	    } else {
	    	$ntp{'timed Configuration'} .= "200 [WARN] timed found in process show. Unable to detect or locate ntp configuration data in common locations";
	    }
    }
    
    if ($opt_forensic) {
		if ( -e "/usr/bin/ntpq" ) {
  			$ntp{'NTPQ query and settings'} = `ntpq -p -c ntpversion 2>/dev/null`;
		}
    }
	# debug output
	if ($opt_debug) {
		print STDOUT "dc_logging complete ... \n";
	}
	return 0;
}

sub DC_networking() {
	# debug output
	if ($opt_debug) {
		print STDOUT "dc_networking started ....  \n"
	}
	# Collect Network information and configuration settings
	my ($if,$ns,$nsr,$pi,$listen,$lsof);
	$if = `ifconfig -a 2>/dev/null`;
	if (!$if) {
		$if = `/sbin/ifconfig -a 2>/dev/null`;
	}
	if ($if) {
		chomp($if);
		$network{'IFConfig (ifconfig -a)'} = $if;
	} else {
		$network{'IFConfig'} = "200 [WARN] Unable to locate or run ifconfig to capture current network interface configuration. Test manually.";
	}
	
	# Get routing table
	$nsr = `netstat -rn 2>/dev/null`;
	if ($nsr) {
		chomp($nsr);
		$network{'Routing (netstat -rn)'} = $nsr;
	} else {
		$network{'Routing'} = "200 [WARN] Unable to locate or run netstat to capture current kernel network routing. Test manually.";
	}
		
	# use lsof to collect information on network connections and listeners (most common approach on all platforms)
	
	if ( -e "/usr/bin/lsof")  { # Some old versions of Solaris don't have lsof
		$listen = `/usr/bin/lsof -i -w -n -P 2>/dev/null`;
		chomp($listen);
		$network{'Connections (lsof -i -w -n -P)'} = $listen;
		if ($opt_debug) {print STDOUT "Connections (/usr/bin/lsof -i -w -n -P)\n";}
	} elsif ( -e "/usr/sbin/lsof") {
		$listen = `/usr/sbin/lsof -i -w -n -P 2>/dev/null`;
        if (!$listen) {
            # Nothing found even though /usr/sbin/lsof exists. May not have permission
            $listen = `netstat -an 2> /dev/null`;
            if ($listen) {
                chomp($listen);
                $network{'Connections (netstat -an)'} = $listen;
            } else {
                $network{'Connections'} = "200 [WARN] Unable to run either lsof or netstat to capture litening ports. May lack permissions.";
            }
        } else {
            chomp($listen);
            $network{'Connections (lsof -i -w -n -P)'} = $listen;
        }
		if ($opt_debug) {print STDOUT "Connections (/usr/sbin/lsof -i -w -n -P)";}
	} else {
		$listen = `netstat -an 2> /dev/null`;
		if ($listen) {
			chomp($listen);
			$network{'Connections (netstat -an)'} = $listen;
		} else {
			$network{'Connections'} = "200 [WARN] Unable to locate or run netstat to capture litening ports. Test manually.";
		}
	}
	
	if ($opt_debug) {print STDOUT "... End of lsof\n";}
	
	if ($opt_forensic) {
		# get the full netstat and information on listeners
		if ($opt_debug) {print STDOUT "Running full netstat if system is on the network\n";}
		if ($onNet) {
			$ns = `netstat 2>/dev/null`; 
			if ($ns) { 
				chomp($ns); 
			} else {
				$ns = "200 [WARN] Unable to locate or run netstat to capture detail routing information as requested. Test manually.";
			}
			$network{'Netstat'} = $ns;
		} else {
			$network{'Netstat'} = '200 [WARN] Subject system not on network. Unable to run full netstat';
		}
		#Deprecated for version 4c8
#		if ($onNet) {
#			# Get details on all established connections and processes
#			my $ns1 = `netstat -tuapn 2>/dev/null`; 
#			if ($ns1) { 
#				chomp($ns1); 
#			} else {
#				$ns1 = "200 [WARN] Unable to locate or run netstat to capture detail routing information as requested. Test manually.";
#			}
#			$network{'Netstat -tuapn Est/Listen processes'} = $ns1;
#		} else {
#			$network{'Netstat -tuapn Est/Listen processes'} = '200 [WARN] Subject system not on network. Unable to run netstat -tuapn for established and listening processes';
#		}
	}
	
	
	if ($opt_verbose) {	
		# Port listeners. This may be used when verbosity is set.
		my $pi;
		if ($opt_debug) {print STDOUT "Running netstat -l \n";}
		if ($onNet) {
			if ($OS =~ /AIX/) {
				$pi = `netstat -Aan | grep LISTEN | awk '{print \$1 " " \$5}'`;
				# This section of the report needs to be enhanced to get PID and process information
				# Shell script to parse:
				#netstat -Aan | grep LISTEN | awk '{print $1 " " $5}' | while read pcb port; do
        		# out=`rmsock $pcb tcpcb`
        		#if echo "$out" | grep "Kernel Extension" > /dev/null; then
                # printf "%-15s Kernel Extension\n" "$port"
        		#else
                #pid=`echo "$out" | sed -n 's/.*pro[c]*ess \([0-9][0-9]*\) .*/\1/p'`
                #if [ -n "$pid" ]; then
                #        proc=`ps -p $pid | tail -n 1 | awk '{print $4}'`
                #        printf "%-15s %-16s $proc\n" "$port" $pid
                #else
                #        echo "Error, Line not recognized \"$out\" for Port $port"
                #fi
        		#fi
				#done
				$network{'PortInformation'} = $pi;
			} else {
				$pi = `netstat -l 2>/dev/null`;
				if ($pi) { 
					chomp($pi); 
				} else {
					$pi = "200 [WARN] Unable to locate or run netstat to capture port listener information as requested. Test manually.";
				} 
				$network{'PortInformation'} = $pi;
			}
		} else {
			$network{'PortInformation'} = '200 [WARN] Subject system not on network. Unable to run full netstat';
		}

		if ($opt_debug) {print STDOUT "...Checking host allow and deny \n";}
		
		if ($opt_debug) {print STDOUT "\t...Checking host allow\n";}
		if ( -f "/etc/hosts.allow" ) {
			my $HA;
			open (my $FP, "< /etc/hosts.allow");
			$HA = 'Note: a /etc/hosts.allow file has been identified. This file may only contain comment records. Check if records exist where there is no # in first position.\n';
			while ( <$FP> ) {
				next if /^(\s)*$/;
				$HA .= $_;
			}
			close ($FP);
			if ($HA) {
				chomp($HA);
				$network{'Hosts Allow'} = $HA;
			}
		}
		if ($opt_debug) {print STDOUT "\t...Checking host deny \n";}
		if ( -f "/etc/hosts.deny" ) {
			my $HD;
			open (my $FP, "< /etc/hosts.deny");
			$HD = 'Note: a /etc/hosts.deny file has been identified. This file may only contain comment records. Check if records exist where there is no # in first position.\n';
			while ( <$FP> ) {
				next if /^(\s)*$/;
				$HD .= $_;
			}
			close ($FP);
			if ($HD) {
				chomp($HD);
				$network{'Hosts Deny'} = $HD;
			}
		}
		if ($opt_debug) {print STDOUT "\t...Checking resolv.conf \n";}
		if ( -f "/etc/resolv.conf" ) {
			my $RC;
			$RC = 'Note: a /etc/resolv.conf file has been identified. This file may be controlled by the operating system based on network configuration and records may not be accurate or exist.\n';
			open (my $FP, "< /etc/resolv.conf") ;
			while ( <$FP> ) {
				next if /^(\s)*$/;
				if (!$opt_verbose) {next if /^#/; }      # Remove comments if not set for verbose
				$RC .= $_;
			}
			close ($FP);
			if ($RC) {
				chomp($RC);
				$network{'ResolvConf'} = $RC;
			}
		}
	}
	
	if ($opt_debug) {print STDOUT "... Obtaining firewall information\n";}
	
	if ($opt_forensic) {
		if ( $OS =~ m/Linux/i ) {
			if ($opt_debug) {print STDOUT "obtaining firewall information\n";}
			my $iptab_status = `service iptables status 2> /dev/null`;
			my $iptab = `iptables -L -n 2> /dev/null`;
			if ($iptab) {
				chomp($iptab);
				$network{'iptables configuration'} = $iptab;
			}
		}
	}
		
	# debug output
	if ($opt_debug) {
		print STDOUT "...dc_networking complete \n";
	}
	return 0;
}

sub DC_remote_accesscontrol() {
	
	# debug output
	if ($opt_debug) {
		print STDOUT "dc_remote_accesscontrol started ...\n"
	}
	
	# Contributed by Linq3 and edited by TA to use sshd -T if available
	##  Added by LInq for BSD:  if ($OS =~ "FreeBSD") {
	my @runningvalues;
	if ( -e '/usr/sbin/sshd' ) {
		my @runningvalues=`sshd -T 2> /dev/null`;
	}
	if (@runningvalues) {
		# Set control bits to identify missing components
		my ($port,$proto,$loglev,$permemtpy,$rootlog,$pam,$maxauth,$maxses,$logingrace);
		foreach my $l (@runningvalues) {
			if ( $l =~ m/port/i ) { 
				# depends on external interface. If there is an outside interface, warn on 22
				my($k, $v) = split(/\s/, $l);
				my $testedValue;
				if ( $v =~ m/22/) {$testedValue = "100 [INFO] Default SSH port detected as port: $v";}
				else {$testedValue = "000 [PASS] Best practice observed. SSH port changed from default as: $v";}
				$ssh{$k} = $testedValue; 
				$port = 1;
			}
			if ( $l =~ m/protocol/i ) { 
				my($k, $v) = split(/\s/, $l);
				my $testedValue;
				if ($v =~ m/1/) {$testedValue = "400 [FAIL] Insecure SSH protocol supported. Detected protocol SSH Version $v";}
				else {$testedValue = "000 [PASS] Protocol SSH version $v detected.";}
				$ssh{$k} = $testedValue; 
				$proto = 1;
			}
			if ( $l =~ m/loglevel/i ) { 
				my($k, $v) = split(/\s/, $l);
				my $testedValue;
				if ($v =~ m/info/i ) {$testedValue = "000 [PASS] Proper log level defined as: $v";}
				else {$testedValue = "400 [FAIL] Log level defined as other than \"info\". This will not log information required by PCI. Detected: $v";}
				$ssh{$k} = $testedValue;
				$loglev = 1;
			}
			if ( $l =~ m/permitemptypasswords/i ) { 
				my($k, $v) = split(/\s/, $l);
				my $testedValue;
				if ($v =~ m/no/i) {$testedValue = "000 [PASS] Correct setting to prohibit an empty password string. Setting: $v";}
				else {$testedValue = "400 [FAIL] SSH configured to accept or act on empty password string. Setting $v";}
				$ssh{$k} = $testedValue; 
				$permemtpy = 1;
			}
			if ( $l =~ m/rootlogin/i ) { 
				my($k, $v) = split(/\s/, $l);
				my $testedValue;
				if ($v =~ m/no/i) {$testedValue = "000 [PASS] Correct setting to prohibit remote root login to system.  Detected: $v";}
				elsif ($v =~ m/without-password/i) {$testedValue = "200 [WARN] SSH configured to permit remote root login to system. This may violate PCI 8.5.a and 10.2.x respectively. Detected: $v";}
				elsif ($v =~ m/forced-commands-only/i) {$testedValue = "200 [WARN] Permits root login without password but using public key authentication for specific commands only. Remote root login may violate PCI 8.5.a and 10.2.x respectively. Investigation needed.  Detected: $v";}
				else {$testedValue = "200 [WARN] SSH configured to permit remote root login to system.  This may violate PCI 8.5.a and 10.2.x respectively. Detected default yes or: $v . IMPORTANT: QSA needs to follow up with customer on this control.";}
				$ssh{$k} = $testedValue; 
				$rootlog = 1;
			}
			if ( $l =~ m/pam/i ) { 
				my($k, $v) = split(/\s/, $l);
				my $testedValue;
				if ($v =~ m/yes/i || $v eq "1") {$testedValue = "000 [PASS] Using PAM modules for authentication.  Detected: $v";}
				else {$testedValue = "200 [WARN] Not configured to use PAM. Auditor must check to validate appropriate authentication mechanism is configured.  Detected: $v";}
				$ssh{$k} = $testedValue; 
				$pam = 1;
			}
			if (( $l =~ m/maxauthtries/i ) && ( $l !~ m/maxauthtrieslog/i )) { 
				my($k, $v) = split(/\s/, $l);
				my $testedValue;
				if ( $v < 7 ) {$testedValue = "000 [PASS] Maximum authentication tries set to $v or less than 7.  Detected: $v";}
				else {$testedValue = "200 [FAIL] Maximum authentication tries set for greater than 6 and beyond current PCI criteria.  Detected: $v";}
				$ssh{$k} = $testedValue; 
				$maxauth = 1;
			}
			if ( $l =~ m/maxsession/i ) { 
				my($k, $v) = split(/\s/, $l);
				my $testedValue = "200 [WARN] This value allows users to open $v simultaneous sessions. Auditor should validate this is the smallest value needed by the business. Setting $v";
				$ssh{$k} = $testedValue; 
				$maxses = 1;
			}
			if ( $l =~ m/logingracetime/i ) { 
				my($k, $v) = split(/\s/, $l);
				if ($v =~ m/m/i) {
					#time is in minutes. Convert to seconds
					$v =~ s/m//;
					$v *= 60; # Set $v to seconds
				}
				my $testedValue;
				if (( $v > 300 ) || ( $v == 0 )) { $testedValue = "200 [FAIL] time in seconds ($v) is too long or set to zero. This is the amount of time a client has to complete login process.";}
				else { $testedValue = "000 [PASS] time in seconds ($v) set appropriately short to disconnect users who do not complete login process";}
				$ssh{$k} = $testedValue; 
				$logingrace = 1;
			}
		}
		
		# Look for missing settings and set values
		my $missingValue = "200 [WARN] Value not explicitly defined. Check OS documentation for default value and confirm consistent with organizations security policy"; 
		if (!$port) { $ssh{'Port'} = $missingValue; }
		if (!$proto) { $ssh{'Protocol'} = $missingValue; }
		if (!$loglev) { $ssh{'LogLevel'} = $missingValue; }
		if (!$permemtpy) { $ssh{'PermitEmptyPasswords'} = $missingValue; }
		if (!$rootlog) { $ssh{'PermitRootLogin'} = "400 [FAIL] Value not explicitly defined. Default is YES. The root account is able to use SSH to login directly to this machine. This must be investigated."; }
		if (!$pam) { $ssh{'UsePAM'} = $missingValue; }
		if (!$maxauth) { $ssh{'MaxAuthTries'} = $missingValue; }
		if (!$maxses) { $ssh{'MaxSessions'} = $missingValue; }
		if (!$logingrace) { $ssh{'LoginGraceTime'} = $missingValue; }
	
    } else {
    	# sshd -T has failed. now read config files
		my $sshConfigFile;
		$sshConfigFile = '/etc/ssh/sshd_conf' if ( -e "/etc/ssh/sshd_conf" );
		$sshConfigFile = '/etc/ssh/sshd_config' if ( -e "/etc/ssh/sshd_config" );
		$sshConfigFile = '/etc/sshd_config' if (-e "/etc/sshd_config" );
		$sshConfigFile = '/etc/sshd_conf' if (-e "/etc/sshd_conf" );
	
		if ($sshConfigFile) {
			# Set control bits to identify missing components
			my ($port,$proto,$loglev,$permemtpy,$rootlog,$pam,$maxauth,$maxses,$logingrace);
			# Open the file for reading
			open (my $FP, "< $sshConfigFile") or print STDOUT "Unable to open $sshConfigFile for reading: $!";
			while (<$FP>) {
				next if m/^#.*/;   # Get rid of comments
				next if m/^(\s)*$/; # Get rid of lines of spaces
				# print STDOUT "$_\n";
				if ( $_ =~ m/port/i ) { 
					# depends on external interface. If there is an outside interface, warn on 22
					my($k, $v) = split(/\s/, $_);
					my $testedValue;
					if ( $v =~ m/22/) {$testedValue = "100 [INFO] Default SSH port detected as port: $v";}
					else {$testedValue = "000 [PASS] Best practice observed. SSH port changed from default as: $v";}
					$ssh{$k} = $testedValue; 
					$port = 1;
				}
				if ( $_ =~ m/protocol/i ) { 
					my($k, $v) = split(/\s/, $_);
					my $testedValue;
					if ($v =~ m/1/) {$testedValue = "400 [FAIL] Insecure SSH protocol supported. Detected protocol SSH Version $v";}
					else {$testedValue = "000 [PASS} Protocol SSH version $v detected.";}
					$ssh{$k} = $testedValue; 
					$proto = 1;
				}
				if ( $_ =~ m/loglevel/i ) { 
					my($k, $v) = split(/\s/, $_);
					my $testedValue;
					if ($v =~ m/info/i ) {$testedValue = "000 [PASS] Proper log level defined as: $v";}
					else {$testedValue = "400 [FAIL] Log level defined as other than \"info\". This will not log information required by PCI. Detected: $v";}
					$ssh{$k} = $testedValue;
					$loglev = 1;
				}
				if ( $_ =~ m/permitemptypasswords/i ) { 
					my($k, $v) = split(/\s/, $_);
					my $testedValue;
					if ($v =~ m/no/i) {$testedValue = "000 [PASS] Correct setting to prohibit an empty password string. Setting: $v";}
					else {$testedValue = "400 [FAIL] SSH configured to accept or act on empty password string. Setting $v";}
					$ssh{$k} = $testedValue; 
					$permemtpy = 1;
				}
				if ( $_ =~ m/rootlogin/i ) { 
					my($k, $v) = split(/\s/, $_);
					my $testedValue;
					if ($v =~ m/no/i) {$testedValue = "000 [PASS] Correct setting to prohibit remote root login to system.  Detected: $v";}
					elsif ($v =~ m/without-password/i) {$testedValue = "400 [FAIL] SSH configured to permit remote root login to system. This may violate PCI 8.5.a and 10.2.x respectively. Detected: $v";}
					elsif ($v =~ m/forced-commands-only/i) {$testedValue = "200 [WARN] Permits root login without password but using public key authentication for specific commands only. This may violate PCI 8.5.a and 10.2.x respectively. Investigation needed.  Detected: $v";}
					else {$testedValue = "400 [FAIL] SSH configured to permit remote root login to system. This may violate PCI 8.5.a and 10.2.x respectively. Detected default yes or: $v";}
					$ssh{$k} = $testedValue; 
					$rootlog = 1;
				}
				if ( $_ =~ m/pam/i ) { 
					my($k, $v) = split(/\s/, $_);
					my $testedValue;
					if ($v =~ m/yes/i) {$testedValue = "000 [PASS] Using PAM modules for authentication.  Detected: $v";}
					else {$testedValue = "200 [WARN] Not configured to use PAM. Auditor must check to validate appropriate authentication mechanism is configured.  Detected: $v";}
					$ssh{$k} = $testedValue; 
					$pam = 1;
				}
				if (( $_ =~ m/maxauthtries/i ) && ( $_ !~ m/maxauthtrieslog/i )) { 
					my($k, $v) = split(/\s/, $_);
					my $testedValue;
					if ( $v < 7 ) {$testedValue = "000 [PASS] Maximum authentication tries set to $v or less than 7.  Detected: $v";}
					else {$testedValue = "200 [FAIL] Maximum authentication tries set for greater than 6 and beyond current PCI criteria.  Detected: $v";}
					$ssh{$k} = $testedValue; 
					$maxauth = 1;
				}
				if ( $_ =~ m/maxsession/i ) { 
					my($k, $v) = split(/\s/, $_);
					my $testedValue = "200 [WARN] This value allows users to open $v simultaneous sessions. Auditor should validate this is the smallest value needed by the business. Setting $v";
					$ssh{$k} = $testedValue; 
					$maxses = 1;
				}
				if ( $_ =~ m/logingracetime/i ) { 
					my($k, $v) = split(/\s/, $_);
					if ($v =~ m/m/i) {
						#time is in minutes. Convert to seconds
						$v =~ s/m//;
						$v *= 60; # Set $v to seconds
					}
					my $testedValue;
					if (( $v > 300 ) || ( $v == 0 )) { $testedValue = "200 [FAIL] time in seconds ($v) is too long or set to zero. This is the amount of time a client has to complete login process.";}
					else { $testedValue = "000 [PASS] time in seconds ($v) set appropriately short to disconnect users who do not complete login process";}
					$ssh{$k} = $testedValue; 
					$logingrace = 1;
				}
			}
			close($FP);
			
			# Look for missing settings and set values
			my $missingValue = "200 [WARN] Value not explicitly defined. Check OS documentation for default value and confirm consistent with organizations security policy"; 
			if (!$port) { $ssh{'Port'} = $missingValue; }
			if (!$proto) { $ssh{'Protocol'} = $missingValue; }
			if (!$loglev) { $ssh{'LogLevel'} = $missingValue; }
			if (!$permemtpy) { $ssh{'PermitEmptyPasswords'} = $missingValue; }
			if (!$rootlog) { $ssh{'PermitRootLogin'} = "400 [FAIL] Value not explicitly defined. Default is YES. The root account is able to use SSH to login directly to this machine. This must be investigated."; }
			if (!$pam) { $ssh{'UsePAM'} = $missingValue; }
			if (!$maxauth) { $ssh{'MaxAuthTries'} = $missingValue; }
			if (!$maxses) { $ssh{'MaxSessions'} = $missingValue; }
			if (!$logingrace) { $ssh{'LoginGraceTime'} = $missingValue; }	
		
		}
	}
	
	if ($opt_debug) {
		print STDOUT "dc_remote_accesscontrol finished ...\n"
	}
	return 0;
}

sub DC_permissions() {
	# This subroutine builds a list of file names into an array and then reads the array and calls testPerms() routine
	# debug output
	if ($opt_debug) {
		print STDOUT "dc_permissions started ...\n"
	}
	my @filenames;
	my @directories;
	
	# Setting up directorynames for testing
	if ( -d "/etc/security" ) {
		my $dir = '/etc/security';
		push(@directories, $dir);
		opendir( DIR, $dir);
		while (my $f = readdir(DIR)) {
			next if ($f =~ m/^\./); # don't list any dot files
			if ( -d $f ) { push(@directories, $f); }
		}
		closedir(DIR);	
	}
	
	if ( -d "/etc/init.d" ) {
		my $dir = '/etc/init.d';
		push(@directories, $dir);
		opendir(DIR, $dir);
		while (my $f = readdir(DIR)) {
			next if ($f =~ m/^\./);
			if ( -d $f ) { push(@directories, $f); }
		}
		closedir(DIR);
	}
	
	if ( -d "/etc/ssh" ) {
		my $dir = '/etc/ssh';
		push(@directories, $dir);
		opendir(DIR, $dir);
		while (my $f = readdir(DIR)) {
			next if ($f =~ m/^\./);
			if ( -d $f ) { push(@directories, $f); }
		}
		closedir(DIR);
	}
	
	if ( -d "/etc/ssl" ) {
		my $dir = '/etc/ssl';
		push(@directories, $dir);
		opendir(DIR, $dir);
		while (my $f = readdir(DIR)) {
			next if ($f =~ m/^\./);
			if ( -d $f ) { push(@directories, $f); }
		}
		closedir(DIR);
	}
	
	if ( -d "/etc/cron.d" ) {
		my $dir = '/etc/cron.d';
		push(@directories, $dir);
		opendir(DIR, $dir);
		while (my $f = readdir(DIR)) {
			next if ($f =~ m/^\./);
			if ( -d $f ) { push(@directories, $f); }
		}
		closedir(DIR);
	}
	
	if ( -d "/etc/cron.daily" ) {
		my $dir = '/etc/cron.daily';
		push(@directories, $dir);
		opendir(DIR, $dir);
		while (my $f = readdir(DIR)) {
			next if ($f =~ m/^\./);
			if ( -d $f ) { push(@directories, $f); }
		}
		closedir(DIR);
	}
	
	if ( -d "/etc/cron.hourly" ) {
		my $dir = '/etc/cron.hourly';
		push(@directories, $dir);
		opendir(DIR, $dir);
		while (my $f = readdir(DIR)) {
			next if ($f =~ m/^\./);
			if ( -d $f ) { push(@directories, $f); }
		}
		closedir(DIR);
	}
	
	if ( -d "/etc/cron.weekly" ) {
		my $dir = '/etc/cron.weekly';
		push(@directories, $dir);
		opendir(DIR, $dir);
		while (my $f = readdir(DIR)) {
			next if ($f =~ m/^\./);
			if ( -d $f ) { push(@directories, $f); }
		}
		closedir(DIR);
	}
	
	if ( -d "/etc/cron.monthly" ) {
		my $dir = '/etc/cron.monthly';
		push(@directories, $dir);
		opendir(DIR, $dir);
		while (my $f = readdir(DIR)) {
			next if ($f =~ m/^\./);
			if ( -d $f ) { push(@directories, $f); }
		}
		closedir(DIR);
	}
	
	# Setup files
	if ( -d "/etc" ) {
		my $dir = '/etc';
		opendir(DIR,$dir);
		while (my $f = readdir(DIR))  {
			next if ($f =~ m/^\./);
			my $target = $dir . "/" . $f; # Must have full path in target to perform activity
			if ( -f $target ) {push(@filenames, $target); }
		}
		closedir(DIR);
	}
	if ($opt_debug) {
		print STDOUT "   Directory processing for file permissions\n";
	}
	foreach my $d (@directories) {
		opendir(DIR,$d);
		while (my $f = readdir(DIR)) {
			next if ($f =~ m/^\./);
			my $target = $d . "/" . $f; # Must have full path in target to perform activity
			if ( -f $target ) {
				push(@filenames, $target); 
			}
		}
		closedir(DIR);
	}
	
	# read and test files... do the output as well
	
	if ($opt_debug) { 
		print STDOUT "    File processing and testing permissions. \n";
	}
	foreach my $k (@filenames) {
		my $v = testPerms($k);
		$perms{$k} = $v;
	}
	
	
	if ($opt_debug) {
		print STDOUT "dc_permissions finished ...\n"
	}
	return 0;
}

sub DC_accesscontrol() {
	# debug output
	if ($opt_debug) {
		print STDOUT "dc_accesscontrol started ...\n"
	}
	# if present and forensic mode, dump bash_history for all interactive user accounts. New in version 4c8
    # Updated to correctly get the unique home directories from the /etc/passwd file instead of assuming a default
	if ($opt_forensic) {
		foreach my $u (@userhomes) {
			# read users from the interactive user array populated by getUsers sub routine
			if ($OS =~ m/darwin/i) {
				$accesscontrol{"Bash History for $u"}.="Bash_history for user $u\n ";
				my $historyFile="$u/.bash_history";
				# must be a stupid Mac
				if ( -e "$historyFile") {
					open(my $f, "< $historyFile");
					while(<$f>){
						$accesscontrol{"Bash History for $u"}.= "$_";
					}
					$accesscontrol{"Bash History for $u"}.= "\n";
					close($f);
				} else {
					# Must not be a bash_history file for this user
					$accesscontrol{"Bash History for $u"}.= "Unable to find $historyFile for user $u\n";
				}
			} else {
				# all real NIX platforms
				$accesscontrol{"Bash History for $u"}.="Bash_history for user $u\n ";
				my $historyFile="$u/.bash_history";
				# must be a stupid Mac
				if ( -e "$historyFile") {
					open(my $f, "< $historyFile");
					while(<$f>){
						$accesscontrol{"Bash History for $u"}.= "$_";
					}
					$accesscontrol{"Bash History for $u"}.= "\n";
					close($f);
				} else {
					# Must not be a bash_history file for this user
					$accesscontrol{"Bash History for $u"}.= "Unable to find $historyFile for user $u\n";
				}
			}
		}
	}
	
	# Gent general authentication settings
	if (-e "/etc/sysconfig/authconfig") {
		open (AC, '< /etc/sysconfig/authconfig');
		while(<AC>) {
			next if m/false/i;
			next if m/nologin/i;
			next if m/hallt/i;
			next if m/sync/i;
			next if m/^#.*/;   # Get rid of comments
			$accesscontrol{'PAM / Authconfig settings'} .= $_;
			# put more tests here in future
		}
		close(AC);
	}
	# get user accounting data
	if (-e "/usr/bin/lastlog") {
		# Remove this
		my $ll = `/usr/bin/lastlog`;
		chomp($ll);
		$accesscontrol{'User Accounting - lastlog'} = $ll;
	}
	if (-e "/usr/bin/last") {	
		# wtmp and btmp as well as prior copies of btmp
		my($lst, $blst);
		my @btmpnames;
		# Get list of btmp files in /var/log
		if ( -d "/var/log" ) {
			my $dir = '/var/log';
			opendir(DIR,$dir);
			while (my $f = readdir(DIR))  {
				next if ($f =~ m/^\./);
				next unless ($f =~ m/btmp/); # unless the name of the file is btmp, go to next record
				my $target = $dir . "/" . $f; # Must have full path in target to perform activity
				if ( -f $target ) {push(@btmpnames, $target); }
			}
			closedir(DIR);
		}
		
		if ($opt_verbose) {
			if ($OS =~ m/darwin/i) {
				$lst=`/usr/bin/last`;
				chomp($lst);
			} elsif ( $OS =~ m/AIX/i ) {
				# just run last on aix
				if ( -x "/var/adm/wtmp" ) {
					$lst = "Found /var/adm/wtmp. Dumping with last \n";
					$lst .= `/usr/bin/last -f /var/adm/wtmp`;
				} else {
					$lst .= `/usr/bin/last`;
				}
				chomp($lst);
			} else {
				$lst = "wtmp dump (last -iF )\n";
				$lst .= `last -iF 2> /dev/null`;
			}
			
			if ( $OS =~ m/AIX/i ) {
				# Check for failedlogins
				if ( -x "/etc/security/failedlogin" ) {
					$blst = "Found /etc/security/failedlogin file. Dumping with last \n";
					$blst .= `/usr/bin/last -f /etc/security/failedlogin`;
				} else {
					$blst = "200 [WARN] Did not find /etc/security/failedlogin file. This may be logged elsewhere. May need to validate manually."
				}
			} elsif (@btmpnames) {
				foreach my $d (@btmpnames) {
					$blst = "\nbtmp dump of failed login attempts (last -iF -f $d )\n";
					$blst .= `last -iF -f $d 2> /dev/null`;
				}
			}
			
		} else {
			if ($OS =~ m/darwin/i) {
				$lst=`/usr/bin/last`;
				chomp($lst);
			} elsif ( -x "/var/adm/wtmp" ) { # might be AIX
					$lst = "Found /var/adm/wtmp. Dumping with last \n";
					$lst .= `/usr/bin/last -f /var/adm/wtmp`;
			} else {
				$lst = "wtmp dump (last -iF -25 ) \n";
				$lst .= `last -iF -25 2> /dev/null`;
				$blst = "\nbtmp dump of failed login attempts (last -iF -f /var/log/btmp )\n";
				$blst .= `last -iF -f /var/log/btmp 2> /dev/null`;
			}
		}
		if ($lst) {
			chomp($lst);
			$accesscontrol{'Successful User Logins (wtmp)'}=$lst;
			if ($blst) {
				$accesscontrol{'Failed User Logins (btmp or /etc/security/failedlogin)'}=$blst;
			}
		}
	}
	
	if ( $OS =~ m/AIX/i ) {
		if ( -e "/usr/sbin/acct/ac" ) {
			my $ac = `/usr/sbin/acct/ac -p`;
			chomp($ac);
			$accesscontrol{'User login-accounting using ac'}=$ac;
		} else {
			$accesscontrol{'User login-accounting using ac'}='200 [WARN] OS is AIX. Unable to locate user accounting utility.';
		}
	} elsif ((-x "/usr/sbin/ac")||(-x "/usr/bin/ac")) {
		my $ac = `ac -p`;
		chomp($ac);
		$accesscontrol{'User login-accounting using ac'}=$ac;
	}
	# Test for passwords in /etc/passwd file -- Read pw file, split and capture second attribute, if greater than one character, capture
	# and report as passwords present in etc/passwd file. Bad practice. 
	
	# Test for passwords in /etc/shadow - DAC configuration - run chage on those accounts -- read shadow, split and capture second attribute
	# for each entry. If greater than one character, then capture and report account name and attributes from shadow. This is a replacement 
	# for use of chage. 
	
	# Collect info on DAC authentication configuration for password, groups and sudo 
	if ( -f "/etc/passwd" ) {
		# Determine the character in the password file
		# that we expect in the password field.  Some dumb UNIX systems have two different characters
		my ($passchar, $passchar2);  
		# FreeBSD uses a star, not an 'x':
		if (($OS =~ m/FreeBSD/i ) || ( $OS =~ m/darwin/i )) {
			$passchar = '*';
		} elsif ( $OS =~ m/AIX/i )  {
			$passchar = '!';
			$passchar2 = '*';
		}else {
			$passchar = 'x';
		}
		open (my $FP, "< /etc/passwd");
		my ($uname, $pw, $spw, $theRest);
		my $fail;
		while (<$FP>) {
			next if m/false/i;
			next if m/nologin/i;
			next if m/hallt/i;
			next if m/sync/i;
			next if m/^#.*/;   # Get rid of comments
			my ($uname, $pw, $uid,$guid,$geco,$homedir,$shell)=split(/:/);
			# next if $pw =~ m/\!/;  # flag for disabled account in the pw field
			if ( length($pw) > 1 ) {
				#bad. Probably has a password in the file
				$accesscontrol{"Account $uname password"} = "200 [FAIL] Account name $uname may have password value in /etc/passwd that is: $pw";
				$fail = 'FAIL';
			}
			if ($passchar2) {  # crap there are two characters
				if (( $pw ne $passchar) && ( $pw ne $passchar2 )) { # test for value of 'x' or '*'
					$accesscontrol{"Account $uname not using shadow"} = "200 [FAIL] Account name $uname detected to have non-'$passchar' or '$passchar2' value in /etc/passwd file";
					$accesscontrol{"Account $uname not using shadow"} .= "Password file string \"$pw\" for this user";
					$fail = 'FAIL';
				}
			} elsif ( $pw ne $passchar) { # test for value of 'x' or '*'
				$accesscontrol{"Account $uname not using shadow"} = "200 [FAIL] Account name $uname detected to have non-'$passchar' value in /etc/passwd file";
				$accesscontrol{"Account $uname not using shadow"} .= "Password file string \"$pw\" for this user";
				$fail = 'FAIL';
			}
		}
		close($FP);
	}
	
	if (($OS =~ m/AIX/i )  && ($opt_forensic)) {  # If AIX and run in forensic mode
		if ( -f "/etc/security/passwd" ) {
			$accesscontrol {'Account password listing (/etc/security/passwd'} = "Note: Forensic listing of local accounts and hashes. Timestamp is epoch.\n"; 
			chomp( $accesscontrol {'Account password listing (/etc/security/passwd)'} .= `cat /etc/security/passwd`);
		}
	}
	
	# 20170322: Test for presence of sssd in the system and check if system is configured. If using sssd, dump it all. 
	if ( -d "/etc/sssd/conf.d") { # RHEL system with sssd capability
			opendir(DIR, "/etc/sssd/conf.d");
			my @files = grep !/^\.\.?$/, readdir(DIR);  # only read file names, no dot or double dot names in listing
			closedir(DIR);
			# Test for attributes in the file. If none, sssd is present but not configured.
			my ($sssdf, $sssd_data);
			$sssd_data = "";
			if (@files) {
				$accesscontrol{'sssd configuration data'} = "000 [PASS] Found sssd configuration files on system. Must be manually reviewed by QSA for correctness. File listing:\n";
				# must be an RHEL linux with files in the sssd directory
				foreach my $f (@files) { 
					$sssdf = $f;
					chomp($sssdf); 
					open( FIL, $sssdf );
					while (<FIL>) {
						$sssd_data .= $_;
					}
					$accesscontrol{'sssd configuration data'} .= $sssdf;
					$accesscontrol{'sssd configuration data'} .= $sssd_data;	
				}
			} else {
				if ( -e "/etc/init.d/sssd") {
					$accesscontrol{'sssd configuration data'} = "200 [WARN] This Linux distribution appears capable of running sssd. Not configured. \n";
				} else {
					$accesscontrol{'sssd configuration data'} = "000 [PASS] This Linux distribution not capable of running sssd on this system or not a RHEL Linux.\n";
				}
			}
	} else {
		$accesscontrol{'sssd configuration data'} = "000 [PASS] Configuration not capable of or configured for running sssd on this system or not a RHEL Linux.\n";
	}
	
	if ($opt_verbose) {
		
		# Check and list out group records from /etc/group that represent admin rights 
		# (root, adm, wheel, daemon, sudo, nopasswdlogin)
		if ( -f "/etc/group" ) {
			my $grp;
			open (my $FP, "< /etc/group");
			while (<$FP>) {
				# if (($_ =~ m/adm/i) ||  ($_ =~ m/root/i) || ($_ =~ m/wheel/i) || ($_ =~ m/daemon/i) || ($_ =~ m/sudo/i) || ($_ =~ m/nopasswd/i)) {
					$grp .= $_;
				#}  Removed condition. Dump full group file
			}
			close($FP);
			chomp($grp);
			$accesscontrol{'Group listing'} = $grp;
		}
	}

	# Test for root remote access
	if ($opt_debug) {print STDOUT ".... Testing for remote root access.\n";}
	my $ratl = "Remote root access. Tests have been performed in three areas to identify if root account is appropriately restricted to prevent direct remote login. \n\n"; # test result for root access
	# Test /etc/passwd
	if ( -f "/etc/passwd" ) {
		if ($opt_debug) {print STDOUT ".... /etc/passwd review\n";}
		open(PW, "<", "/etc/passwd");
		while (<PW>) {
			next if m/^#.*/;
			my ($username, $password, $uid, $gid, $real_name, $home, $shell) = split(/:/,$_);
			if ($username =~ m/root/i ) {
				if (($shell =~ m/nologin/) || ($shell =~ m/\/bin\/false/i)) {
					$ratl .= "000 [PASS] Root account set to nologin in /etc/passwd\n";
				} else {
					$ratl .= "200 [WARN] Root account not set to nologin or shell /bin/false in /etc/passwd.\n";
				}
				last; # stop the while loop
			}
		}
		close(PW);
	}
	
	# Test default login controls
	my $defloginset;
	if (( -f "/etc/default/login") || ( -f "/etc/login.defs" )) {
		
		if ($opt_debug) {print STDOUT ".... login defs review\n";}
		my $defaultfile = "/etc/default/login" if ( -f "/etc/default/login" );
		$defaultfile = "/etc/login.defs" if ( -f "/etc/login.defs" );
		open (FP, "< $defaultfile");
		while (<FP>) {
			next if m/^(\s)*$/;  # remove spaces
			next if m/^#.*/ ;  # Skip comments if not in verbose mode
			if ( $_ =~ m/^CONSOLE\s/i ) {
				my($k, $v) = split(/\s/, $_);
				if ($v =~ m/\/etc\/consoles/i ) {
					$ratl .= "000[PASS] Set to require root to login from console only.\n";
				} elsif ($v =~ m/(?s:.)/i) {
					$ratl .= "200[WARN] Check setting in login defaults to verify root login access is suitably limited. The root account may have remote access.\n";
				}
				$defloginset = 1;
				last;
			}
		}
		if (!$defloginset) {
			$ratl .= "200 [WARN] Default login setting to limit remote root access to specific connections is not set. Review the CONSOLE attribute to assure it's set properly.\n";
		}
		close(FP);
	}
	
	if ($ratl) {
		if ($ratl =~ m/FAIL/i ) {
			$ratl .= "\nCondition detected that requires investigation and follow up. Root account can be used remotely to access this system.\n";
		} elsif ($ratl =~ m/WARN/i ) {
			$ratl .= "\nCondition detected that requires investigation. Root account may not be sufficiently restricted from remote access to this system.\n";
		} else {
			$ratl .= "\nRoot account may be sufficiently blocked from remotely accessing this system. If CONSOLE attribute used, validate that the value is appropriately set in the login defaults file.\n";
		}
		
		$accesscontrol{'Non-console root login'} = $ratl;
	}
	
	# if ($opt_verbose) {
	if (( -f "/etc/default/login") || ( -f "/etc/login.defs" )) {
		my $ldf;
		my $defaultfile = "/etc/default/login" if ( -f "/etc/default/login" );
		$defaultfile = "/etc/login.defs" if ( -f "/etc/login.defs" );
		open (my $FP, "< $defaultfile");
		while (<$FP>) {
			next if /^(\s)*$/;  # remove spaces
			# must test for attributes 
			if ( $_ =~ m/^\#CONSOLE\s/i ) {
				$ldf .= "\n";
				$ldf .= "200 [WARN] CONSOLE attribute appears to be commented out and may allow root to login remotely. This value should be set to /dev/console\n";
			
			}
			if ( $_ =~ m/^\#SYSLOG\=/ ) {
				$ldf .= "\n";
				$ldf .= "400 [FAIL] SYSLOG attribute is commented out and will not log root logins to syslog. This value should be set to YES\n";
			
			}
			if ( $_ =~ m/^\#SYSLOG_FAILED_LOGINS/i ) {
				$ldf .= "\n";
				$ldf .= "400 [FAIL] SYSLOG_FAILED_LOGINS attribute is commented out and will not log failed logins to syslog. This value should be set to YES\n";
			
			}
			next if m/^#.*/;      # Remove comments before writing to hash
			$ldf .= $_;
			if (( $_ =~ m/^PASSREQ/i ) && ( $_ !~ m/yes/i )) { 
					$ldf .= "\n";
					$ldf .= "400 [FAIL] PASREQ is set to allow access without a password. Dangersous setting. Should be set to YES. \n";
			}
			if (( $_ =~ m/^SYSLOG/i ) && ( $_ !~ m/yes/i )) { 
					$ldf .= "\n";
					$ldf .= "400 [FAIL] SYSLOG attribute is set to value other than YES and will not log root logins to syslog. This value should be set to YES\n";
			}	
					
		}
		close($FP);
		chomp($ldf);
		$accesscontrol{'Login defaults from etc/default/login or /etc/default/login'} = $ldf;

	# List of contents of /etc/pam.d
	
		if ( -d "/etc/pam.d") {
			opendir(DIR, "/etc/pam.d");
			my @files = grep !/^\.\.?$/, readdir(DIR);  # only read file names, no dot or double dot names in listing
			closedir(DIR);
			my $pdf;
			foreach my $f (@files) { $pdf .= $f; }
			chomp($pdf);
			$accesscontrol{'Directory Listing of pam.d'} = $pdf;
		}
		if ( -f "/etc/pam.d/common-passwd" ) {
			my $pc;
			open (my $FP, "< /etc/pam.d/common-passwd");
			while (<$FP>) {
				next if /^(\s)*$/;  # remove spaces
				if (!$opt_verbose) {next if /^#.*/; }      # Remove comments if not set for verbose
				$pc .= $_;
			}
			close($FP);
			if ($pc) {
				chomp($pc);
				$accesscontrol{'common-passwd'} = $pc;			
			} else {
				$accesscontrol{'common-passwd'} = "Not used. Look in /etc/pam.d for detail configuration and settings.";
			}
		}
		if ( -f "/etc/pam.d/common-auth" ) {
			my $pc;
			open (my $FP, "< /etc/pam.d/common-auth");
			while (<$FP>) {
				next if /^(\s)*$/;  # remove spaces
				if (!$opt_verbose) {next if /^#.*/; }      # Remove comments if not set for verbose
				$pc .= $_;
			}
			close($FP);
			if ($pc) {
				chomp($pc);
				$accesscontrol{'common-auth'} = $pc;			
			} else {
				$accesscontrol{'common-auth'} = "Not used. Look in /etc/pam.d for detail configuration and settings.";
			}
		}
		if ( -f "/etc/pam.d/passwd" ) {
			my $pc;
			open (my $FP, "< /etc/pam.d/passwd");
			while (<$FP>) {
				next if /^(\s)*$/;  # remove spaces
				if (!$opt_verbose) {next if /^#.*/; }      # Remove comments if not set for verbose
				if (!$opt_verbose) {next if /^\@/; }     # remove leading reference
				$pc .= $_;
			}
			close($FP);
			if ($pc) {
				chomp($pc);
				$accesscontrol{'pam_d-passwd'} = $pc;			
			} 
		}	
	
		if ( -f "/etc/pam.d/login" ) {
			my $pc;
			open (my $FP, "< /etc/pam.d/login");
			while (<$FP>) {
				next if /^(\s)*$/;  # remove spaces
				if (!$opt_verbose) {next if /^#.*/; }      # Remove comments if not set for verbose
				if (!$opt_verbose) {next if /^\@/; }     # remove leading reference
				$pc .= $_;
			}
			close($FP);
			if ($pc) {
				chomp($pc);
				$accesscontrol{'pam_d-login'} = $pc;			
			} 
		}
	}
	
	if ( -f "/etc/pam.d/system-auth" ) {
		my $pc;
		open (my $FP, "< /etc/pam.d/system-auth");
		while (<$FP>) {
			next if /^(\s)*$/;  # remove spaces
			if (!$opt_verbose) {next if /^#.*/; }      # Remove comments if not set for verbose
			$pc .= $_;
		}
		close($FP);
		if ($pc) {
			chomp($pc);
			$accesscontrol{'system-auth'} = $pc;			
		} else {
			$accesscontrol{'system-auth'} = "Not used. Look in /etc/pam.d for detail configuration and settings.";
		}
	}
	
	if ( -f "/etc/pam.conf" ) {
		my $pc;
		open (my $FP, "< /etc/pam.conf");
		while (<$FP>) {
			next if /^(\s)*$/;  # remove spaces
			if (!$opt_verbose) {next if /^#.*/; }      # Remove comments if not set for verbose
			$pc .= $_;
		}
		close($FP);
		if ($pc) {
			chomp($pc);
			$accesscontrol{'PAM config file (etc/pam.config)'} = $pc;			
		} else {
			$accesscontrol{'PAM config file (etc/pam.config)'} = "Not used. Look in /etc/pam.d for detail configuration and settings.";
		}
	}
	
	if ( -f "/etc/defaults/useradd" ) {
		my $pc;
		open (my $FP, "< /etc/defaults/useradd");
		while (<$FP>) {
			next if /^(\s)*$/;  # remove spaces
			if (!$opt_verbose) {next if /^#.*/; }      # Remove comments if not set for verbose
			$pc .= $_;
		}
		close($FP);
		if ($pc) {
			chomp($pc);
			$accesscontrol{'Default user add configuration'} = $pc;			
		} else {
			$accesscontrol{'Default user add configuration'} = "Not used. Look in /etc/pam.d for detail configuration and settings.";
		}
	}
	
	if ( -f "/etc/adduser.conf" ) {
		my $pc;
		open (my $FP, "< /etc/adduser.conf");
		while (<$FP>) {
			next if /^(\s)*$/;  # remove spaces
			if (!$opt_verbose) {next if /^#.*/; }      # Remove comments if not set for verbose
			$pc .= $_;
		}
		close($FP);
		if ($pc) {
			chomp($pc);
			$accesscontrol{'Add user configuration file'} = $pc;			
		} else {
			$accesscontrol{'Add user configuration file'} = "Not used. Look in /etc/pam.d for detail configuration and settings.";
		}
	}

	# Get sudo information if /etc/sudoers exists
	if ( -f "/etc/sudoers") {
  		# system has sudo configured
  		my $srs;
        if (!$suFlag) {
            # run with force flag cannot open this file
            $srs = '200 [WARN] Run without su privileges and not able to open or read /etc/sudoers even though this file exists';
        } else {
            open (my $FP, "< /etc/sudoers");
            while (<$FP>) {
                next if /^(\s)*$/;  # remove spaces
                if (!$opt_verbose) {next if /^#.*/; }      # Remove comments if not set for verbose
                $srs .= $_;
            }
            close($FP);
            chomp($srs);
        }
		$accesscontrol{'Listing of sudoers file'} = $srs;
	}
	
	# For Sun OS, dump the policy files
	if ( -f "/etc/security/policy.conf" ) {
		my $sp;
		$sp .= "/etc/security/policy.conf\n";
		open (my $FP, "< /etc/security/policy.conf");
		while (<$FP>) {
			next if /^(\s)*$/;  # remove spaces
			if ( $_ =~ m/^\#CRYPT_ALGORITHMS_DEPRECATE/i ) { # Test for commented out attributes that should be set
				$sp .= "\n";
				$sp .= "400 [FAIL] CRYPT_ALGORITHMS_DEPRECATE attribute is commented out. This value should be set to \'__unix__\' to prevent use of dangers service.\n";
				$sp .= "\n";
			
			}
			next if /^#.*/;      # Remove comments 
			$sp .= $_;
			if ( $_ =~ m/^CRYPT_ALGORITHMS_DEPRECATE/i ) {
				if ( $_ !~ m/\=__unix__/i ) { # set to something other than =__unix__
					$sp .= "\n";
					$sp .= "200 [FAIL] CRYPT_ALGORITHMS_DEPRECATE attribute may be set to value other than \'__unix__\'.\n";
					$sp .= "\n";
				}
			}
			if ( $_ =~ m/^CRYPT_DEFAULT/i ) {
				if ( $_ =~ m/unix/ ) { 
					$sp .= "\n";
					$sp .= "400 [FAIL] CRYPT_DEFAULT is set for \'unix\' and only evaluates first 8 characters of password.\n";
					$sp .= "Dangersous default setting. Should be set to 5 or 6. See: http://www.insecuresystem.org/2010/04/solaris-10-password-fail.html\n";
				}
				if ( $_ !~ m/\=[5-6]$/ ) { # Hack to look for a string of =5 or =6.... 
					$sp .= "\n";
					$sp .= "200 [FAIL] CRYPT_DEFAULT is set for value of other than 5 or 6 and does not use strong cryptography to protect passwords. \n";
					$sp .= "Should be set to 5 or 6. See: /etc/security/crypt.conf for settings.\n";
					if ( -f "/etc/security/crypt.conf") {
						$sp .= "\n/etc/security/crypt.conf\n";
						open (my $FP, "< /etc/security/crypt.conf");
						while (<$FP>) {
							next if /^(\s)*$/;  # remove spaces
							next if /^#.*/;       # Remove comments 
							$sp .= $_;
						}
						close($FP);
					}
				}
			}
		}
		close($FP);
		if($sp) {
			chomp($sp);
			$accesscontrol{'SUN Security Policy configuration file'} = $sp;
		}
	
	}
	if ( -f "/etc/user_attr") {
		my $sp;
		open (my $FP, "< /etc/user_attr");
		while (<$FP>) {
			next if /^(\s)*$/;  # remove spaces
			if (!$opt_verbose) {next if /^#.*/; }      # Remove comments if not set for verbose
			$sp .= $_;
		}
		close($FP);
		if($sp) {
			chomp($sp);
			$accesscontrol{'SUN User attribute file'} = $sp;
		}
	}	
	if ($opt_verbose) {  # Detail security auditing policies for sun servers.... Too verbose for short report
		if ( -f "/etc/security/auth_attr") {
			my $sp;
			open (my $FP, "< /etc/security/auth_attr");
			while (<$FP>) {
				next if /^(\s)*$/;  # remove spaces
				if (!$opt_verbose) {next if /^#.*/; }      # Remove comments if not set for verbose
				$sp .= $_;
			}
			close($FP);
			if($sp) {
				chomp($sp);
				$accesscontrol{'SUN Security authorization attributes file'} = $sp;
			}
		}
		if ( -f "/etc/security/prof_attr") {
			my $sp;
			open (my $FP, "< /etc/security/prof_attr");
			while (<$FP>) {
				next if /^(\s)*$/;  # remove spaces
				if (!$opt_verbose) {next if /^#.*/; }      # Remove comments if not set for verbose
				$sp .= $_;
			}
			close($FP);
			if($sp) {
				chomp($sp);
				$accesscontrol{'SUN Security profile attributes file'} = $sp;
			}
		}
	}

	# HP UX  password information
	if ( -f "/etc/default/security" ) {
		my $sp;
		open (my $FP, "< /etc/default/security");
		while (<$FP>) {
			next if /^(\s)*$/;  # remove spaces
			if (!$opt_verbose) {next if /^#.*/; }      # Remove comments if not set for verbose
			$sp .= $_;
		}
		close($FP);
		if($sp) {
			chomp($sp);
			$accesscontrol{'HP Default security configuration file'} = $sp;
		}
	}

	# IBM AIX  password information
	if ( -e "/etc/security/user" ) {
		my $sp;
		open (my $FP, "< /etc/security/user");
		while (<$FP>) {
			next if /^(\s)*$/;  # remove spaces
			if (!$opt_verbose) {next if /^#.*/; }      # Remove comments if not set for verbose
			$sp .= $_;
		}
		close($FP);
		if($sp) {
			chomp($sp);
			$accesscontrol{'IBM Security user file'} = $sp;
		}
	}
	if ( -e "/etc/security/login.cfg" ) {
		my $sp;
		open (my $FP, "< /etc/security/login.cfg");
		while (<$FP>) {
			next if /^(\s)*$/;  # remove spaces
			if (!$opt_verbose) {next if /^#.*/; }      # Remove comments if not set for verbose
			$sp .= $_;
		}
		close($FP);
		if($sp) {
			chomp($sp);
			$accesscontrol{'IBM Security login configuration file'} = $sp;
		}
	}
	
	# debug output
	if ($opt_debug) {
		print STDOUT "dc_accesscontrol complete ....\n";
	}
	return 0;

}

sub DC_FIM() {
	# debug output
	if ($opt_debug) {
		print STDOUT "dc_FIM started .... \n"
	}
	# scan processes and etc/init.d for presence of FIM software
	my $tfim;
	if ($OS =~ "SunOS") {
		$tfim = `ps -afe`;
	} else {
		$tfim = `ps ax`;
	}
	# add some file listing information
	$tfim .= `ls /bin`;
	$tfim .= `ls /usr/bin`;
	$tfim .= `ls /sbin`; 
	if ( -d "/usr/sbin") {$tfim .= `ls /usr/sbin`;}
	if ( -d "/usr/local/bin") {$tfim .= `ls /usr/local/bin`;}
	if ( -d "/opt/bin") {$tfim .= `ls /opt/bin`;}
	if ( -d "/usr/local/sbin") {$tfim .= `ls /usr/local/sbin`;}
	if ( -d "/opt/sbin") {$tfim .= `ls /opt/sbin`;}
	if ( -d "/etc") {$tfim .= `ls /etc`;}
	if ( -d "/usr/local/etc") {$tfim .= `ls /usr/local/etc`;}
	if ( -d "/opt/etc") {$tfim .= `ls /opt/etc`;}
	if ($tfim =~ /\bafick\b/i) {
		$FIM{'FIMservice'} = "Afick detected.";
	} elsif ($tfim =~ /\baide\b/i) {
		$FIM{'FIMservice'} = "AIDE detected.";
	} elsif ($tfim =~ /\bFCheck\b/i) {
		$FIM{'FIMservice'} = "FCheck detected.";
	} elsif ($tfim =~ /\bintegrit\b/i) {
		$FIM{'FIMservice'} = "Integrit detected.";
	} elsif ($tfim =~ /\bosiris\b/i) {
		$FIM{'FIMservice'} = "Osiris detected.";
	} elsif ($tfim =~ /\bossec\b/i) {
		$FIM{'FIMservice'} = "OSSEC detected.";
	} elsif ($tfim =~ /\bSamhain\b/i) {
		$FIM{'FIMservice'} = "Samhain detected.";
	} elsif ($tfim =~ /\btripwire\b/i) {
		$FIM{'FIMservice'} = "Tripwire detected.";
	} 
	if ($opt_debug) {
		print STDOUT "... dc_FIM complete \n";
	}
	return 0;
}

sub DC_Packages() {
	
	if ($opt_debug) {
		print STDOUT "dc_packages starting......\n";
	}
	
	# Set default value and overwrite as you go
	my $pkg;
	if ($opt_verbose) {
		if ( -f "/usr/bin/dpkg" ) { # must be debian
			$pkg = `dpkg -l 2>/dev/null`;
			chomp($pkg);
		} elsif ( -f "/usr/bin/lslpp" ) {  # Try AIX
			$pkg = `lslpp -LJ 2>/dev/null`;
			chomp($pkg);
		} elsif ( $OS =~ m/HP/ ) { # Try HP/UX
			$pkg = `swlist 2>/dev/null`;
			chomp($pkg);
		} elsif ( $OS =~ m/bsd/i ) { # Try some BSD
			$pkg = `pkg_info -a 2>/dev/null`;
			chomp($pkg);
		} elsif ( $OS =~ m/sun/i ) { # Try some Solaris
			$pkg = `pkginfo 2>/dev/null`;
			chomp($pkg);
		} elsif ( -f "/bin/rpm" ) { # must be CentOS or RHEL
			$pkg = `rpm -q -a 2>/dev/null`;
			chomp($pkg);
		} elsif ( $OS =~ m/darwin/i) {
			# It's a dumbass Mac
			$pkg = `system_profiler -detailLevel full SPApplicationsDataType`;
			chomp($pkg);
		} else {
			$pkg = '200 [WARN] Unable to identify installed packages on this system';
		}
	} else {
		$pkg = '200 [WARN] SystemReport run with Force flag or not run in verbose mode. Run with "-v" or "-f" option if you want to see this output';
	}
	
	# if ($opt_debug) {print STDOUT "Ending: $pkg \n";} # debug step to list all packages
	
	$packages{'Listing of installed packages'} = $pkg;
	
	if ($opt_debug) {
		print STDOUT "dc_packages End.\n";
	}
	
	return 0;
}

sub DC_patch() {
	use File::stat;
	use Time::Local;
	
	if ($opt_debug) {
		print STDOUT "dc_patch starting......\n";
	}
	
	# Set default value and overwrite as you go
	$patch{'Available Updates'} = '200 [WARN] Unable to identify available updates';
	
	if (-e "/var/log/apt/history.log") {
		if ($opt_debug) {print STDOUT "time test apt-get found\n";}
			
		my $filename = "/var/log/apt/history.log";
		my $time_result = getFileTimes($filename);
	
		if ( -M "/var/log/apt/history.log" > 90 ) {
			$patch{'Last Known Update'} = "400 [Fail] Last update logged greater than 90 days ago: " . $time_result;
		} else {
			$patch{'Last Known Update'} = "000 [PASS] Last update logged: " . $time_result;
		}
	} elsif ( -e "/var/log/yum.log" ){
		if ($opt_debug) {print STDOUT "time test yum.log found\n";}
		
		my $filename = "/var/log/yum.log";
		my $time_result = getFileTimes($filename);
		
		if ( -M "/var/log/yum.log" > 90 ) {
			$patch{'Last Known Update'} = "400 [Fail] Last update logged greater than 90 days ago: " . $time_result;
		} else {
			$patch{'Last Known Update'} = "000 [PASS] Last update logged: " . $time_result;
		}
	} elsif ( -e "/private/var/log/install.log" ){  # must be darwin  a Mac
		if ($opt_debug) {print STDOUT "time test /private/var/log/install.log found\n";}
		
		my $filename = "/private/var/log/install.log";
		my $time_result = getFileTimes($filename);
		
		if ( -M "/private/var/log/install.log" > 90 ) {
			$patch{'Last Known Update'} = "400 [Fail] Last update logged greater than 90 days ago: " . $time_result;
		} else {
			$patch{'Last Known Update'} = "000 [PASS] Last update logged: " . $time_result;
		}
	} elsif ( -e "/etc/objrepos/history" ){  # must be AIX box
		if ($opt_debug) {print STDOUT "time test /etc/objrepos/history found\n";}
		
		my $filename = "/etc/objrepos/history";
		my $time_result = getFileTimes($filename);
		
		if ( -M "/etc/objrepos/history" > 90 ) {
			$patch{'Last Known Update'} = "200 [WARN] Last update logged greater than 90 days ago: " . $time_result . ". Data from /etc/objrepos/history. Must manually verify.";
		} else {
			$patch{'Last Known Update'} = "000 [PASS] Last update logged: " . $time_result;
		}
	} else {
		$patch{'Last Known Update'} = '200 [WARN] Unable to determine when last update performed';
	}
	
	# Check for and run package management programs
	if ( -e "/usr/bin/apt-show-versions" ) {
		# Must be debian variant of Linux
		if (my $updates = `apt-show-versions -u 2> /dev/null`) {
			chomp($updates);
			$patch{'Available Updates'} = "400 [FAIL] Updates are available for this server \n" . $updates;
		} else {
			# If apt-show-versions -u returns nothing, then system is up to date
			$patch{'Available Updates'} = "000 [PASS] Check completed. No updates detected.";
		}
		
	} elsif (-e "/usr/bin/yum") {
		if ( $onNet ) {  # This is a BAD hack. I should check for presence of internal repo servers and not defaults
			# Must be Fedora or Red Hat
			my $updates = `yum check-update 2> /dev/null`;
			chomp($updates);
			my $tmpU;
			# The following may seem stupid, but yum responds with single line stating loading plugins no matter what
			# Must evaluate the results in order to discover the patch status
			open(my $fh, '<', \$updates);
			# each line of the scaler $updates
			while (<$fh>) {
				# Ignore blank lines and any line with 'Load' in it as in: Loading plugins:
				next if /^Load/;
				next if /^Setting/;
				next if /^(\s)*$/;  # remove spaces
				$tmpU .= $_;
			}
			close($fh);
			
			if ($tmpU) {
				$patch{'Available Updates'} = "400 [FAIL] Updates are available for this server \n" . $updates;
			} else {
				$patch{'Available Updates'} = "000 [PASS] Check completed. No updates detected.";
			}
		} else { # System is NOT on the network. this is a hack.
			$patch{'Available Updates'} = "200 [WARN] yum check-updates cannot get to a mirror server. QSA may need to manually verify this. Ask SA to run yum check-update manually.";

		}
	} elsif ( -e "/usr/bin/pkg") {  # for SunOS 11
		my $FMRI = `/usr/bin/pkg info kernel | grep -i fmri 2>/dev/null`;
		if ($FMRI) {
			$patch{'Available Updates'} = "200 [WARN] SunOS 11 detected\nFMRI = $FMRI \n  NOTE: QSA must evaluate the following three fields in the FMRI value: \n
\t175 -- The value 175 indicates that the system has Oracle Solaris 11 OS installed. This value is a constant for Oracle Solaris 11.\n
\t0 -- The first field to the right of �175� indicates the update release. In this example, there have been no updates to the initial release.\n
\t2 -- The next field contains the SRU value. In this example, the second patch bundle (called SRU2) has been installed on Oracle Solaris 11, update 0.\n
Other values in the FMRI field should be ignored. (See: https://docs.oracle.com/cd/E19836-01/E20747/z40003531559469.html)";
		}
	} elsif ( -e "/usr/bin/showrev" ) { # For SunOS 10
		# Procedure and steps for identification of patch updates for SunOS 10
		my $OSUpdt = "1. showrev (Installed kernel version)\n";
		$OSUpdt .= `/usr/bin/showrev | grep -i "kernel\ version" 2>/dev/null`;
		$OSUpdt .= "2. uname results:\n";
		$OSUpdt .= `uname -a 2>/dev/null`;
		$OSUpdt .= "3. Patch status:\n";
		$OSUpdt .= `/usr/bin/showrev -p | tail -4 2>/dev/null`;
		if ($OSUpdt) {
			$patch{'Available Updates'} = "200 [WARN] SunOS 10 detected\n";
			$patch{'Available Updates'} .= $OSUpdt;
			$patch{'Available Updates'} .= "   NOTE: QSA should compare the numeric patch and kernel values with the values listed on the Oracle web site to determine if the system is behind in patchs.\n";
			$patch{'Available Updates'} .= "(See: https://docs.oracle.com/cd/E19836-01/E20747/z40003531559469.html)"
		}
		
	}
	
	undef $@; #reset for alarm control
	if (-e "/usr/sbin/softwareupdate") {  
		#Must be a Mac ... Using eval with timeout since this is a dog
		my $evStat = eval {
			local $SIG{ALRM} = sub { print STDOUT "TimeOut for Mac software update check\n" };
			alarm 80;  # Set to 80 second timeout
			my $updates = `/usr/sbin/softwareupdate -l 2>&1`; #The stupid no updates message goes to STDERR
			chomp($updates);
			if ($updates =~ m/found/) {
				$patch{'Available Updates'} = "400 [FAIL] Updates are available for this server \n" . $updates;
			} else {
				$patch{'Available Updates'} = "000 [PASS] Check completed. No updates detected. \n" . $updates;
			}
			alarm 0;
		};
		alarm 0; # avoid race condition	
		if ($evStat =~ m/TimeOut/i ) {
			# timeout condition occurrs
			$patch{'Available Updates'} = "200 [INFO] Timeout while checking updates. Unable to identify updates. Recommend manual testing. \n";
		}
	} 
 	
 	if ($opt_debug) { print STDOUT "... dc_patch complete\n"; }
	return 0;
}

sub DC_include(){
	use File::stat;
	use Time::Local;
	
	if ($opt_debug) {
		print STDOUT "DC_Include starting......\n";
	}
	
	my @includeFiles=split(/,/,$opt_include);
	
	# Set default value and overwrite as you go
	$include{'List of Requested Files'} .= 'Listing of files requested:';
	$include{'List of Requested Files'} .= "\n";
	foreach my $f (@includeFiles) {
		$include{'List of Requested Files'} .= $f . "\n";
	}
	foreach my $f (@includeFiles) {
		if (-f $f) {
			my $listing;
			open(my $F, '<', "$f") or die "Unable to open file $f : $!";
				while (<$F>) {
					$listing .= $_;
				}
			close($F);
			$include{"$f"} .= $f . "\n";
			$include{"$f"} .= $listing;
			undef $listing;
		} elsif ( -d $f ) {
			$include{"$f"} .= "Requested file named $f is a directory\n";
		} else {
			$include{"f"} .= "Requested file named $f does not exist or is not a plane file.\n";
		}
	}
 	if ($opt_debug) { print STDOUT "... DC_Include complete\n"; }
	return 0;
}

sub WriteXML() {
	# Check for output file
	my $filename = $general{'Hostname'};
	$filename .= "-SystemRpt.xml";
	if ( -f "$filename" ) { unlink $filename; } # delete file if it already exists
	open (my $XO, "> $filename") or die "Unable to open xml file for writing : $!";

	# Write XML headers to the file
	my $stdheader = '<?xml version="1.0" encoding="UTF-8"?>';
	print($XO "$stdheader \n");
	if ($opt_rpt) {
		my $cssheader = '<?xml-stylesheet type="text/css" href="SystemReport.css"?>';
		print($XO "$cssheader \n");
	}
	print($XO "<Report>\n");
	print($XO "<General>\n");
	foreach my $key (keys %general) {
		my $value = $general{$key};
		print($XO "<$key>\n");
		print($XO "$value \n");
		print($XO "</$key>\n");
	}
	print($XO "</General>\n");
	print($XO "<Network Testing for External IP>\n");
	foreach my $key (keys %extIPtest) {
		my $value = $extIPtest{$key};
		print($XO "<$key>\n");
		print($XO "$value \n");
		print($XO "</$key>\n");
	}
	print($XO "</Network Testing for External IP>\n");
	print($XO "<Network Testing for URL reference>\n");
	foreach my $key (keys %nettest_URL) {
		my $value = $nettest_URL{$key};
		print($XO "<$key>\n");
		print($XO "$value \n");
		print($XO "</$key>\n");
	}
	print($XO "</Network Testing for URL reference>\n");
	print($XO "<Network Testing for IP reference>\n");
	foreach my $key (keys %nettest_IP) {
		my $value = $nettest_IP{$key};
		print($XO "<$key>\n");
		print($XO "$value \n");
		print($XO "</$key>\n");
	}
	print($XO "</Network Testing for IP reference>\n");	
	print($XO "<Network Testing for App_Web proxy>\n");
	foreach my $key (keys %extProxyTest) {
		my $value = $extProxyTest{$key};
		print($XO "<$key>\n");
		print($XO "$value \n");
		print($XO "</$key>\n");
	}
	print($XO "</Network Testing for App_Web proxy>\n");
	#  Temp not implemented
	#foreach my $key (keys %bootloader) {
	#	my $value = $bootloader{$key};
	#	print($XO "    <$key>\n");
	#	print($XO "$value \n");
	#	print($XO "    </$key>\n");
	#}
	print($XO "<Insecure Services>\n");
	foreach my $key (keys %InsecServices) {
		my $value = $InsecServices{$key};
		print($XO "<$key>\n");
		print($XO "$value \n");
		print($XO "</$key>\n");
	}
	print($XO "</Insecure Services>\n");
	print($XO "<Insecure Processes>\n");
	foreach my $key (keys %Processes) {
		my $value = $Processes{$key};
		print($XO "<$key>\n");
		print($XO "$value \n");
		print($XO "</$key>\n");
	}
	print($XO "</Insecure Processes>\n");
	print($XO "<Services>\n");
	foreach my $key (keys %Services) {
		my $value = $Services{$key};
		print($XO "<$key>\n");
		print($XO "$value \n");
		print($XO "</$key>\n");
	}
	print($XO "</Services>\n");
	print($XO "<Batchjobs>\n");
	foreach my $key (keys %batchjobs) {
		my $value = $batchjobs{$key};
		print($XO "<$key>\n");
		print($XO "$value \n");
		print($XO "</$key>\n");
	}
	print($XO "</Batchjobs>\n");
	print($XO "<Logging>\n");
	foreach my $key (keys %logging) {
		my $value = $logging{$key};
		print($XO "<$key>\n");
		print($XO "$value \n");
		print($XO "</$key>\n");
	}
	print($XO "</Logging>\n");
	print($XO "<NTP>\n");
	foreach my $key (keys %ntp) {
		my $value = $ntp{$key};
		print($XO "<$key>\n");
		print($XO "$value \n");
		print($XO "</$key>\n");
	}
	print($XO "</NTP>\n");
	print($XO "<RemoteAccessControl>\n");
	foreach my $key (keys %ssh) {
		my $value = $ssh{$key};
		print($XO "<$key>\n");
		print($XO "$value \n");
		print($XO "</$key>\n");
	}
	print($XO "</RemoteAccessControl>\n");
	print($XO "<Permissions>\n");
	foreach my $key (keys %perms) {
		my $value = $perms{$key};
		print($XO "<$key>\n");
		print($XO "$value \n");
		print($XO "</$key>\n");
	}
	print($XO "</Permissions>\n");
	print($XO "<AccessControl>\n");
	foreach my $key (keys %accesscontrol) {
		my $value = $accesscontrol{$key};
		print($XO "<$key>\n");
		print($XO "$value \n");
		print($XO "</$key>\n");
	}
	print($XO "</AccessControl>\n");
	print($XO "<Network>\n");
	foreach my $key (keys %network) {
		my $value = $network{$key};
		print($XO "<$key>\n");
		print($XO "$value \n");
		print($XO "</$key>\n");
	}
	print($XO "</Network>\n");
	print($XO "<FIM>\n");
	foreach my $key (keys %FIM) {
		my $value = $FIM{$key};
		print($XO "<$key>\n");
		print($XO "$value \n");
		print($XO "</$key>\n");
	}
	print($XO "</FIM>\n");
	#print($XO "  <Patch>\n");
	# temp not implemented
	#foreach my $key (keys %patch) {
	#	my $value = $patch{$key};
	#	print($XO "    <$key>\n");
	#	print($XO "$value \n");
	#	print($XO "    </$key>\n");
	#}
	#print($XO "  </Patch>\n");
	print($XO "</Report>\n");
	close($XO);
	return 0;
}

sub WriteHTML() {
	# prepare report document
	# copy XML document file to html and append CSS.
	my $filename = $hostname;
	$filename .= "-SystemReport.html";
	if ( -f "$filename" ) { unlink $filename; } # delete file if it already exists
	open (my $RO, "> $filename") or die "Unable to open $filename file for writing : $!";
	print($RO "<html>\n");
	print($RO "<head>\n");
	print($RO "    <title>PSC Unix Server Configuration Audit Report on host: $hostname</title>\n");
	print($RO '<meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />');
	print($RO "\n");
	print($RO '<meta name="title" content="PCI Server Configuration Audit Report" />');
	print($RO "\n");
	print($RO '<meta name="author" content="Tom Arnold, Vice President, PSC" />');
	print($RO "\n");
	# Copyright TAG HACK due to html structure
	print($RO '<meta name="copyright" content="(c) Copyright Payment Software Company Inc. (2008-2018) All rights reserved" />');
	print($RO "\n");
	print($RO '<meta name="generator" content="SystemReport.pl from PSC" />');
	print($RO "\n");
	print($RO '<meta name="generator-url" content="www.paysw.com" />');
	print($RO "\n");
	print($RO '<style type="text/css">');
	print($RO "\n");
	print($RO 'body {
		background-color: #FFFFFF; 
		font-family:Open Sans, Lucida Sans Unicode, Lucida Grande, 
		sans-serif;
		font-size: 10pt; 
		text-align: left; 
	}
	
	b {
		color: #395596;
		font-size:12px;
		font-stretch:semi-expanded;
	}
	
	p.red {
		color: #FF0000;
	}
	
	p.orange {
		color: #FFA500;
	}
	
	@font-face {
	    font-family: logoFont;
	    src: url(COLONNA.TTF);
	}
	
	div.logo {
	  	font-family: \'Colonna MT\', logoFont;
		font-size:104px;
	}
	
	div.reportpart {
		margin-top: 10px; 
		margin-bottom: 30px;
	}
	
	div.reportparttitle {
		background: -webkit-linear-gradient(35deg, #395596, #00c0ee); /* For Safari 5.1 to 6.0 */
	  	background: -o-linear-gradient( 35deg, #395596, #00c0ee); /* For Opera 11.1 to 12.0 */
	  	background: -moz-linear-gradient(35deg, #395596, #00c0ee); /* For Firefox 3.6 to 15 */
	  	background: linear-gradient(35deg, #395596, #00c0ee); /* Standard syntax */
		width:100%;	 
		border: 1px solid #395596; 
		border-radius: 25px; 
		padding-top: 10px; 
		padding-bottom: 10px; 
		margin-top: 10px; 
		margin-bottom: 20px; 
		text-align: center; 
		font-size: 18px;
		color: #FFF;
		box-shadow: 10px 10px 5px #CCC;
		-moz-box-shadow: 10px 10px 5px #CCC;
		-webkit-box-shadow: 10px 10px 5px #CCC;
		-o-box-shadow: 10px 10px 5px #CCC;
	}
	
	div.reportsectiontitle {
		background: -webkit-linear-gradient(35deg, #395596, #00c0ee); /* For Safari 5.1 to 6.0 */
	  	background: -o-linear-gradient( 35deg, #395596, #00c0ee); /* For Opera 11.1 to 12.0 */
	  	background: -moz-linear-gradient(35deg, #395596, #00c0ee); /* For Firefox 3.6 to 15 */
	  	background: linear-gradient(35deg, #395596, #00c0ee); /* Standard syntax */
		padding:7px; 
		padding-left: 15px;
		padding-right: 15px;
		border: 1px solid #395596; 
		border-radius: 25px;
		font-size: 16px; 
		font-weight: bold; 
		margin-top: 15px;
		margin-bottom: 25px;
		color: #FFF;
		white-space:pre-wrap;
		box-shadow: 10px 10px 5px #CCC;
		-moz-box-shadow: 10px 10px 5px #CCC;
		-webkit-box-shadow: 10px 10px 5px #CCC;
		-o-box-shadow: 10px 10px 5px #CCC;
	}
	
	div.reportsectionbody {
		margin-left: 20px; 
		margin-right: 20px;
		color: #333;
	}
	
	div.reportsectiontitlecritical {
		background: -webkit-linear-gradient(35deg, #FFF, #CCC); /* For Safari 5.1 to 6.0 */
	  	background: -o-linear-gradient( 35deg, #FFF, #CCC); /* For Opera 11.1 to 12.0 */
	  	background: -moz-linear-gradient(35deg, #FFF, #CCC); /* For Firefox 3.6 to 15 */
	  	background: linear-gradient(35deg, #FFF, #CCC); /* Standard syntax */ 
		padding:7px; 
		padding-left: 15px;
		padding-right: 15px;
		border: 2px solid #F00;
		border-radius: 25px; 
		font-size:12px; 
		font-weight: 500;
		color:#F00
	}
	
	div.reportsectiontitlehigh {
		background: -webkit-linear-gradient(35deg, #F00, #C10000); /* For Safari 5.1 to 6.0 */
	  	background: -o-linear-gradient( 35deg, #F00, #C10000); /* For Opera 11.1 to 12.0 */
	  	background: -moz-linear-gradient(35deg, #F00, #C10000); /* For Firefox 3.6 to 15 */
	  	background: linear-gradient(35deg, #F00, #C10000); /* Standard syntax */ 
		padding:7px; 
		padding-left: 15px;
		padding-right: 15px;
		border: 1px solid #395596; 
		border-radius: 25px;
		font-size:12px;
		font-weight: 100;
		color:#FFF;
	}
	
	div.reportsectiontitlemedium {
		background: -webkit-linear-gradient(35deg, #F60, #F90); /* For Safari 5.1 to 6.0 */
	  	background: -o-linear-gradient( 35deg, #F60, #F90); /* For Opera 11.1 to 12.0 */
	  	background: -moz-linear-gradient(35deg, #F60, #F90); /* For Firefox 3.6 to 15 */
	  	background: linear-gradient(35deg, #F60, #F90); /* Standard syntax */ 
		padding:7px; 
		padding-left: 15px;
		padding-right: 15px;
		border: 1px solid #395596; 
		border-radius: 25px;
		font-size:12px;
		font-weight: 75;
		color:#FFF;
	}
	
	div.reportsectiontitlelow {
		background: -webkit-linear-gradient(35deg, #FF0, #FF6); /* For Safari 5.1 to 6.0 */
	  background: -o-linear-gradient( 35deg, #FF0, #FF6); /* For Opera 11.1 to 12.0 */
	  background: -moz-linear-gradient(35deg, #FF0, #FF6); /* For Firefox 3.6 to 15 */
	  background: linear-gradient(35deg, #FF0, #FF6); /* Standard syntax */ 
		padding:7px; 
		padding-left: 15px;
		padding-right: 15px;
		border: 1px solid #395596;
		border-radius: 25px;
		font-size:12px;
		font-weight: 50;
		color:#000;
	}
	
	div.reportsectiontitleinfo {
		background: #000; 
		padding:7px;
		padding-left: 15px;
		padding-right: 15px;
		border: 1px solid #395596; 
		border-radius: 25px;
		font-size:16px; 
		font-weight: bold;
		color:#FFF;
	}
	
	div.reportlinebodyhigh {
		margin-left: 20px; 
		margin-right: 20px; 
		font-color: #00c0ee; 
		font-family: Open Sans, Lucida Sans Unicode, Lucida Grande, sans-serif;    
		padding: 5px; 
		padding-left: 15px;
		padding-right: 15px;
		font-size: 14px;
	}
	
	div.reportlinebody {
		margin-left: 20px; 
		margin-right: 20px; 
		font-family: Open Sans, Lucida Sans Unicode, Lucida Grande, sans-serif;    
		padding: 5px; 
		font-size: 14px;
	}
	
	div.reportlinebodysm {
		margin-left: 20px; 
		margin-right: 20px; 
		font-family: Open Sans, Lucida Sans Unicode, Lucida Grande, sans-serif;    
		padding: 5px; 
		font-size: 10px;
	}
	
	a:link {
		color: #00c0ee; 
		text-decoration: none;
	}
	
	a:visited {
		color:#333; 
		text-decoration: none;
	}
	
	a:hover {
		color: #395596; 
		text-decoration: none;
	}
	
	table {
		background-color: #F3F3F3; 
		width: 100%; 
		font-size: 12px; 
		padding:7px; 
		padding-left: 15px;
		padding-right: 15px;
		border: 1px solid #6E9BCD;
		border-radius: 25;
	}
	
	tr:nth-child(even) {
		background-color:#f9f9f9; }
	
	td {
		vertical-align: top; 
		text-align: center; 
		padding: 3px;
	}
	
	td.l {
		vertical-align: top; 
		text-align: left;
		padding: 3px;
	}
	
	td.r {
		vertical-align: top; 
		text-align: right; 
		padding: 3px;
	}
	
	td.leftRed {
		vertical-align: top; 
		text-align: left; 
		padding: 3px;
		color: #FF0000;
	}
	
	td.left {
		text-align: left; 
	}
	
	td.red {
		color: #FF0000;
	}
	
	pre {
		background-color: #F3F3F3; 
		font-family: Open Sans, Lucida Sans Unicode, Lucida Grande, sans-serif;   
		white-space:pre-wrap;
		text-justify:inter-word;
		padding: 7px;
		border-width: 1px;
		border-style:groove;
		border: 1px solid #395596; 
		border-radius: 25px;
		font-size: 12px;
	}
  </style>');
	print($RO "\n</head>\n");
	print($RO "<body>\n");
	print($RO "<div class=reportparttitle>\n");
	my $today = `date`;
	print($RO "<p>PSC System Report for $hostname</p><p>as of $today</p>");
	print($RO "</div>\n");
	print($RO "<br />\n");
	
	# General information
	print($RO "<div class=reportsectiontitle>\n");
	print($RO "General System Information\n");
	print($RO "</div>\n");
	print($RO "<div class=reportsectionbody>\n");
	print($RO "<p>This section of the report presents general information about the server. </p>\n<p>Some portions of the report 
	contain the results of actual testing. For instance, the network testing portion examines the server's ability to open 
	connections to arbitrary addresses on the public Internet. Other sections of the report provide details that an auditor may 
	need to verify manually.</p>\n<p>Because of inherent limitations, error or fraud may occur and not be detected. Even upon 
	completion of our work, we may not identify all security issues or recommend all possible remedial actions. Furthermore, 
	the projection of any conclusions, based on our findings, to future periods is subject to the risk that (1) changes made 
	to the system or controls, (2) changes in processing requirements, or (3) degree of compliance with the policies or procedures 
	may alter the validity of such conclusions. </p>\n");
	foreach my $k (keys %general) {
		my $value = $general{$k};
		print($RO "<p>$k</p>\n");
		print($RO "<pre>\n");
		# Symbol substitution to fix issues
		$value =~ s/</&lt;/g;
		$value =~ s/>/&gt;/g;
		print($RO "$value \n");
		print($RO "</pre>\n");
	}
	print($RO "</div>\n");
	
	# Include (This section is a custom include for a file)
	# Only runs if $oopt_include is set
	if ($opt_include) {
		print($RO "<div class=reportsectiontitle>\n");
		print($RO "Custom file include\n");
		print($RO "</div>\n");
		print($RO "<div class=reportsectionbody>\n");
		print($RO "<p>This section of the report presents a dump of file data from the target system that was included
		by the request of the user when the '--include' option was activated. This information is in raw form and has not
		been analyzed. </p>\n");
		foreach my $k (keys %include) {
			my $value = $include{$k};
			print($RO "<p>$k</p>\n");
			print($RO "<pre>\n");
			# Symbol substitution to fix issues
			$value =~ s/</&lt;/g;
			$value =~ s/>/&gt;/g;
			print($RO "$value \n");
			print($RO "</pre>\n");
		}
		print($RO "</div>\n");
	}
	
	# %bootloader;  # boot loader information from target system
	
	# %extIPtest ; # Listing and analysis of external IP presence
	my $items = keys %extIPtest;
	if ($items < 1 ) {
		# Set color flag if missing
		print($RO "<div class=reportsectiontitlehigh>\n");
		print($RO "External IP Address Detection Test");
		print($RO "</div>\n");
		print($RO "<div class=reportsectionbody>\n");
		print($RO "<p>Testing for external IP address from Platform $hostname. This test uses outbound network route to identify if this server 
		has a valid external IP address and presence on the public Internet. This is an inital test of the firewall and network security 
		controls supporting this server.\n</p>");
	} else {
		foreach my $k (keys %extIPtest) {
			my $value = $extIPtest{$k};
			if ($value =~ m/000/) {
				print($RO "<div class=reportsectiontitle>\n");
				print($RO "External IP Address Detection Test");
				print($RO "</div>\n");
				print($RO "<div class=reportsectionbody>\n");
				print($RO "<p>Testing for external IP address from Platform $hostname. This test sent a signal outboud through the internal network 
				to an external server on public Internet in an attempt to identify a valid external IP address. No valid response was received from the external target. 
				This may suggest that this server is isolated or that the external target did not respond. Review additional tests in the network 
				testing section of this report to futher validate server isolation.</p>\n");
				print($RO "<p>$k</p>\n");
				print($RO "<pre>\n");
				print($RO "$value \n");
				print($RO "</pre>\n");
			} else {
				print($RO "<div class=reportsectiontitlehigh>\n");
				print($RO "External IP Address Detection Test");
				print($RO "</div>\n");
				print($RO "<div class=reportsectionbody>\n");
				print($RO "<p>Testing for external IP address from Platform $hostname. This test sent a signal outboud through the internal network 
				to an external server and retrieved a valid external IP address. This server has direct access to the public Internet through the 
				the internal network infrastructure. This server is not isolated. </p>\n<p>This test utilized raw socket network communication 
				techniques and is considered very accurate. The presence of these results reflects the lack of network isolation controls to prevent
				this server from opening connections and communicating to arbitrary servers on the Public Internet. </p>\n");
				print($RO "<p class=red>$k</p>\n");
				print($RO "<pre>\n");
				print($RO "$value \n");
				print($RO "</pre>\n");
				print($RO "<p>IP Registration Information on Discovered IP address</p>\n");
				print($RO "<p>Executed <i>whois</i> query to obtain registration information on detected external IP address. Assessor should
				verify that this IP address is properly registered to an organization that is either the ISP for Client or the Client themselves. 
				Further, the Assessor should check to verify that this IP address is within the scope of PCI external scans and PCI external 
				penetration testing. </p>\n");
				foreach my $w (keys %extIPwhois) {
					my $nv = $extIPwhois{$w};
					print($RO "<p class=red>$w</p>\n");
					print($RO "<pre>\n");
					print($RO "$nv \n");
					print($RO "</pre>\n");				
				}
			}
		}
	}
	print($RO "</div>\n");
	
	# Web or Application proxy detection
	# %nettest_URL and %nettest_IP # Listing and analysis oof server's ability to communicate with arbitrary public Internet servers
	# URL testing and results listing
	my $headingTest = 'PASS'; # Default to Pass
	foreach my $t (keys %extProxyTest) {
		if ( $extProxyTest{$t} =~ m[FAIL] ) {
			# as soon as you find one that fales, get out
			$headingTest = 'FAIL';
			last;
		} elsif ( $extProxyTest{$t} =~ m[WARN] ) {
			$headingTest = 'WARN';
		} 
	}
	
	if ($headingTest !~ m/PASS/ ) {
		# Set color flag if missing
		if ($headingTest =~ m/FAIL/) {print($RO "<div class=reportsectiontitlehigh>\n");}
		else { print($RO "<div class=reportsectiontitlemedium>\n"); }
		print($RO "Outbound Web or Application Proxy Test\n");
		print($RO "</div>\n");
		print($RO "<div class=reportsectionbody>\n");
		print($RO "<p>Test of the ability for server $hostname to open a port 80 (http) connection to specific site and receive a response from 
		an application or Web proxy server. This test verifies that a valid HTTP response is returned and looks for a \"magic\" value from the 
		target server. The presence of both a good response with the magic value suggests that a outbound proxy server is resopnding on the 
		network. This condition may not mean that a specific server has direct Internet access, but suggests that a pxoxy may be interacting. 
		Any auditor receiving this message should inspect for the presence of the proxy and verify that it is properly secured.</p>\n");
		foreach my $k (keys %extProxyTest) {
			my $value = $extProxyTest{$k};
			print($RO "<tr>\n");
			print($RO "<p class=red>$k</p>\n");
			print($RO "<pre>\n");
			print($RO "$value \n");
			print($RO "</pre>\n");
		}
	} else {
		print($RO "<div class=reportsectiontitle>\n");
		print($RO "Outbound Web or Application Proxy Test\n");
		print($RO "</div>\n");
		print($RO "<div class=reportsectionbody>\n");
		print($RO "<p>Test of the ability for server $hostname to open a port 80 (http) connection to specific site and receive a response from 
		an application or Web proxy server. This test verifies that a valid HTTP response is returned and looks for a \"magic\" value from the 
		target server. The presence of both a good response with the magic value suggests that a outbound proxy server is resopnding on the 
		network. </p>\n");
		foreach my $k (keys %extProxyTest) {
			my $value = $extProxyTest{$k};
			print($RO "<tr>\n");
			print($RO "<p>$k</p>\n");
			print($RO "<pre>\n");
			print($RO "$value \n");
			print($RO "</pre>\n");
		}

	}
	print($RO "</div> \n");
		
	# %nettest_URL and %nettest_IP # Listing and analysis oof server's ability to communicate with arbitrary public Internet servers
	# URL testing and results listing
	$headingTest = 'PASS'; # Default to Pass
	foreach my $t (keys %nettest_URL) {
		if ($nettest_URL{$t} =~ m[FAIL] ) {
			# as soon as you find one that fales, get out
			$headingTest = 'FAIL';
			last;
		} elsif ( $nettest_URL{$t} =~ m[WARN] ) {
			$headingTest = 'WARN';
		} 
	}
	
	if ($headingTest !~ m/PASS/ ) {
		# Set color flag if missing
		if ($headingTest =~ m/FAIL/) {print($RO "<div class=reportsectiontitlehigh>\n");}
		else { print($RO "<div class=reportsectiontitlemedium>\n"); }
		print($RO "Public Internet Communications to URL Test\n");
		print($RO "</div>\n");
		print($RO "<div class=reportsectionbody>\n");
		print($RO "<p>Test of the ability for server $hostname to open a port 80 (http) connection to arbitrary sites on the public Internet. 
		This test will verify as to whether or not the local network where this server is hosted is suitably isolated from external networks; 
		when the connection is initiated by this server. For each URL listed below, the results of the test are presented. Network and systems
		administration staff are encouraged to review and understand these results. If this test is performed as a result of an audit, check
		with your Assessor when evaluating these results.</p>\n<p>This test utilized raw socket network communication 
		techniques and is considered very accurate. The presence of these results reflects the lack of network isolation controls to prevent
		this server from opening connections and communicating to arbitrary servers on the Public Internet. </p>\n</div>");
		print($RO "<table>\n");
		print($RO "<tr>\n");
		print($RO "<th>Site</th>\n");
		print($RO "<th>Test Result</th>\n");
		print($RO "</tr>\n");foreach my $k (keys %nettest_URL) {
			my $value = $nettest_URL{$k};
			print($RO "<tr>\n");
			if ($value =~ m/FAIL/) { 
				print($RO "<td>$k</td><td class=Red>$value</td>\n");
			} else {
				print($RO "<td>$k</td><td>$value</td>\n");
			}
			print($RO "</tr>\n");
		}
		print($RO "</table>\n");
		print($RO "<BR />\n");
	} else {
		print($RO "<div class=reportsectiontitle>\n");
		print($RO "Public Internet Communications to URL Test\n");
		print($RO "</div>\n");
		print($RO "<div class=reportsectionbody>\n");
		print($RO "<p>Test of the ability for server $hostname to open a port 80 (http) connection to arbitrary sites on the public Internet. 
		This test will verify as to whether or not the local network where this server is hosted is suitably isolated from external networks; 
		when the connection is initiated by this server. For each URL listed below, the results of the test are presented. Network and systems
		administration staff are encouraged to review and understand these results. If this test is performed as a result of an audit, check
		with your Assessor when evaluating these results.</p>\n");
		print($RO "<p>No tests to external sites were successful.</p>\n");
		print($RO "</div> \n");
	}
	
	# IP address testing and results listing
	$headingTest = 'PASS'; # reset stupid flag to see if they passed or failed
	foreach my $t (keys %nettest_IP) {
		if ($nettest_IP{$t} =~ m[FAIL] ) {
			# as soon as you find one that fales, get out
			$headingTest = 'FAIL';
			last;
		} elsif ( $nettest_IP{$t} =~ m[WARN] ) {
			$headingTest = 'WARN';
		} 
	}
	
	if ($headingTest !~ m/PASS/ ) {
		# Set color flag if missing
		if ($headingTest =~ m/FAIL/) {print($RO "<div class=reportsectiontitlehigh>\n");}
		else { print($RO "<div class=reportsectiontitlemedium>\n"); }
		print($RO "Public Internet Communications to IP Address Test\n");
		print($RO "</div>\n");
		print($RO "<div class=reportsectionbody>\n");
		print($RO "<p>Test of the ability for server $hostname to open a port 80 (http) connection to arbitrary IP address on the public Internet. 
		This test will verify as to whether or not the local network where this server is hosted is suitably isolated from external networks; 
		when the connection is initiated by this server. For each site listed below, the results of the IP Address test test are presented. Network and systems
		administration staff are encouraged to review and understand these results. If this test is performed as a result of an audit, check
		with your Assessor when evaluating these results.</p>\n<p>This test utilized raw socket network communication 
		techniques and is considered very accurate. The presence of these results reflects the lack of network isolation controls to prevent
		this server from opening connections and communicating to arbitrary servers on the Public Internet. </p>\n</div>");
		print($RO "<table>\n");
		print($RO "<tr>\n");
		print($RO "<th>Site</th>\n");
		print($RO "<th>Test Result</th>\n");
		print($RO "</tr>\n");
		foreach my $k (keys %nettest_IP) {
			my $value = $nettest_IP{$k};
			print($RO "<tr>\n");
			if ($value =~ m/FAIL/) { 
				print($RO "<td>$k</td><td class=Red>$value</td>\n");
			} else {
				print($RO "<td>$k</td><td>$value</td>\n");
			}
			print($RO "</tr>\n");
		}
		print($RO "</table>\n");
		print($RO "<BR />\n");
	} else {
		print($RO "<div class=reportsectiontitle>\n");
		print($RO "Public Internet Communications to IP Test\n");
		print($RO "</div>\n");
		print($RO "<div class=reportsectionbody>\n");
		print($RO "<p>Test of the ability for server $hostname to open a port 80 (http) connection to arbitrary sites on the public Internet. 
		This test will verify as to whether or not the local network where this server is hosted is suitably isolated from external networks; 
		when the connection is initiated by this server. For each URL listed below, the results of the test are presented. Network and systems
		administration staff are encouraged to review and understand these results. If this test is performed as a result of an audit, check
		with your Assessor when evaluating these results.</p>\n");
		print($RO "<p>No tests to external IP addresses were successful.</p>\n");
		print($RO "</div> \n");
	}
		
	# Insecure Service Detection
	$headingTest = 'PASS'; # reset stupid flag to see if they passed or failed
	foreach my $t (keys %InsecServices) {
		if ($InsecServices{$t} =~ m[FAIL] ) {
			# as soon as you find one that fales, get out
			$headingTest = 'FAIL';
			last;
		} elsif ( $InsecServices{$t} =~ m[WARN] ) {
			$headingTest = 'WARN';
		} 
	}
	
	if ($headingTest !~ m/PASS/ ) {
		# Set color flag if missing
		if ($headingTest =~ m/FAIL/) {print($RO "<div class=reportsectiontitlehigh>\n");}
		else { print($RO "<div class=reportsectiontitlemedium>\n"); }
		print($RO "Running Services - Examination for insecure service detection\n");
		print($RO "</div>\n");
		print($RO "<div class=reportsectionbody>\n");
		print($RO "<p>Examine the list of running services on $hostname using service --status-all or similar command. Then program analyzes the 
		list of services in an attempt to identify and detect any common, insecure services. This test is not definitive  
		and may not detect all possible insecure services. This test only examines the list of insecure services that are 
		commonly identified by the operating system vendor. Client and QSA are encouraged to examine the full listing of the 
		services in the following section to identify other running processes that may be considered risky. Also, for all items noted as FAIL, 
		Client should provide a description of the additional security controls that have been put in place to protect this 
		server and compensate for the presence of the running service. </p>\n</div>");
		print($RO "<table>\n");
		print($RO "<tr>\n");
		print($RO "<th>Insecure Service</th>\n");
		print($RO "<th>Test Result</th>\n");
		print($RO "</tr>\n");
		foreach my $k (keys %InsecServices) {
			my $value = $InsecServices{$k};
			print($RO "<tr>\n");
			if ($value =~ m/FAIL/) { 
				print($RO "<td>$k</td><td class=red>$value</td>\n");
			} else {
				print($RO "<td>$k</td><td>$value</td>\n");
			}
			print($RO "</tr>\n");
		}
		print($RO "</table>\n");
		print($RO "<BR />\n");
		print($RO "</div>\n");
	} else {
		print($RO "<div class=reportsectiontitle>\n");
		print($RO "Running Services - Examination for insecure service detection\n");
		print($RO "</div>\n");
		print($RO "<div class=reportsectionbody>\n");
		print($RO "<p>Examine the list of running services on $hostname using service --status-all or similar command. Then program analyzes the 
		list of services in an attempt to identify and detect any common, insecure services. This test is not definitive  
		and may not detect all possible insecure services. This test only examines the list of insecure services that are 
		commonly identified by the operating system vendor. Client and QSA are encouraged to examine the full listing of the 
		services in the following section to identify other running processes that may be considered risky. </p>\n");
		print($RO "<table>\n");
		print($RO "<tr>\n");
		print($RO "<th>Insecure Service</th>\n");
		print($RO "<th>Test Result</th>\n");
		print($RO "</tr>\n");
		foreach my $k (keys %InsecServices) {
			my $value = $InsecServices{$k};
			print($RO "<tr>\n");
			if ($value =~ m/FAIL/) { 
				print($RO "<td>$k</td><td class=Red>$value</td>\n");
			} else {
				print($RO "<td>$k</td><td>$value</td>\n");
			}
			print($RO "</tr>\n");
		}
		print($RO "</table>\n");
		print($RO "<BR />\n");
		print($RO "</div>\n");
	}
	
	# Insecure Process Detection
	$headingTest = 'PASS'; # reset stupid flag to see if they passed or failed
	foreach my $t (keys %Processes) {
		if ($Processes{$t} =~ m[FAIL] ) {
			# as soon as you find one that fales, get out
			$headingTest = 'FAIL';
			last;
		} elsif ( $Processes{$t} =~ m[WARN] ) {
			$headingTest = 'WARN';
		} 
	}
	
	if ($headingTest !~ m/PASS/ ) {
		# Set color flag if missing
		if ($headingTest =~ m/FAIL/) {print($RO "<div class=reportsectiontitlehigh>\n");}
		else { print($RO "<div class=reportsectiontitlemedium>\n"); }
		print($RO "Running Process Examination for insecure service detection\n");
		print($RO "</div>\n");
		print($RO "<div class=reportsectionbody>\n");
		print($RO "<p>Examine the running processes on $hostname by running a process show (ps aux). Then program analyzes the 
		list of running process in an attempt to identify and detect any common, insecure services. This test is not definitive 
		and may not detect all possible insecure services. This test only examines the list of insecure services that are 
		commonly identified by the operating system vendor. Client and QSA are encouraged to examine the full listing of the 
		process show to identify other running processes that may be considered risky. Also, for all items noted as FAIL, 
		Client should provide a description of the additional security controls that have been put in place to protect this 
		server and compensate for the presence of the running service. </p>\n</div>");
		print($RO "<table>\n");
		print($RO "<tr>\n");
		print($RO "<th>Insecure Service</th>\n");
		print($RO "<th>Test Result</th>\n");
		print($RO "</tr>\n");
		foreach my $k (keys %Processes) {
			my $value = $Processes{$k};
			print($RO "<tr>\n");
			if ($value =~ m/FAIL/) { 
				print($RO "<td>$k</td><td class=Red>$value</td>\n");
			} else {
				print($RO "<td>$k</td><td>$value</td>\n");
			}
			print($RO "</tr>\n");
		}
		print($RO "</table>\n");
		print($RO "<BR />\n");
		print($RO "</div>\n");
	} else {
		print($RO "<div class=reportsectiontitle>\n");
		print($RO "Running Process Examination for insecure service detection\n");
		print($RO "</div>\n");
		print($RO "<div class=reportsectionbody>\n");
		print($RO "<p>Examine the running processes on $hostname by running a process show (ps aux). Then program analyzes the 
		list of running process in an attempt to identify and detect any common, insecure services. This test is not definitive 
		and may not detect all possible insecure services. This test only examines the list of insecure services that are 
		commonly identified by the operating system vendor. Client and QSA are encouraged to examine the full listing of the 
		process show to identify other running processes that may be considered risky.</p>\n");
		print($RO "<table>\n");
		print($RO "<tr>\n");
		print($RO "<th>Insecure Service</th>\n");
		print($RO "<th>Test Result</th>\n");
		print($RO "</tr>\n");
		foreach my $k (keys %Processes) {
			my $value = $Processes{$k};
			print($RO "<tr>\n");
			if ($value =~ m/FAIL/) { 
				print($RO "<td>$k</td><td class=Red>$value</td>\n");
			} else {
				print($RO "<td>$k</td><td>$value</td>\n");
			}
			print($RO "</tr>\n");
		}
		print($RO "</table>\n");
		print($RO "<BR />\n");
		print($RO "</div>\n");
	}
	
	# %Services;  # Listing of services and top processes
	$items = keys %Services;
	if ($items < 1 ) {
		# Set color flag if missing
		print($RO "<div class=reportsectiontitlemedium>\n");
		print($RO "Services Detected on Platform\n");
		print($RO "</div>\n");
		print($RO "<div class=reportsectionbody>\n");
		print($RO "<p>No running Services configuration information detected</p>\n");
	} else {
		print($RO "<div class=reportsectiontitle>\n");
		print($RO "Services Detected on Platform\n");
		print($RO "</div>\n");
		print($RO "<div class=reportsectionbody>\n");
		print($RO "<p>Depending on the distribution or type of NIX operating system, this section of the report attempts to identify a listing of 
		running services. In some cases, service detection may be quite simple. In others, this program dumps values of files that should give 
		the Assessor an idea of the service running on the platform.</p>\n");
		foreach my $k (keys %Services) {
			my $value = $Services{$k};
			print($RO "<p>$k</p>\n");
			print($RO "<pre>\n");
			# quote and replace the < and > symbols in $value so they behave in html
			$value =~ s/</&lt;/g;
			$value =~ s/>/&gt;/g;
			print($RO "$value \n");
			print($RO "</pre>\n");
		}
	}
	print($RO "</div>\n");
	
	# %batchjobs; # batch job listing
	$items = keys %batchjobs;
	if ($items < 1 ) {
		print($RO "<div class=reportsectiontitlemedium>\n");
		print($RO "Batch Jobs Defined on Platform\n");
		print($RO "</div>\n");
		print($RO "<div class=reportsectionbody>\n");
		print($RO "<p>No Batch Job configuration information detected</p>\n");
	} else {
		print($RO "<div class=reportsectiontitle>\n");
		print($RO "Batch Jobs Defined on Platform\n");
		print($RO "</div>\n");
		print($RO "<div class=reportsectionbody>\n");
		print($RO "<p>This portion of the report examines typical batch operations that would be run on the server. The objective is to 
		examine what operations are in place so that an assessor can determine if any batch jobs may create a security issue on the platform.</p>\n");
		foreach my $k (keys %batchjobs) {
			my $value = $batchjobs{$k};
			print($RO "<p>$k</p>\n");
			print($RO "<pre>\n");
			$value =~ s/</&lt;/g;
			$value =~ s/>/&gt;/g;
			print($RO "$value \n");
			print($RO "</pre>\n");
		}
	}
	print($RO "</div>\n");
	
	# %logging;  # log and logging routines
	$items = keys %logging;
	if ($items < 1 ) {
		print($RO "<div class=reportsectiontitlemedium>\n");
		print($RO "Logging Configuration\n");
		print($RO "</div>\n");
		print($RO "<div class=reportsectionbody>\n");
		print($RO "<p>No Logging configuration information detected</p>\n");
	} else {
		print($RO "<div class=reportsectiontitle>\n");
		print($RO "Logging Configuration\n");
		print($RO "</div>\n");
		print($RO "<div class=reportsectionbody>\n");
		print($RO "<p>This portion of the report examines common logging configurations for this server to participate with a central log server. 
		The configuration files listed may also provide information about the types of log events that are being captured. Note: Lines preceded with
		a hash mark (#) are comments and not active commands. If all lines are preceded by a hash mark, then this server is not configured to send
		log events to a central log server. </p>\n");
		if (!$opt_verbose) { # add note about the data displayed.
			print($RO "<p>Note: Detail output from some of these configuration files can be obtained by running $0 with -v option</p>\n");
		}
		foreach my $k (keys %logging) {
			my $value = $logging{$k};
			print($RO "<p>$k</p>\n");
			print($RO "<pre>\n");
			print($RO "$value \n");
			print($RO "</pre>\n");
		}
	}
	print($RO "</div>\n");
	
	#NTP settings from %ntp
	$items = keys %ntp;
	# check for FAIL condition (hack)
	$headingTest = 'PASS'; # reset stupid flag to see if they passed or failed
	foreach my $t (keys %ntp) {
		if ($ntp{$t} =~ m[FAIL] ) {
			# as soon as you find one that fales, get out
			$headingTest = 'FAIL';
		} elsif ( $ntp{$t} =~ m[WARN] ) {
			$headingTest = 'WARN';
		} 
	}
	
	if ($items < 1 ) {
		# Set color flag if missing
		print($RO "<div class=reportsectiontitlemedium>\n");
		print($RO "Server Time Settings (NTP)");
		print($RO "</div>\n");
		print($RO "<div class=reportsectionbody>\n");
		print($RO "<p>Test and examine the server configuration settings for time synchronization. </p>
		<p>System Report was unable to detect ntp configuration settings.</p>\n");
	} else {
		if ($headingTest !~ m/PASS/) {
			if ($headingTest =~ m/FAIL/) {print($RO "<div class=reportsectiontitlehigh>\n");}
			else {print($RO "<div class=reportsectiontitlemedium>\n");}
			print($RO "Server Time Settings (NTP)");
			print($RO "</div>\n");
			print($RO "<div class=reportsectionbody>\n");
			print($RO "<p>Test and examine the server configuration settings for time synchronization. This test attempts to locate the ntp.conf 
			file or the use of ntpdate in the cron.daily directory. Failing to locate these, the test responds that it is unable to locate 
			time synchronization configurations. If the ntp.conf file is located, we attempt to locate if a external time server has been defined. 
			Should a server definition not be located, this test will be marked as a failure.</p> 
			<p>Assessor is advised to manually examine the server and to interview staff in an attempt to determine whether the server will 
			synchronize it's time to an internal, trusted time source. Even if this test is marked as passing, the Assessor is advised to verify 
			that the configured time source is suitably positioned on the internal network.</p>\n");
			foreach my $k (keys %ntp) {
				my $value = $ntp{$k};
				print($RO "<p class=red>$k</p>\n");
				print($RO "<pre>\n");
				print($RO "$value \n");
				print($RO "</pre>\n");
			}
		} else {
			print($RO "<div class=reportsectiontitle>\n");
			print($RO "Server Time Settings (NTP)");
			print($RO "</div>\n");
			print($RO "<div class=reportsectionbody>\n");
			print($RO "<p>Test and examine the server configuration settings for time synchronization. This test attempts to locate the ntp.conf 
			file or the use of ntpdate in the cron.daily directory. Failing to locate these, the test responds that it is unable to locate 
			time synchronization configurations.</p> 
			<p>Assessor is advised to examine these values closely to verify that the time synchronization is properly configured on this server 
			and to verify that the server synchronizes within an internal, trusted time source. </p>\n");
			foreach my $k (keys %ntp) {
				my $value = $ntp{$k};
				print($RO "<p>$k</p>\n");
				if ($value) {
					if ($value =~ m/ntpdate/) {
						# This is a reporting hack to add some value in the actual report and description of what is being shown
						print($RO "<p>The server has an ntpdate file in cron.daily. The contents of this file should show what IP address or named 
						time server this system is going to in order to synchronize internal clocks.</p>\n");
					}
					print($RO "<pre>\n");
					print($RO "$value \n");
					print($RO "</pre>\n");
				} else {
					# $value not set
					print($RO "<p class=red>400 [FAIL] no value set for $k :: QSA must investigate separately.</p>\n");
				}
			}
		}
	}
	print($RO "</div>\n");
	# %ssh:  Remote access control
	$headingTest = 'PASS'; # reset stupid flag to see if they passed or failed
	foreach my $t (keys %ssh) {
		if ($ssh{$t} =~ m[FAIL] ) {
			# as soon as you find one that fales, get out
			$headingTest = 'FAIL';
			last;
		} elsif ( $ssh{$t} =~ m[WARN] ) {
			$headingTest = 'WARN';
		} 
	}
	if ($headingTest !~ m/PASS/) {
		if ($headingTest =~ m/FAIL/) {print($RO "<div class=reportsectiontitlehigh>\n");}
		else {print($RO "<div class=reportsectiontitlemedium>\n");}
		print($RO "Remote Access (ssh)\n");
		print($RO "</div>\n");
		print($RO "<div class=reportsectionbody>\n");
		print($RO "<p>Examine configuration files for Secure Shell (sshd) server. This configuration file controls how a remote
		user logs into this server. Each setting is evaluated based on the current best practices for configuration of ssh. </p>\n<p>Note:
		The ssh setting for port may report a warning if the default of 22 is set. Current best practice suggests that this port 
		number should be set to a high-port value if the server is visible on the public Internet. Although this is a form of 
		obscurity, the high port number will help reduce robot attacks or attacks by script kiddies. Alone changing this port 
		value will not impact the overall security posture of the server. </p>
		<p>Note 2: Some of the listed configuration parameters may not be explicitly set. In this situation, a warning has been
		identified in the following table. The auditor should review the impact on authentication by not explicitly setting 
		the referenced value and confirm that the default meets or exceeds current PCI data security criteria. </p>\n</div>");
		print($RO "<table>\n");
		print($RO "<tr>\n");
		print($RO "<th>Config Parameter</th>\n");
		print($RO "<th>Test Result</th>\n");
		print($RO "</tr>\n");
		foreach my $k (keys %ssh) {
			my $value = $ssh{$k};
			print($RO "<tr>\n");
			if ($value =~ m/FAIL/) { 
				print($RO "<td>$k</td><td class=Red>$value</td>\n");
			} else {
				print($RO "<td>$k</td><td>$value</td>\n");
			}
			print($RO "</tr>\n");
		}
		print($RO "</table>\n");
		print($RO "<BR />\n");
		print($RO "</div>\n");
	} else {
		print($RO "<div class=reportsectiontitle>\n");
		print($RO "Remote Access (ssh)\n");
		print($RO "</div>\n");
		print($RO "<div class=reportsectionbody>\n");
		print($RO "<p>Examine configuration files for Secure Shell (sshd) server. This configuration file controls how a remote
		user logs into this server. Each setting is evaluated based on the current best practices for configuration of ssh.</p>
		<p>Note: Some of the listed configuration parameters may not be explicitly set. In this situation, a warning has been
		identified in the following table. The auditor should review the impact on authentication by not explicitly setting 
		the referenced value and confirm that the default meets or exceeds current PCI data security criteria. </p>\n");
		print($RO "<table>\n");
		print($RO "<tr>\n");
		print($RO "<th>Config Parameter</th>\n");
		print($RO "<th>Test Result</th>\n");
		print($RO "</tr>\n");
		foreach my $k (keys %ssh) {
			my $value = $ssh{$k};
			print($RO "<tr>\n");
			if ($value =~ m/FAIL/) { 
				print($RO "<td>$k</td><td class=Red>$value</td>\n");
			} else {
				print($RO "<td>$k</td><td>$value</td>\n");
			}
			print($RO "</tr>\n");
		}
		print($RO "</table>\n");
		print($RO "<BR />\n");
		print($RO "</div>\n");
	}
	
	# %perms:  Permissions
	$headingTest = 'PASS'; # reset stupid flag to see if they passed or failed
	foreach my $t (keys %perms) {
		if ($perms{$t} =~ m[FAIL] ) {
			# as soon as you find one that fales, get out
			$headingTest = 'FAIL';
			last;
		} elsif ( $perms{$t} =~ m[WARN] ) {
			$headingTest = 'WARN';
		} 
	}
	
	if ($headingTest !~ m/PASS/ ) {
		# Set color flag if missing
		if ($headingTest =~ m/FAIL/) {print($RO "<div class=reportsectiontitlehigh>\n");}
		else { print($RO "<div class=reportsectiontitlemedium>\n"); }
		print($RO "Configuration file permissions test \n");
		print($RO "</div>\n");
		print($RO "<div class=reportsectionbody>\n");
		print($RO "<p>Examine system configuration files from /etc and specific subdirectories related to security configurations. 
		Each set of file permissions is analyzed based on direct access controls functioning within the NIX operating system. This
		test queries the operating system to determine what the settings are for the file owner, group, or world. This tool 
		analyzes the settings to identify any risky permissions that might internally expose the target server. </p>
		<p>Depending on the settings configured in the server, the direct access settings may be overridden by server ACLs and LDAP 
		integration. It is important that the PCI Assessor interview and obtain more information to verify the results. </p>
		<p>The Tests in this section have identified a material finding. The following table identifies a specific file where 
		permission settings that may expose this server. </p>\n");
		if (!$opt_verbose) {
			print($RO "<p>Details of all file permissions tested will not be listed. This report will only displays settings 
			and files where the permissions may not be properly set. Run this report with the -v option to review all files and 
			permissions.</p>\n");
		}
		print($RO "</div>");
		print($RO "<table>\n");
		print($RO "<tr>\n");
		print($RO "<th>File Name</th>\n");
		print($RO "<th>Test Result</th>\n");
		print($RO "</tr>\n");
		foreach my $k (keys %perms) {
			my $value = $perms{$k};
			print($RO "<tr>\n");
			if ($value =~ m/FAIL/) { 
				print($RO "<td>$k</td><td class=leftRed>$value</td>\n");
			} elsif ($opt_verbose) {
				print($RO "<td>$k</td><td class=left>$value</td>\n");
			}
			print($RO "</tr>\n");
		}
		print($RO "</table>\n");
		print($RO "<BR />\n");
		print($RO "</div>\n");
	} else {
		print($RO "<div class=reportsectiontitle>\n");
		print($RO "Configuration file permissions test \n");
		print($RO "</div>\n");
		print($RO "<div class=reportsectionbody>\n");
		print($RO "<p>Examine system configuration files from /etc and specific subdirectories related to security configurations. 
		Each set of file permissions is analyzed based on direct access controls functioning within the NIX operating system. This
		test queries the operating system to determine what the settings are for the file owner, group, or world. This tool 
		analyzes the settings to identify any risky permissions that might internally expose the target server. </p>\n
		<p>Depending on the settings configured in the server, the direct access settings may be overridden by server ACLs and LDAP 
		integration. It is important that the PCI Assessor interview and obtain more information to verify the results. </p>\n");
		if ($opt_verbose) {
			print($RO "<table>\n");
			print($RO "<tr>\n");
			print($RO "<th>File Name</th>\n");
			print($RO "<th>Test Result</th>\n");
			print($RO "</tr>\n");
			foreach my $k (keys %perms) {
				my $value = $perms{$k};
				print($RO "<tr>\n");
				# Never a failing condition for this one to run
				print($RO "<td>$k</td><td class=left>$value</td>\n");
				print($RO "</tr>\n");
			}
			print($RO "</table>\n");
		} else {
			print($RO "<p>All file permissions tested appear to meet the minimum requiurements for the operating system examined. 
			No exceptions were detected by System Report.</p>\n<p>Details of all file permissions tested will not be listed. This 
			report will only displays settings and files where the permissions may not be properly set. Run this report with the 
			-v option to review all files and permissions.</p>\n");
		}
		print($RO "<BR />\n");
		print($RO "</div>\n");
	}
	
	# %accesscontrol;   # Access control information
	$headingTest = 'PASS'; # Default to Pass
	foreach my $t (keys %accesscontrol) {
		if ($accesscontrol{$t} =~ m/\[FAIL\]/i ) {
			# as soon as you find one that fales, get out
			$headingTest = 'FAIL';
			last;
		} elsif ( $accesscontrol{$t} =~ m/\[WARN\]/i ) {
			$headingTest = 'WARN';
		} 
	}
	
	$items = keys %accesscontrol;
	if (($headingTest !~ m/PASS/i) || ($items < 1 )) {  # flag if fail or no items
		if ($headingTest =~ m/FAIL/) {print($RO "<div class=reportsectiontitlehigh>\n");}
		else {print($RO "<div class=reportsectiontitlemedium>\n");}
		print($RO "Access Control and Authentication Configuration\n");
		print($RO "</div>\n");
		print($RO "<div class=reportsectionbody>\n");
		foreach my $k (keys %accesscontrol) {
			my $value = $accesscontrol{$k};
			if ($value =~ m/\[FAIL\]/i) { print($RO "<p class=red>Security Issue Detected >>> $k</p>\n"); }
			elsif ($value =~ m/\[WARN\]/i) { print($RO "<p class=orange>Warning Detected >>> $k</p>\n")}
			else {print($RO "<p>$k</p>\n");}
			print($RO "<pre>\n");
			$value =~ s/</&lt;/g;
			$value =~ s/>/&gt;/g;
			print($RO "$value \n");
			print($RO "</pre>\n");
		}
	} else {
		print($RO "<div class=reportsectiontitle>\n");
		print($RO "Access Control and Authentication Configuration\n");
		print($RO "</div>\n");
		print($RO "<div class=reportsectionbody>\n");
		foreach my $k (keys %accesscontrol) {
			my $value = $accesscontrol{$k};
			print($RO "<p>$k</p>\n");
			print($RO "<pre>\n");
			print($RO "$value \n");
			print($RO "</pre>\n");
		}
	}
	print($RO "</div>\n");
	
	# our %network;       #networking information
	$items = keys %network;
	if ($items < 1 ) {
		print($RO "<div class=reportsectiontitlemedium>\n");
		print($RO "Network Configuration\n");
		print($RO "</div>\n");
		print($RO "<div class=reportsectionbody>\n");
		print($RO "<p>No Network configuration information detected</p>\n");
	} else {
		print($RO "<div class=reportsectiontitle>\n");
		print($RO "Network Configuration\n");
		print($RO "</div>\n");
		print($RO "<div class=reportsectionbody>\n");
		foreach my $k (keys %network) {
			my $value = $network{$k};
			print($RO "<p>$k</p>\n");
			print($RO "<pre>\n");
			print($RO "$value \n");
			print($RO "</pre>\n");
		}
	}
	print($RO "</div>\n");
	
	# our %FIM;        #  file integrity monitoring information
	$items = keys %FIM;
	if ($items < 1 ) {
		print($RO "<div class=reportsectiontitlehigh>\n");
		print($RO "File Integrity Monitoring\n");
		print($RO "</div>\n");
		print($RO "<div class=reportsectionbody>\n");
		print($RO "<p>This test scanned running processes and installed applications in an attempt to locate installed File Integrity Management 
		(FIM) software. It is important to note that this test only detects the presence of such software and does not attempt to evaluate the 
		effective implementation or deployment. As such, the Assessor is encourgaed to check the configuration of any FIM software and examine the 
		alert and messagin output. </p>\n<p class=red>No File Integrity Monitoring detected</p>\n");
	} else {
		print($RO "<div class=reportsectiontitle>\n");
		print($RO "File Integrity Monitoring\n");
		print($RO "</div>\n");
		print($RO "<div class=reportsectionbody>\n");
		print($RO "<p>This test scanned running processes and installed applications in an attempt to locate installed File Integrity Management 
		(FIM) software. It is important to note that this test only detects the presence of such software and does not attempt to evaluate the 
		effective implementation or deployment. As such, the Assessor is encourgaed to check the configuration of any FIM software and examine the 
		alert and messagin output. </p>\n<p>The following packages were discovered.</p>\n");
		foreach my $k (keys %FIM) {
			my $value = $FIM{$k};
			print($RO "<p>$k</p>\n");
			print($RO "<pre>\n");
			print($RO "$value \n");
			print($RO "</pre>\n");
		}
	}
	print($RO "</div>\n");
	
	# %patch;     # patching information
	$headingTest = 'PASS'; # reset stupid flag to see if they passed or failed
	foreach my $t (keys %patch) {
		if ($patch{$t} =~ m/FAIL/ ) {
			# as soon as you find one that fales, get out
			$headingTest = 'FAIL';
			last;
		} elsif ( $patch{$t} =~ m[WARN] ) {
			$headingTest = 'WARN';
		} 
	}
	$items = keys %patch;
	if ($items < 1 ) {
		print($RO "<div class=reportsectiontitlemedium>\n");
		print($RO "Patching and Updates\n");
		print($RO "</div>\n");
		print($RO "<div class=reportsectionbody>\n");
		print($RO "<p>This test utilized common utilities found in some NIX environments to determine if patches are current 
		on the subject server. This testing is non-deterministic and depends on several variables that are not under the control 
		of this testing software. As an example, the Client may be performing manual tests or using tools that are not a part of the 
		standard distribution. As such, the accuracy of these results will need to be separately verified. </p>\n
		<p>No Patching and Installed Applications information detected.</p>\n");
	} else {
		if ($headingTest =~ m/FAIL/) {
			print($RO "<div class=reportsectiontitlehigh>\n");
		} elsif ($headingTest =~ m/WARN/) {
			print($RO "<div class=reportsectiontitlemedium>\n");
		} else {
			print($RO "<div class=reportsectiontitle>\n");
		}
		print($RO "Patching and Updates \n");
		print($RO "</div>\n");
		print($RO "<div class=reportsectionbody>\n");
		print($RO "<p>This test utilized common utilities found in some NIX environments to determine if patches are current 
		on the subject server. This testing is non-deterministic and depends on several variables that are not under the control 
		of this testing software. As an example, the Client may be performing manual tests or using tools that are not a part of the 
		standard distribution. As such, the accuracy of these results will need to be separately verified. </p>\n<p>During this inspection 
		the software was able to acquire responses from the common package managers. The results are listed below.</p>\n");
		foreach my $k (keys %patch) {
			my $value = $patch{$k};
			if ($value =~ m/FAIL/i) {print($RO "<p class=red>$k</p>\n");}
			elsif ($value =~ m/WARN/i) {print($RO "<p class=orange>$k</p>\n");}
			else {print($RO "<p>$k</p>\n");}
			print($RO "<pre>\n");
			$value =~ s/</&lt;/g;
			$value =~ s/>/&gt;/g;
			print($RO "$value \n");
			print($RO "</pre>\n");
		}
	}
	print($RO "</div>\n");
	
	# perform dump of %packages to list installed softwaare packages
	print($RO "<div class=reportsectiontitle>\n");
	print($RO "Installed software packages \n");
	print($RO "</div>\n");
	print($RO "<div class=reportsectionbody>\n");
	print($RO "<p>This test utilized common utilities found in NIX environments to identify and list all installed software packages. 
	The packages listed here include only software that was installed through the operating system's package manager. Software installed 
	by compilation or manually by Client may not be listed and will need to be identified separately by the Assessor.  
	This testing is non-deterministic and depends on several variables that are not under the control 	of this testing software. 
	As an example, the Client may be performing manual software installation, not using package manager or compiling software on the platform. 
	As such, the accuracy of these results will need to be  verified. </p>\n<p>During this inspection 
	the software was able to acquire responses from the common package managers. The results are listed below.</p>\n");
	foreach my $k (keys %packages) {
		my $value = $packages{$k};
		print($RO "<p>$k</p>\n");
		print($RO "<pre>\n");
		$value =~ s/</&lt;/g;
		$value =~ s/>/&gt;/g;
		print($RO "$value \n");
		print($RO "</pre>\n");
	}
	print($RO "</div>\n");
	
	# General report operation section	
	print($RO "<div class=reportsectiontitle>\n");
	print($RO "SystemReport Tool Settings and Options\n");
	print($RO "</div>\n");
	print($RO "<div class=reportsectionbody>\n");
	# Solaris systems don't always have a $ENV{"User"} set
	my ($local_User, $local_Logname);
	my $RPT_User = 'Unknown';
	my $RPT_Logname = 'Unknown';
	undef $@;
	eval {
		$local_User=$ENV{"USER"};
	};
	if ($@) { $RPT_User="Unknown";}
	undef $@;
	eval {
		$local_Logname=$ENV{"LOGNAME"};
	};
	if ($@) { $RPT_Logname="Unknown"; }
	if ($opt_debug) {
		print STDOUT "   Local ENV variables fetched...\n";
		if ($local_Logname) {print STDOUT "      Logname:  $local_Logname \n"; }
		else {print STDOUT "      Logname:  $RPT_Logname \n"; }
		if ($local_User) {print STDOUT "      User:  $local_User \n"; }
		else {print STDOUT "      User:  $RPT_User \n"; }
	}
	if ($local_User) {$RPT_User = $local_User; }
	if ($local_Logname) {$RPT_Logname = $local_Logname; }
	print($RO "<p>SystemReport.pl Version: $version run $today <br />Run by User: $RPT_User  with Login Name: $RPT_Logname</p>");
	print($RO "<p>Options selected: </p>");
	print($RO "<ul>");
	print($RO "<li>Debug</li>") if ($opt_debug);
	if ($opt_forensic) {
		print($RO "<li>Forensic mode selected </li>");
	}
	if ($opt_verbose) {
	 	print($RO "<li>Verbose mode - including configuration file comments </li>");
	} else {
	 	print($RO "<li>Regular mode - no comments included for configuration files</li> ")
	}
	print($RO "</ul>");
	print($RO "<p>&copy Copyright $year, Payment Software Company Inc (d/b/a PSC)  All Rights Reserved<br />");
	print($RO "The use of this tool is licensed and governed by the terms and conditions of Client's agreement with PSC.</p>");
	print($RO "</div>");
		
	# End of report	
	print($RO "</body></html>\n");

	close($RO);
	return 0;
	
}

# Mainline processing
# Set options
GetOptions('debug|d' => \$opt_debug, 
'help|h' =>\$opt_help, 
'report|r' => \$opt_rpt, 
'short|s' => \$opt_short, 
'forensic|f' => \$opt_forensic,
'Force' => \$opt_Force,
'about|a' => \$opt_version,
'xml_only|x' => \$opt_xml_only, 
'include=s' => \$opt_include );

if ($opt_short) {
	# Examine this option first since forensic mode would override it.
	$opt_verbose=0;
}

if ($opt_forensic) {
	$opt_verbose=1;
	$opt_Force=1;
}  # If forensic flag used, turn on verbose and Force running of program even if not run as sudo or root

# Test for sudo or root privilege
test_sudo();

if ($opt_debug) {
	dumpoptions() == 0 or die "Failed to call dumpoption subroutine : $!";
}

if ($opt_version) {
	version() == 0 or die "Failed to call version subroutine : $!";
	exit(0);
}

if ($opt_help) {
	# Only flag that will exit the program
	help() == 0 or die "Failed to call help subroutine : $!";
	exit(0);  
}

# Data Collection Phase
print(STDOUT "SystemReport from PSC -- version: $version\n");
if ($opt_forensic) {print(STDOUT "Forensic Mode Selected\n");}
print(STDOUT "Data Collection Phase.....\n");   # Print as general output
DC_general() == 0 or die "Data collection General routine failed : $!";
DC_nettest() == 0 or die "Data collection Net Test routine failed : $!";
# DC_bootloader() == 0 or die "Data collection Bootloader failed : $!";
DC_services() == 0 or die "Data collection Services routine failed : $!";
DC_batchjobs() == 0 or die "Data collection Batchjobs routine failed : $!";
DC_logging() == 0 or die "Data collection Logging routine failed : $!";
DC_networking() == 0 or die "Data collection Networking routine failed : $!";
DC_remote_accesscontrol() == 0 or die "Data collection Remote access control failed : $!";
DC_permissions() == 0 or die "Data collection permissions test failed : $!";
DC_accesscontrol() == 0 or die "Data collection Accesscontrol routine failed : $!";
DC_FIM() == 0 or die "Data collection FIM routine failed : $!";
DC_patch() == 0 or die "Data collection Patch routine failed : $!";
DC_Packages() == 0 or die "Data collection Packages routine failed : $!";
if ($opt_include) { DC_include() == 0 or die "Data collection Include routine failed : $!"; }

# Output phase
print(STDOUT "Report Preparation and Output Phase.....\n");
if ($opt_xml_only) {
	WriteXML() == 0 or die "Output routine WriteXML failed : $!";
}
if ($opt_rpt) {
	WriteHTML() == 0 or die "Output routine WriteHTML failed : $!";
}


# END
