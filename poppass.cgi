#!/usr/bin/env perl
## poppass.cgi
##
## Example CGI client for poppassd servers which implement
## Eudora-style password change protocol.
##
## Distributed with yppoppassd; see
##     http://github.com/rlister/yppoppassd
## for more details on the server and the protocol.
##
## Copyright Ric Lister 2000

use IO::Socket::INET;
use CGI qw/:standard :html3 *table/;
use CGI::Carp;

## I use the following while debugging
# use CGI::Pretty;
# $CGI::Pretty::INDENT = "  ";

## server running poppassd server, user localhost where possible
$SERVER_NAME = "localhost";
$SERVER_PORT = 106;

$MIN_PASSWD_LEN = 6;                ## what constitutes too short passwd
$FIELD_LEN = 25;                    ## size of input fields

## important: for the purpose of the conversation w/the server, the
## field strings must be same as the server expects, in order
## (confirm_newpass is an exception as we only use it internally)
@fields = ("user", "pass", "newpass", "confirm_newpass");
@prompts = ("Username", "Old password", "New password",
	    "Confirm new password");
@field_type = (\&textfield, \&password_field, \&password_field,
	       \&password_field);

## get started with HTML
print header(),
    start_html("Change password"),
    h1("Change password");

## print form
if ( !param ) {
  &print_form();
}
## act on form input
else {

  ## easier to read like this
  $user = param($fields[0]);
  $oldpass = param($fields[1]);
  $newpass = param($fields[2]);
  $confirm_newpass = param($fields[3]);

  ## we can do some basic integrity checking here
  if ( !$user ) {
    &html_error("Username required.");
  }
  elsif ( $newpass ne $confirm_newpass ) {
    &html_error("Mismatch of new passwords.");
  }
  elsif ( length($newpass) < $MIN_PASSWD_LEN ) {
    &html_error("New password must be at least ", $MIN_PASSWD_LEN,
		" characters long.");
  }

  ## all's well, make call to server
  else {
    $status = &change_passwd($user, $oldpass, $newpass);
  }

}

print end_html();

exit(0);


  
## print data entry form
sub print_form {
  print startform(-method=>"POST"), start_table();

  foreach $i (0..3) {
    print Tr(td({-align=>'right'}, $prompts[$i]),
	     td($field_type[$i]($fields[$i], '', $FIELD_LEN)));
  }

  print Tr(td(submit("Change password")),
	   td({-align=>'right'}, reset("Reset form")));

  print end_table(), endform(), ;
}

  

## print error message to browser  
sub html_error {
  my(@msg) = @_;

  print h2("Error"), p(@msg),
      p("Please go back and try again.");
}

  

## make tcp call to poppassd server
## return 0 success, 
sub change_passwd {
  my(@args) = @_;

  my $n = 0;
  my $status;

  ## open socket
  $socket = IO::Socket::INET->new(PeerAddr=>$SERVER_NAME,
				  PeerPort=>$SERVER_PORT,
				  Proto=>"tcp",
				  Type=>SOCK_STREAM);

  ## check we got a socket back
  unless ( $socket ) {
    warn("Can't connect to $SERVER_NAME:$SERVER_PORT: @_");
    &html_error("Can't connect to server, contact administrator.");
    return(1);
  }

  ## listen on socket for server responses
  while ( <$socket> ) {
    s/\r\n//g;

    if ( m/^200 / ) {
      ## third 200 response means success, we won't be fussy and
      ## wait for the 4th (200 Bye, or whatever the server signs off)
      if ( $n > 2 ) {
	print $socket "quit\r\n";
	print h2("Success"),
	  p(), "Password has been changed for user: ", em($args[0]);
	$status = 0;
	last;
      }

      print $socket "$fields[$n] $args[$n]\r\n";
      ++$n;
    }
    ## do any servers actually return 300 ever? if so handle it like
    ## 200, except for last reponse
    ##
    ## could handle 400 by timing out a random time and trying again
    ## but don't know any servers that return 400
    ##
    ## 500 is a permanent error
    elsif ( m/^500 / ) {
      &html_error("Received the following error from server: ", $_);
      $status = 500;
      last;
    }

    ## null response
    elsif ( m// ) {
      &html_error("Got no response from server");
      warn("No response from $SERVER_NAME:$SERVER_PORT.");
      $status = -1;
      last;
    }
  }

  close($socket);
  return($status);
}
