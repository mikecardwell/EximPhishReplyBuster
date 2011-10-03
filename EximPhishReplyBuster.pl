# Copyright (c) 2011, Mike Cardwell - https://grepular.com/
#
# See LICENSE section in pod text below for usage and distribution rights.
#

use strict;
use warnings;
use HTML::Entities;
use MIME::Base64 qw( decode_base64 );
use MIME::QuotedPrint;

## Store the password. Called from the authenticators

	my $password;
	sub remember_password {
		$password = shift;
		return $password;
	}

## Detect existance of password in body. Called from MIME and DATA ACLs.

	sub detect_password {

		## Optional filename passed. This is so the MIME ACL can pass on access to a decoded file

			my $filename = shift;

		## If they haven't set a password, return

			return 'false' unless defined $password;

		## Get the body to work on

			my $body = '';
			{
				if( $filename && open my $in, '<', $filename ){

					## Read the message body from an already decoded file
					
						local $/ = undef;
						$body = <$in>;
						close $in;
				} else {

					## Read the message body from $message_body in Exim, and decode it

						$body = Exim::expand_string( '$message_body' ) || '';
						my $transfer_encoding = lc(Exim::expand_string( '$h_Content-Transfer-Encoding' )||'');
						$body = decode_base64( $body ) if $transfer_encoding eq 'base64';
						if( $transfer_encoding eq 'quoted-printable' ){
							$body =~ s/= /=\n/gsm;
							$body = decode_qp( $body );
						}
				}
			}

		## Scan for the password in the body

			return 'true' if index( $body, $password ) > -1;

		## Encode the password with HTML entities and scan again

			return 'true' if index( $body, encode_entities($password)) > -1;

		## Didn't find the password

			return 'false';
	}

__END__
=pod

=head1 NAME

EximPhishReplyBuster -- Detects when an email contains the same password
that was used during submission to authenticate the connection.

=head1 DESCRIPTION

This application helps you configure Exim to enforce a hypothetical
policy stating that users shouldn't send their passwords via email.

=head1 SYNOPSIS

Scammers send emails to users asking them to reply with their login
details. They usually pretend to be the users I.T department or similar
to trick the user into replying. This is called a phishing attack, or
spear phishing attack.

If your users send email using authenticated SMTP through Exim, and you
use PLAIN or LOGIN authenticators, then Exim "knows" which username and
password they used to connect, and it also knows the content of the
message they're sending. Exim can use this knowledge to block emails
where the password is contained within the message body. This script
helps you to do that.

=head1 CONFIGURATION 

Your version of Exim must have been built with Embedded Perl. You can
check if it has by running this command:

exim -bV | grep ^Support

Check if "Perl" is in the outputted list. For more info on Embedded
Perl, see:

http://www.exim.org/exim-html-current/doc/html/spec_html/ch12.html

Check if you have the necessary Perl modules installed by running
the command:

perl -c EximPhishReplyBuster.pl

If there is any output, then something is wrong.

=over

=item B<perl_startup>

  First of all, tell Exim how it can access EximPhishReplyBuster by
  adding the following global configuration item to the Exim config:

  perl_startup = do '/path/to/EximPhishReplyBuster.pl'

=item B<Authenticators>

  It is not possible to access the authenticated SMTP password from
  outside the authenticators. To get around this limitation, this
  script provides a function called remember_password.

  In your PLAIN authenticator, replace any reference to $auth3 or $3
  with:

  ${perl{remember_password}{$auth3}}

  In your LOGIN authenticator, replace any reference to $auth2 or $2
  with:

  ${perl{remember_password}{$auth2}}

  This function echos back the password, but also stores it in memory
  so it can be referred to later on in the ACLs.

=item B<acl_smtp_mime>

  Add the following configuration to your acl_smtp_mime ACL and it
  will decode each text/* MIME part and scan it for the password
  used for authentication.

  deny authenticated  = *
       condition      = ${if match{$mime_content_type}{^text/}}
       decode         = ${md5:$mime_filename}
       condition      = ${perl{detect_password}{$mime_decoded_filename}}
       message        = Do not send your password in emails

=item B<acl_smtp_data>

  We also want to scan the raw message body for single part emails, so
  add this to your acl_smtp_data ACL:

  deny authenticated = *
       condition     = ${perl{detect_password}}
       message       = Do not send your password in emails

=item B<message_body_visible = 500>

  This is an optional global configuration item that you can change.
  When doing the scan in acl_smtp_mime, we read in each individual
  MIME part and scan the entire thing. However, in acl_smtp_data, we
  only operate on the contents of $message_body. $message_body by
  default only contains the first 500 characters of the message body.
  You may want to increase this value to something like 10000.

=item B<SMTP rejection or autoresponse?>

  Some email clients may not display the error message to the user when
  the message is rejected. It is almost certainly going to be better to
  do an "accept" rather than "deny", and use an ACL variable to record
  the fact that the email contains the password. Then in the routers
  you can send an autoresponse to the sender to let them know that the
  email has been blocked, and the reasons why. You could even Cc in
  the email administrators or security team to any such autoresponse.

=back

=head1 COPYRIGHT

Copyright (c) 2011  Mike Cardwell - https://grepular.com/

=head1 LICENSE

Licensed under the GNU General Public License. See
http://www.opensource.org/licenses/gpl-2.0.php

=head1 SEE ALSO

L<HTML::Entities>, L<MIME::Base64>, L<MIME::QuotedPrint>.

=head1 AUTHOR

Mike Cardwell - https://grepular.com/ 

Copyright (C) 2011 Mike Cardwell - https://grepular.com/

=cut
