use strict;
use warnings;
package AWS::SNS::Verify;

use JSON;
use HTTP::Tiny;
use MIME::Base64;
use Moo;
use Ouch;
use Crypt::OpenSSL::RSA;
use Crypt::OpenSSL::X509;

has body => (
    is          => 'ro',
    required    => 1,
);

has message => (
    is          => 'ro',
    lazy        => 1,
    default     => sub {
        my $self = shift;
        return JSON::decode_json($self->body);
    }
);

has certificate_string => (
    is          => 'ro',
    lazy        => 1,
    default     => sub {
        my $self = shift;
        return $self->fetch_certificate;
    }
);

has certificate => (
    is          => 'ro',
    lazy        => 1,
    default     => sub {
        my $self = shift;
        return Crypt::OpenSSL::X509->new_from_string($self->certificate_string);
    }
);

sub fetch_certificate {
    my $self = shift;
    my $response = HTTP::Tiny->new->get($self->message->{SigningCertURL});
    if ($response->{success}) {
        return $response->{content};
    }
    else {
        ouch $response->{status}, $response->{reason}, $response;
    }
}

sub generate_signature_string {
    my $self = shift;
    my $body = $self->message;
    my @fields;
    if ($body->{Type} eq 'Notification') {
        @fields = (qw(Message MessageId Subject Timestamp TopicArn Type)) ;
    }
    else {
        @fields = (qw(Message MessageId SubscribeURL Timestamp Token TopicArn Type));
    }
    my @parts;
    foreach my $field (@fields) {
        if (exists $body->{$field}) {
            push @parts, $field;
            push @parts, $body->{$field};
        }
    }
    return join("\n", @parts)."\n";
}

sub decode_signature {
    my $self = shift;
    return decode_base64($self->message->{Signature});
}

sub verify {
    my $self = shift;
    my $rsa = Crypt::OpenSSL::RSA->new_public_key($self->certificate->pubkey);
    unless ($rsa->verify($self->generate_signature_string, $self->decode_signature)) {
        ouch 'Bad SNS Signature', 'Could not verify the SES message from its signature.', $self;
    }
    return 1;
}


=head1 NAME

AWS::SNS::Verify - Verifies authenticity of SNS messages.

=head1 SYNOPSIS

 my $body = request->body; # example fetch raw body from Dancer
 my $sns = AWS::SNS::Verify->new(body => $body);
 if ($sns->verify) {
     return $sns->message;
 }

=head1 DESCRIPTION

This module will parse a message from Amazon Simple Notification Service and validate its signature. This way you know the message came from AWS and not some third-party. More info here: L<http://docs.aws.amazon.com/sns/latest/dg/SendMessageToHttp.verify.signature.html>.

=head1 METHODS

=head2 new

Constructor.

=over

=item body

Required. JSON string posted by AWS SNS. Looks like:

 {
    "Type" : "Notification",
    "MessageId" : "a890c547-5d98-55e2-971d-8826fff56413",
    "TopicArn" : "arn:aws:sns:us-east-1:041977924901:foo",
    "Subject" : "test subject",
    "Message" : "test message",
    "Timestamp" : "2015-02-20T20:59:25.401Z",
    "SignatureVersion" : "1",
    "Signature" : "kzi3JBQz64uFAXG9ZuAwPI2gYW5tT7OF83oeHb8v0/XRPsy0keq2NHTCpQVRxCgPOJ/QUB2Yl/L29/W4hiHMo9+Ns0hrqyasgUfjq+XkVR1WDuYLtNaEA1vLnA0H9usSh3eVVlLhpYzoT4GUoGgstRVvFceW2QVF9EYUQyromlcbOVtVpKCEINAvGEEKJNGTXQQUkPUka3YMhHitgQg1WlFBmf+oweSYUEj8+RoguWsn6vluxD0VtIOGOml5jlUecfhDqnetF5pUVYMqCHPfHn6RBguiW+XD6XWsdKKxkjqo90a65Nlb72gPSRw6+sIEIgf4J39WFZK+FCpeSm0qAg==",
    "SigningCertURL" : "https://sns.us-east-1.amazonaws.com/SimpleNotificationService-d6d679a1d18e95c2f9ffcf11f4f9e198.pem",
    "UnsubscribeURL" : "https://sns.us-east-1.amazonaws.com/?Action=Unsubscribe&SubscriptionArn=arn:aws:sns:us-east-1:041977924901:foo:20b2d060-2a32-4506-9cb0-24b8b9e605e1",
    "MessageAttributes" : {
        "AWS.SNS.MOBILE.MPNS.Type" : {"Type":"String","Value":"token"},
        "AWS.SNS.MOBILE.WNS.Type" : {"Type":"String","Value":"wns/badge"},
        "AWS.SNS.MOBILE.MPNS.NotificationClass" : {"Type":"String","Value":"realtime"}
    }
 }

=item certificate_string

By default AWS::SNS::Verify will fetch the certificate string by issuing an HTTP GET request to C<SigningCertURL>. If you wish to use a cached version, then pass it in.

=back

=head2 verify

Returns a 1 on success, or an L<Ouch> on a failure.

=head2 message

Returns a hash reference of the decoded L<body> that was passed in to the constructor.

=head2 certificate_string

If you want to cache the certificate in a local cache, then get it using this method.


=head1 REQUIREMENTS

Requires Perl 5.12 or higher and these modules:

=over

=item *

Ouch

=item *

JSON

=item * 

HTTP::Tiny

=item * 

MIME::Base64

=item * 

Moo

=item * 

Crypt::OpenSSL::RSA

=item * 

Crypt::OpenSSL::X509

=back

=head1 SUPPORT

=over

=item Repository

L<http://github.com/rizen/AWS-SNS-Verify>

=item Bug Reports

L<http://github.com/rizen/AWS-SNS-Verify/issues>

=back


=head1 AUTHOR

JT Smith <jt_at_plainblack_dot_com>

=head1 LEGAL

AWS::SNS::Verify is Copyright 2015 Plain Black Corporation (L<http://www.plainblack.com>) and is licensed under the same terms as Perl itself.

=cut


1;
