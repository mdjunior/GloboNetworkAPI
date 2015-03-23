#!/usr/bin/perl

# how to decode str into json in perl:
#  http://xmodulo.com/how-to-parse-json-string-in-perl.html

use strict;
use warnings;

use AnyEvent;
use JSON qw( decode_json );
use Data::Dumper;

$|++;
use Net::RabbitFoot;

my $conn = Net::RabbitFoot->new()->load_xml_spec()->connect(
    host => 'localhost',
    port => 5672,
    user => 'guest',
    pass => 'guest',
    vhost => '/',
);

my $channel = $conn->open_channel();

$channel->declare_exchange(
    exchange => 'networkapi_exchange',
    type => 'topic',
);

my $result = $channel->declare_queue(exclusive => 0);

my $queue_name = $result->{method_frame}->{queue};


$channel->bind_queue(
    exchange => 'networkapi_exchange',
    queue => $queue_name,
    routing_key => '#',
);


print " [*] Waiting for logs. To exit press CTRL-C\n";

sub callback {
    my $var = shift;
    my $body = $var->{body}->{payload};
    my $routing_key = $var->{deliver}->{method_frame}->{routing_key};
    my $decoded = decode_json($body);

    print  Dumper($decoded);
}

$channel->consume(
    on_consume => \&callback,
    no_ack => 1,
);

# Wait forever
AnyEvent->condvar->recv;