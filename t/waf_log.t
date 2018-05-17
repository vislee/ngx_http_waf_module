#!/usr/bin/perl

# (C) vislee

# Tests for http waf module.

###############################################################################

use warnings;
use strict;

use Test::More;

use IO::Select;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->plan(5)
    ->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

load_module /tmp/nginx/modules/ngx_http_waf_module.so;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;


        location /sec/log {
            security_loc_rule id:1001 "str:eq@test" "z:ARGS";
            security_loc_rule id:1002 "str:eq@waflog" "s:$TLOG:2" "z:ARGS";
            security_loc_rule id:1003 "str:ct@/allow/url" "s:$ALLOW:2" "z:#URL";

            security_waf on;

            security_check $TLOG>3 LOG;
            security_check $ALLOW>1 ALLOW;

            security_log %%TESTDIR%%/waf.log;

            proxy_pass http://127.0.0.1:8082/;
        }

        location /log/syslog {
            security_loc_rule id:2001 "str:eq@test" "z:ARGS";

            security_waf on;
            security_log syslog:server=127.0.0.1:%%PORT_8985_UDP%%,tag=SEETHIS;

            proxy_pass http://127.0.0.1:8082/;
        }

        location /log/unflat {
            security_loc_rule id:3001 "str:eq@test" "z:ARGS";

            security_waf on;
            security_log %%TESTDIR%%/waf_unflat.log unflat;
            proxy_pass http://127.0.0.1:8082/;
        }
    }

    server {
        listen       127.0.0.1:8082;
        server_name  localhost;

        location / {
            return 200 "ok";
        }
    }
}

EOF

$t->run();

###############################################################################

my $s = IO::Socket::INET->new(
    Proto => 'udp',
    LocalAddr => '127.0.0.1:' . port(8985)
)
    or die "Can't open syslog socket: $!";


http_get('/log/unflat?foo=test');
http_get('/sec/log?foo=test');
http_get('/sec/log?waflog=hello&hello=waflog');
http_get('/sec/log/allow/url?waflog=hello&hello=waflog');
like(get_syslog('/log/syslog?foo=test'), qr/SEETHIS:/, 'waf syslog tag');

$t->stop();

like($t->read_file('waf_unflat.log'), qr/"rule": {"id": "3001"/, 'waf unflat log');
like($t->read_file('waf.log'), qr/"rule_BLOCK_1001_score": "0"/, 'waf log');
like($t->read_file('waf.log'), qr/"TLOG_total": "4"/, 'waf log');
like($t->read_file('waf.log'), qr/"ALLOW_total": "2"/, 'waf log');

###############################################################################
sub get_syslog {
    my ($uri) = @_;
    my $data = '';

    http_get($uri);

    IO::Select->new($s)->can_read(1);
    while (IO::Select->new($s)->can_read(0.1)) {
        my $buffer;
        sysread($s, $buffer, 4096);
        $data .= $buffer;
    }
    return $data;
}