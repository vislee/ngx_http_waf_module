#!/usr/bin/perl

# (C) vislee

# Tests for http waf module.

###############################################################################

use warnings;
use strict;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $modules = $ENV{TEST_NGINX_MODULES};

my $t = Test::Nginx->new()->plan(2)
    ->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

load_module $modules/ngx_http_waf_module.so;

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

            security_waf on;

            security_check $TLOG>3 LOG;

            security_log %%TESTDIR%%/waf.log;

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

http_get('/sec/log?foo=test');
http_get('/sec/log?waflog=hello&hello=waflog');

$t->stop();

like($t->read_file('waf.log'), qr/"rule_BLOCK_1001_score": "0"/, 'waf log');
like($t->read_file('waf.log'), qr/"TLOG_total": "4"/, 'waf log');
