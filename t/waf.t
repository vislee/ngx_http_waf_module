#!/usr/bin/perl

# (C) vislee

# Tests for http waf module.

###############################################################################

use warnings;
use strict;

use Test::More;

use Socket qw/ CRLF /;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new();

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

load_module /tmp/nginx/modules/ngx_http_waf_module.so;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    sec_rule id:1001 "str:sw@/test" z:#URL;

    sec_rule id:1002 "str:ct@testct" "z:V_ARGS:teststr";
    sec_rule id:1003 "str:eq@testeq" "z:V_ARGS:teststr";
    sec_rule id:1004 "str:sw@testsw" "z:V_ARGS:teststr";
    sec_rule id:1005 "str:ew@testew" "z:V_ARGS:teststr";
    sec_rule id:1006 "str:rx@test-[a-z]{3}-done" "z:V_ARGS:teststr";
    sec_rule id:1007 "libinj:sql" "z:V_ARGS:teststr";
    sec_rule id:1007 "libinj:xss" "z:V_ARGS:teststr";


    sec_rule id:2001 "str:eq@keyval" "z:ARGS";
    sec_rule id:2002 "str:eq@onlyval" "z:#ARGS";
    sec_rule id:2003 "str:eq@onlykey" "z:@ARGS";

    sec_rule id:2004 "str:eq@vbar" "z:V_ARGS:foo";
    sec_rule id:2005 "str:eq@xbar" "z:X_ARGS:^x-[a-z]{2,3}-regex$";

    sec_rule id:3001 "str:eq@keyval"  "z:HEADERS";
    sec_rule id:3002 "str:eq@onlykey" "z:@HEADERS";
    sec_rule id:3003 "str:eq@onlyval" "z:#HEADERS";
    sec_rule id:3004 "str:eq@vbar" "z:V_HEADERS:foo";
    sec_rule id:3005 "str:eq@xbar" "z:X_HEADERS:^X-[A,B,C]{2,4}-regex$";

    sec_rule id:4001 "str:eq@testwl1" "z:V_ARGS:foo|V_ARGS:bar";
    sec_rule id:4002 "str:eq@testwl2" "z:V_ARGS:foo|V_ARGS:bar";

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        location / {
            waf_security on;

            sec_loc_rule "wl:4001" "z:V_ARGS:bar";
            sec_loc_rule "wl:4002" "z:ARGS";

            proxy_pass http://127.0.0.1:8081/;
        }

    }

    server {
        listen       127.0.0.1:8081;
        server_name  localhost;

        location / {
            return 200 "ok";
        }
    }
}

EOF


$t->try_run('no waf')->plan(35);

###############################################################################

like(http_get('/testwaf'), qr/403 Forbidden/, 'waf: test url block');
like(http_get('/'), qr/200 OK/, 'waf url test ok');

like(http_get("/?teststr=hello testct world"),
    qr/403 Forbidden/, 'waf: test contain block');
like(http_get("/?teststr=testeq"),
    qr/403 Forbidden/, 'waf: test equal block');
like(http_get("/?teststr=testsw world"),
    qr/403 Forbidden/, 'waf: test startwith block');
like(http_get("/?teststr=hello testew"),
    qr/403 Forbidden/, 'waf: test endwith block');
like(http_get("/?teststr=test-abc-done"),
    qr/403 Forbidden/, 'waf: test regex block');
like(http_get("/?teststr=1 or 1=1"),
    qr/403 Forbidden/, 'waf: test sqli block');
like(http_get("/?teststr=\"/><script>alert(1)</script><!-"),
    qr/403 Forbidden/, 'waf: test xss block');
like(http_get("/?teststr=hello world"),
    qr/200 OK/, 'waf: test str match ok');


like(http_get("/?foo=keyval"), qr/403 Forbidden/, 'waf: test args block');
like(http_get("/?keyval=bar"), qr/403 Forbidden/, 'waf: test args block');
like(http_get("/?foo=test"), qr/200 OK/, 'waf: test args block');

like(http_get("/?foo=onlyval"), qr/403 Forbidden/, 'waf: test args val block');
like(http_get("/?onlyval=bar"), qr/200 OK/, 'waf: test args val ok');

like(http_get("/?foo=onlykey"), qr/200 OK/, 'waf: test args key ok');
like(http_get("/?onlykey=bar"), qr/403 Forbidden/, 'waf: test args key block');

like(http_get("/?foo=vbar"), qr/403 Forbidden/, 'waf: test args speckey block');
like(http_get("/?test=vbar"), qr/200 OK/, 'waf: test args speckey ok');

like(http_get("/?x-abc-regex=xbar"),
    qr/403 Forbidden/, 'waf: test args regexkey block');
like(http_get("/?test=xbar"), qr/200 OK/, 'waf: test args regexkey ok');


like(http(
    "GET / HTTP/1.0" . CRLF .
    "Host: localhost" . CRLF .
    "X-Foo: keyval" . CRLF .
    CRLF
),qr/403 Forbidden/, 'waf: test headers block');
like(http(
    "GET / HTTP/1.0" . CRLF .
    "Host: localhost" . CRLF .
    "keyval: bar" . CRLF .
    CRLF
), qr/403 Forbidden/, 'waf: test headers block');


like(http(
    "GET / HTTP/1.0" . CRLF .
    "Host: localhost" . CRLF .
    "onlykey: bar" . CRLF .
    CRLF
), qr/403 Forbidden/, 'waf: test headers onlykey block');
like(http(
    "GET / HTTP/1.0" . CRLF .
    "Host: localhost" . CRLF .
    "foo: onlykey" . CRLF .
    CRLF
), qr/200 OK/, 'waf: test headers onlykey ok');


like(http(
    "GET / HTTP/1.0" . CRLF .
    "Host: localhost" . CRLF .
    "foo: onlyval" . CRLF .
    CRLF
), qr/403 Forbidden/, 'waf: test headers onlyval block');
like(http(
    "GET / HTTP/1.0" . CRLF .
    "Host: localhost" . CRLF .
    "onlyval: bar" . CRLF .
    CRLF
), qr/200 OK/, 'waf: test headers onlyval ok');


like(http(
    "GET / HTTP/1.0" . CRLF .
    "Host: localhost" . CRLF .
    "foo: vbar" . CRLF .
    CRLF
), qr/403 Forbidden/, 'waf: test headers sepckey block');
like(http(
    "GET / HTTP/1.0" . CRLF .
    "Host: localhost" . CRLF .
    "test: vbar" . CRLF .
    CRLF
), qr/200 OK/, 'waf: test headers sepckey ok');


like(http(
    "GET / HTTP/1.0" . CRLF .
    "Host: localhost" . CRLF .
    "X-ABC-regex: xbar" . CRLF .
    CRLF
), qr/403 Forbidden/, 'waf: test headers regexkey block');
like(http(
    "GET / HTTP/1.0" . CRLF .
    "Host: localhost" . CRLF .
    "X-YYY-regex: xbar" . CRLF .
    CRLF
), qr/200 OK/, 'waf: test headers regexkey ok');


like(http_get("/?foo=testwl1"),
    qr/403 Forbidden/, 'waf: test whitelist block');
like(http_get("/?bar=testwl1"),
    qr/200 OK/, 'waf: test whitelist ok');
like(http_get("/?foo=testwl2"),
    qr/200 OK/, 'waf: test whitelist2 ok');
like(http_get("/?bar=testwl2"),
    qr/200 OK/, 'waf: test whitelist2 ok');
###############################################################################