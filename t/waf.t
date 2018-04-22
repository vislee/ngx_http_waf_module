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

    security_rule id:1001 "str:sw@/test" z:#URL "note:test url";
    security_rule id:1002 "str:sw@/hello" "z:X_URL:/hello/[a-z]{3,5}";

    security_rule id:1010 "str:ct@testct" "z:V_ARGS:teststr";
    security_rule id:1011 "str:eq@testeq" "z:V_ARGS:teststr";
    security_rule id:1012 "str:sw@testsw" "z:V_ARGS:teststr";
    security_rule id:1013 "str:ew@testew" "z:V_ARGS:teststr";
    security_rule id:1014 "str:rx@test-[a-z]{3}-done" "z:V_ARGS:teststr";
    security_rule id:1015 "libinj:sql" "z:V_ARGS:teststr";
    security_rule id:1016 "libinj:xss" "z:V_ARGS:teststr";
    security_rule id:1017 "str:ge@def" "z:V_ARGS:testge";
    security_rule id:1018 "str:le@def" "z:V_ARGS:testle";



    security_rule id:2001 "str:eq@argskv" "z:ARGS";
    security_rule id:2002 "str:eq@argsonlyval" "z:#ARGS";
    security_rule id:2003 "str:eq@argsonlykey" "z:@ARGS";

    security_rule id:2004 "str:eq@argsvbar" "z:V_ARGS:foo";
    security_rule id:2005 "str:eq@argsxbar" "z:X_ARGS:^x-[a-z]{2,3}-regex$";
    security_rule id:2006 "str:eq@/allowurl" "s:$ALLOW:5" "z:#URL";

    security_rule id:3001 "str:eq@headerkeyval"  "z:HEADERS";
    security_rule id:3002 "str:eq@headeronlykey" "z:@HEADERS";
    security_rule id:3003 "str:eq@headeronlyval" "z:#HEADERS";
    security_rule id:3004 "str:eq@headervbar" "z:V_HEADERS:foo";
    security_rule id:3005 "str:eq@headerxbar" "z:X_HEADERS:^X-[A,B,C,D]{2,4}-regex$";

    security_rule id:4000 "str:eq@testwl0" "s:$WL0:2" "z:ARGS";
    security_rule id:4001 "str:eq@testwl1" "s:$WL1:2" "z:ARGS";
    security_rule id:4002 "str:eq@testwl2" "z:V_ARGS:foo|V_ARGS:bar";
    security_rule id:4003 "str:eq@testwl3" "z:V_ARGS:foo|V_ARGS:bar";
    security_rule id:4004 "str:eq@testwl4" "z:HEADERS";
    security_rule id:4005 "str:eq@testwl5" "z:ARGS";
    security_rule id:4006 "str:eq@testwl6" "z:ARGS";
    security_rule id:4007 "str:eq@testwl7" "z:ARGS";
    security_rule id:4008 "str:eq@testwl8" "z:ARGS";
    security_rule id:4009 "str:eq@testwl9" "z:HEADERS";

    security_rule id:5001 "str:eq@testcalc" "s:$CALC1:2" "z:V_ARGS:foo|V_ARGS:bar";

    security_rule id:6001 "str:eq@testvar" "s:$VAR:2" "z:V_ARGS:foo|V_ARGS:bar";

    security_rule id:7001 "str:ct@testbody" "z:#RAW_BODY";
    security_rule id:7002 "str:eq@testurlencodebody" "z:V_BODY:foo";

    security_rule id:8001 "str:ct@eval" "z:#FILE";

    security_rule id:9001 "str:eq@testscorecheck" "s:$TESTCHK:10" "z:V_ARGS:foo";


    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        large_client_header_buffers 4 1k;

        location / {
            security_waf on;

            client_body_buffer_size 4k;

            security_loc_rule "wl:4000" "z:@ARGS";
            security_loc_rule "wl:4002" "z:V_ARGS:bar";
            security_loc_rule "wl:4003" "z:ARGS";
            security_loc_rule "wl:4004" "z:X_HEADERS:x-[a-z]{1,5}|V_HEADERS:foo";
            security_loc_rule "wl:4005" "z:ARGS";
            security_loc_rule "wl:4007";
            security_loc_rule "wl:4009" "z:X_HEADERS:x-[a-z]{1,5}|V_HEADERS:foo|@HEADERS";

            security_check $WL0>3 BLOCK;
            security_check $WL1>3 BLOCK;
            security_check $CALC1>3 BLOCK;
            security_check $VAR>3 $var_res;
            security_check $ALLOW>1 ALLOW;

            security_log off;

            proxy_pass http://127.0.0.1:8081/$var_res;

            location /innerlocation/ {
                security_waf on;

                security_loc_rule id:20001 "str:eq@innerlocation" "s:$WL0:3" "z:V_ARGS:Foo_location";

                security_check $WL0>4 BLOCK;

                security_log %%TESTDIR%%/waf_location.log;

                proxy_pass http://127.0.0.1:8081/;
            }
        }
    }

    server {
        listen       127.0.0.1:8081;
        server_name  localhost;

        location / {
            return 200 "ok";
        }

        location /block {
            return "302" "http://test.com/";
        }
    }
}

EOF


$t->try_run('no waf')->plan(90);

###############################################################################

like(http_get('/testwaf'), qr/403 Forbidden/, 'waf_1001: test url block');
like(http_get('/'), qr/200 OK/, 'waf_1001: url test ok');

like(http_get('/hello/waf'), qr/403 Forbidden/, 'waf_1002: test url block');
like(http_get('/hello/hellowaf'), qr/403 Forbidden/, 'waf_1002: test url ok');

like(http_get("/?teststr=hello testct world"),
    qr/403 Forbidden/, 'waf_1010: test contain block');
like(http_get("/?TESTstr=hello TESTct world"),
    qr/403 Forbidden/, 'waf_1010: test case contain block');
like(http_get("/?teststr=hello world"),
    qr/200 OK/, 'waf_1010: test contain ok');
like(http_get("/?teststr=testeq"),
    qr/403 Forbidden/, 'waf_1011: test equal block');
like(http_get("/?teststr=testequal"),
    qr/200 OK/, 'waf_1011: test equal ok');
like(http_get("/?teststr=testsw world"),
    qr/403 Forbidden/, 'waf_1012: test startwith block');
like(http_get("/?teststr=hello testsw world"),
    qr/200 OK/, 'waf_1012: test startwith ok');
like(http_get("/?teststr=hello testew"),
    qr/403 Forbidden/, 'waf_1013: test endwith block');
like(http_get("/?teststr=hello testew world"),
    qr/200 OK/, 'waf_1013: test endwith ok');
like(http_get("/?teststr=test-abc-done"),
    qr/403 Forbidden/, 'waf_1014: test regex block');
like(http_get("/?teststr=test-abcd-done"),
    qr/200 OK/, 'waf_1014: test regex ok');
like(http_get("/?teststr=1 or 1=1"),
    qr/403 Forbidden/, 'waf_1015: test sqli block');
like(http_get("/?teststr=1"),
    qr/200 OK/, 'waf_1015: test sqli ok');
like(http_get("/?teststr=\"/><script>alert(1)</script><!-"),
    qr/403 Forbidden/, 'waf_1016: test xss block');
like(http_get("/?teststr=1"),
    qr/200 OK/, 'waf_1016: test xss ok');

like(http_get("/?testge=defa"),
    qr/403 Forbidden/, 'waf_1017: test gt block');
like(http_get("/?testge=def"),
    qr/403 Forbidden/, 'waf_1017: test ge block');
like(http_get("/?testge=e"),
    qr/403 Forbidden/, 'waf_1017: test ge block');
like(http_get("/?testge=d"),
    qr/200 OK/, 'waf_1017: test ge ok');

like(http_get("/?testle=de"),
    qr/403 Forbidden/, 'waf_1018: test lt block');
like(http_get("/?testle=def"),
    qr/403 Forbidden/, 'waf_1018: test le block');
like(http_get("/?testle=d"),
    qr/403 Forbidden/, 'waf_1018: test lt block');
like(http_get("/?testle=e"),
    qr/200 OK/, 'waf_1018: test le ok');

like(http_get("/?teststr=hello world"),
    qr/200 OK/, 'waf_10xx: test str match ok');
like(http_get("/?aaaaaa=hello world"),
    qr/200 OK/, 'waf_10x: test str match ok');

like(http_get("/?foo=argskv"),
    qr/403 Forbidden/, 'waf_2001: test args block');
like(http_get("/?foo=argsKV"),
    qr/403 Forbidden/, 'waf_2001: test caseargs block');
like(http_get("/?argskv=bar"),
    qr/403 Forbidden/, 'waf_2001: test args block');
like(http_get("/?foo=test"), qr/200 OK/, 'waf_2001: test args block');

like(http_get("/?foo=argsonlyval"),
    qr/403 Forbidden/, 'waf_2002: test args val block');
like(http_get("/?foo=argstval"), qr/200 OK/, 'waf_2002: test args val ok');
like(http_get("/?argsonlyval=bar"), qr/200 OK/, 'waf_2002: test args val ok');

like(http_get("/?foo=argsonlykey"), qr/200 OK/, 'waf_2003: test args key ok');
like(http_get("/?foo=testargsv"),
    qr/200 OK/, 'waf_2003: test args key ok');
like(http_get("/?argsonlykey=bar"),
    qr/403 Forbidden/, 'waf_2003: test args key block');

like(http_get("/?foo=argsvbar"),
    qr/403 Forbidden/, 'waf_2004: test args speckey block');
like(http_get("/?foo=argstval"),
    qr/200 OK/, 'waf_2004: test args speckey ok');
like(http_get("/?test=argsvbar"), qr/200 OK/, 'waf_2004: test args speckey ok');

like(http_get("/?x-abc-regex=argsxbar"),
    qr/403 Forbidden/, 'waf_2005: test args regexkey block');
like(http_get("/?x-abc-regex=argsxtval"),
    qr/200 OK/, 'waf_2005: test args regexkey ok');
like(http_get("/?test=argsxbar"),
    qr/200 OK/, 'waf_2005: test args regexkey ok');

like(http_get("/allowurl?foo=argsvbar"),
    qr/200 OK/, 'waf_2006: test allow uri ok');

like(http(
    "GET / HTTP/1.0" . CRLF .
    "Host: localhost" . CRLF .
    "X-Foo: headerkeyval" . CRLF .
    CRLF
),qr/403 Forbidden/, 'waf_3001: test headers block');
like(http(
    "GET / HTTP/1.0" . CRLF .
    "Host: localhost" . CRLF .
    "headerkeyval: bar" . CRLF .
    CRLF
), qr/403 Forbidden/, 'waf_3001: test headers block');
like(http(
    "GET / HTTP/1.0" . CRLF .
    "Host: localhost" . CRLF .
    "X-Foo: foobar" . CRLF .
    CRLF
),qr/200 OK/, 'waf_3001: test headers ok');


like(http(
    "GET / HTTP/1.0" . CRLF .
    "Host: localhost" . CRLF .
    "headeronlykey: bar" . CRLF .
    CRLF
), qr/403 Forbidden/, 'waf_3002: test headers onlykey block');
like(http(
    "GET / HTTP/1.0" . CRLF .
    "Host: localhost" . CRLF .
    "foo: headeronlykey" . CRLF .
    CRLF
), qr/200 OK/, 'waf_3002: test headers onlykey ok');


like(http(
    "GET / HTTP/1.0" . CRLF .
    "Host: localhost" . CRLF .
    "foo: headeronlyval" . CRLF .
    CRLF
), qr/403 Forbidden/, 'waf_3003: test headers onlyval block');
like(http(
    "GET / HTTP/1.0" . CRLF .
    "Host: localhost" . CRLF .
    "headeronlyval: bar" . CRLF .
    CRLF
), qr/200 OK/, 'waf_3003: test headers onlyval ok');


like(http(
    "GET / HTTP/1.0" . CRLF .
    "Host: localhost" . CRLF .
    "foo: headervbar" . CRLF .
    CRLF
), qr/403 Forbidden/, 'waf_3004: test headers sepckey block');
like(http(
    "GET / HTTP/1.0" . CRLF .
    "Host: localhost" . CRLF .
    "aaa: bbbb" . CRLF .
    "ccc: dddd" . CRLF .
    "ddd: eeee" . CRLF .
    "eee: ffff" . CRLF .
    "fff: gggg" . CRLF .
    "ggg: hhhh" . CRLF .
    "hhh: iiii" . CRLF .
    "iii: jjjj" . CRLF .
    "abcd: aa" . CRLF .
    "defg: bb" . CRLF .
    "hijk: cc" . CRLF .
    "xyz: xxx" . CRLF .
    "x_y_z: yyy" . CRLF .
    "foo: headervbar" . CRLF .
    CRLF
), qr/403 Forbidden/, 'waf_3004: test multi headers sepckey block');
like(http(
    "GET / HTTP/1.0" . CRLF .
    "Host: localhost" . CRLF .
    "test: headervbar" . CRLF .
    CRLF
), qr/200 OK/, 'waf_3004: test headers sepckey ok');


like(http(
    "GET / HTTP/1.0" . CRLF .
    "Host: localhost" . CRLF .
    "X-ABC-regex: headerxbar" . CRLF .
    CRLF
), qr/403 Forbidden/, 'waf_3005: test headers regexkey block');
like(http(
    "GET / HTTP/1.0" . CRLF .
    "Host: localhost" . CRLF .
    "X-YYY-regex: headerxbar" . CRLF .
    CRLF
), qr/200 OK/, 'waf_3005: test headers regexkey ok');


like(http_get("/?testwl0=testwl0"),
    qr/200 OK/, 'waf_4000: test whitelist0 ok');
like(http_get("/?testwl1=testwl1"),
    qr/403 Forbidden/, 'waf_4001: test whitelist1 block');
like(http_get("/?foo=testwl2"),
    qr/403 Forbidden/, 'waf_4002: test whitelist2 block');
like(http_get("/?bar=testwl2"),
    qr/200 OK/, 'waf_4002: test whitelist2 ok');
like(http_get("/?foo=testwl3"),
    qr/200 OK/, 'waf_4003: test whitelist3 ok');
like(http_get("/?bar=testwl3"),
    qr/200 OK/, 'waf_4003: test whitelist3 ok');
like(http(
    "GET / HTTP/1.0" . CRLF .
    "Host: localhost" . CRLF .
    "foo: testwl4" . CRLF .
    CRLF
), qr/200 OK/, 'waf_4004: test whitelist4 ok');
like(http(
    "GET / HTTP/1.0" . CRLF .
    "Host: localhost" . CRLF .
    "x-xyz: testwl4" . CRLF .
    CRLF
), qr/200 OK/, 'waf_4004: test whitelist4 ok');
like(http(
    "GET / HTTP/1.0" . CRLF .
    "Host: localhost" . CRLF .
    "bar: testwl4" . CRLF .
    CRLF
), qr/403 Forbidden/, 'waf_4004: test whitelist4 block');
like(http(
    "GET / HTTP/1.0" . CRLF .
    "Host: localhost" . CRLF .
    "testwl4: bar" . CRLF .
    CRLF
), qr/403 Forbidden/, 'waf_4004: test whitelist4 block');
like(http_get("/?foo=testwl5"),
    qr/200 OK/, 'waf_4005: test whitelist5 ok');
like(http_get("/?bar=testwl6"),
    qr/403 Forbidden/, 'waf_4006: test whitelist6 block');
like(http_get("/?foo=testwl7"),
    qr/200 OK/, 'waf_4007: test whitelist5 ok');
like(http_get("/?bar=testwl8"),
    qr/403 Forbidden/, 'waf_4008: test whitelist6 block');
like(http(
    "GET / HTTP/1.0" . CRLF .
    "Host: localhost" . CRLF .
    "testwl9: bar" . CRLF .
    CRLF
), qr/200 OK/, 'waf_4009: test whitelist4 ok');
like(http(
    "GET / HTTP/1.0" . CRLF .
    "Host: localhost" . CRLF .
    "foo: testwl9" . CRLF .
    CRLF
), qr/200 OK/, 'waf_4009: test whitelist4 ok');

like(http_get("/?foo=testcalc&bar=testcalc"),
    qr/403 Forbidden/, 'waf_5001: test calc block');
like(http_get("/?foo=testcalc&test=testcalc"),
    qr/200 OK/, 'waf_5001: test calc ok');

like(http_get("/?foo=testvar&bar=testvar"),
    qr/302 Found/, 'waf_6001: test calc block');
like(http_get("/?foo=testvar&test=testvar"),
    qr/200 OK/, 'waf_6001: test calc ok');

like(http_get("/innerlocation/?foo=testwl0&foo_Location=innerlocation"),
    qr/403 Forbidden/, 'waf_20001: test inner location block');
like(http_get("/innerlocation/?foo_Location=innerlocation"),
    qr/200 OK/, 'waf_20001: test inner location ok');

like(http(
    "POST / HTTP/1.0" . CRLF .
    "Host: localhost" . CRLF .
    "Content-Type: application/x-www-form-urlencoded" . CRLF .
    "Content-Length: 9" . CRLF .
    CRLF .
    "testbody!"
), qr/403 Forbidden/, 'waf_7001: test raw body block');
like(http(
    "POST / HTTP/1.0" . CRLF .
    "Host: localhost" . CRLF .
    "Content-Type: application/x-www-form-urlencoded" . CRLF .
    "Content-Length: 11" . CRLF .
    CRLF .
    "helloworld!"
), qr/200 OK/, 'waf_7001: test raw body ok');


like(http(
    "POST / HTTP/1.0" . CRLF .
    "Host: localhost" . CRLF .
    "Content-Type: application/x-www-form-urlencoded" . CRLF .
    "Content-Length: 30" . CRLF .
    CRLF .
    "foo=testurlencodebody&bar=test"
), qr/403 Forbidden/, 'waf_7002: test body urlencode block');
like(http(
    "POST / HTTP/1.0" . CRLF .
    "Host: localhost" . CRLF .
    "Content-Type: application/x-www-form-urlencoded" . CRLF .
    "Content-Length: 30" . CRLF .
    CRLF .
    "fcc=testurlencodebody&bar=test"
), qr/200 OK/, 'waf_7002: test body urlencode ok');


like(http(
    "POST / HTTP/1.1" . CRLF .
    "Host: localhost" . CRLF .
    "Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryoWJTVDAYOLw4Tlo4" . CRLF .
    "Content-Length: 430" . CRLF .
    "Connection: close" . CRLF .
    CRLF .
    "------WebKitFormBoundaryoWJTVDAYOLw4Tlo4" . CRLF .
    "Content-Disposition: form-data; name=\"MAX_FILE_SIZE\"" . CRLF .
    CRLF .
    "100000" . CRLF .
    "------WebKitFormBoundaryoWJTVDAYOLw4Tlo4" . CRLF .
    "Content-Disposition: form-data; name=\"uploaded\"; filename=\"ttt\"" . CRLF .
    "Content-Type: application/octet-stream" . CRLF .
    CRLF .
    "<?php \@eval(\$_POST['pass']);?>" . CRLF .
    "------WebKitFormBoundaryoWJTVDAYOLw4Tlo4" . CRLF .
    "Content-Disposition: form-data; name=\"Upload\"" . CRLF .
    CRLF .
    "Upload" . CRLF .
    "------WebKitFormBoundaryoWJTVDAYOLw4Tlo4--" . CRLF
), qr/403 Forbidden/, 'waf_8001: test body multipart block');

like(http(
    "POST / HTTP/1.1" . CRLF .
    "Host: localhost" . CRLF .
    "Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryoWJTVDAYOLw4Tlo4" . CRLF .
    "Content-Length: 430" . CRLF .
    "Connection: close" . CRLF .
    CRLF .
    "------WebKitFormBoundaryoWJTVDAYOLw4Tlo4" . CRLF .
    "Content-Disposition: form-data; name=\"MAX_FILE_SIZE\"" . CRLF .
    CRLF .
    "100000" . CRLF .
    "------WebKitFormBoundaryoWJTVDAYOLw4Tlo4" . CRLF .
    "Content-Disposition: form-data; name=\"uploaded\"; filename=\"ttt\"" . CRLF .
    "Content-Type: application/octet-stream" . CRLF .
    CRLF .
    "<?php \@test(\$_POST['pass']);?>" . CRLF .
    "------WebKitFormBoundaryoWJTVDAYOLw4Tlo4" . CRLF .
    "Content-Disposition: form-data; name=\"Upload\"" . CRLF .
    CRLF .
    "Upload" . CRLF .
    "------WebKitFormBoundaryoWJTVDAYOLw4Tlo4--" . CRLF
), qr/200 OK/, 'waf_8001: test body multipart ok');


like(http(
    "POST / HTTP/1.1" . CRLF .
    "Host: localhost" . CRLF .
    "Content-Type: multipart/form-data; boundary= '----WebKitFormBoundaryoWJTVDAYOLw4Tlo4'" . CRLF .
    "Content-Length: 425" . CRLF .
    "Connection: close" . CRLF .
    CRLF .
    "------WebKitFormBoundaryoWJTVDAYOLw4Tlo4" . CRLF .
    "Content-Disposition: form-data; name=\"MAX_FILE_SIZE\"" . CRLF .
    CRLF .
    "100000" . CRLF .
    "------WebKitFormBoundaryoWJTVDAYOLw4Tlo4" . CRLF .
    "Content-Disposition: form-data; filename=xxx; name=\"uploaded\"; filename=\"empty\"" . CRLF .
    "Content-Type: application/octet-stream" . CRLF .
    CRLF .
    "test eval" . CRLF .
    "------WebKitFormBoundaryoWJTVDAYOLw4Tlo4" . CRLF .
    "Content-Disposition: form-data; name=\"Upload\"" . CRLF .
    CRLF .
    "Upload" . CRLF .
    "------WebKitFormBoundaryoWJTVDAYOLw4Tlo4--" . CRLF
), qr/403 Forbidden/, 'waf_8001: test body multipart block');


like(http(
    "POST / HTTP/1.1" . CRLF .
    "Host: localhost" . CRLF .
    "Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryoWJTVDAYOLw4Tlo4" . CRLF .
    "Content-Length: 3700" . CRLF .
    "Connection: close" . CRLF .
    CRLF .
    "------WebKitFormBoundaryoWJTVDAYOLw4Tlo4" . CRLF .
    "Content-Disposition: form-data; name=\"MAX_FILE_SIZE\"" . CRLF .
    CRLF .
    "100000" . CRLF .
    "------WebKitFormBoundaryoWJTVDAYOLw4Tlo4" . CRLF .
    "Content-Disposition: form-data; name=\"uploaded\"; filename=aaa; filename=\"empty\"" . CRLF .
    "Content-Type: application/octet-stream" . CRLF .
    CRLF .
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" .
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" .
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" .
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" .
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" .
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" .
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" .
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" .
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" .
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" .
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" .
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" .
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" .
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" .
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" .
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" .
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" .
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" .
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" .
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" .
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" .
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" .
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" .
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" .
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" .
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" .
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" .
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" .
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" .
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" .
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" .
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" .
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" .
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" .
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" .
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" .
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" .
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" .
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" .
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" .
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" .
    "eval" . CRLF .
    "------WebKitFormBoundaryoWJTVDAYOLw4Tlo4" . CRLF .
    "Content-Disposition: form-data; name=\"Upload\"" . CRLF .
    CRLF .
    "Upload" . CRLF .
    "------WebKitFormBoundaryoWJTVDAYOLw4Tlo4--" . CRLF
), qr/403 Forbidden/, 'waf_8001: test body multipart block');



like(http(
    "POST / HTTP/1.1" . CRLF .
    "Host: localhost" . CRLF .
    "Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryoWJTVDAYOLw4Tlo4" . CRLF .
    "Content-Length: 8500" . CRLF .
    "Connection: close" . CRLF .
    CRLF .
    "------WebKitFormBoundaryoWJTVDAYOLw4Tlo4" . CRLF .
    "Content-Disposition: form-data; name=\"MAX_FILE_SIZE\"" . CRLF .
    CRLF .
    "100000" . CRLF .
    "------WebKitFormBoundaryoWJTVDAYOLw4Tlo4" . CRLF .
    "Content-Disposition: form-data; name=\"uploaded\"; filename=aaa; filename=\"empty\"" . CRLF .
    "Content-Type: application/octet-stream" . CRLF .
    CRLF .
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" .
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" .
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" .
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" .
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" .
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" .
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" .
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" .
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" .
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" .
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" .
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" .
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" .
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" .
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" .
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" .
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" .
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" .
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" .
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" .
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" .
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" .
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" .
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" .
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" .
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" .
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" .
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" .
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" .
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" .
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" .
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" .
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" .
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" .
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" .
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" .
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" .
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" .
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" .
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" .
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" .
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" .
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" .
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" .
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" .
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" .
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" .
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" .
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" .
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" .
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" .
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" .
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" .
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" .
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" .
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" .
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" .
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" .
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" .
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" .
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" .
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" .
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" .
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" .
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" .
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" .
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" .
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" .
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" .
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" .
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" .
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" .
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" .
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" .
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" .
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" .
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" .
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" .
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" .
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" .
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" .
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" .
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" .
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" .
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" .
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" .
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" .
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" .
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" .
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" .
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" .
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" .
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" .
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" .
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" .
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" .
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" .
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" .
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" .
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" .
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" .
    "eval" . CRLF .
    "------WebKitFormBoundaryoWJTVDAYOLw4Tlo4" . CRLF .
    "Content-Disposition: form-data; name=\"Upload\"" . CRLF .
    CRLF .
    "Upload" . CRLF .
    "------WebKitFormBoundaryoWJTVDAYOLw4Tlo4--" . CRLF
), qr/200 OK/, 'waf_8001: test body multipart overflow');


like(http_get("/?foo=testscorecheck"),
    qr/200 OK/, 'waf_9001: test empty score check ok');
###############################################################################
