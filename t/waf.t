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
    security_rule id:1110 "str:!ct@testct" "z:V_ARGS:teststrnotct";
    security_rule id:1011 "str:eq@testeq" "z:V_ARGS:teststr";
    security_rule id:1111 "str:!eq@testeq" "z:V_ARGS:teststrnoteq";
    security_rule id:1012 "str:sw@testsw" "z:V_ARGS:teststr";
    security_rule id:1112 "str:!sw@testsw" "z:V_ARGS:teststrnotsw";
    security_rule id:1013 "str:ew@testew" "z:V_ARGS:teststr";
    security_rule id:1113 "str:!ew@testew" "z:V_ARGS:teststrnotew";
    security_rule id:1014 "str:rx@test-[a-z]{3}-done" "z:V_ARGS:teststr";
    security_rule id:1114 "str:!rx@test-[a-z]{3}-done" "z:V_ARGS:teststrnotrx";
    security_rule id:1015 "libinj:sql" "z:V_ARGS:teststr";
    security_rule id:1016 "libinj:xss" "z:V_ARGS:teststr";
    security_rule id:1017 "str:ge@def" "z:V_ARGS:testge";
    security_rule id:1117 "str:!ge@def" "z:V_ARGS:testnotge";
    security_rule id:1018 "str:le@def" "z:V_ARGS:testle";
    security_rule id:1118 "str:!le@def" "z:V_ARGS:testnotle";
    security_rule id:1019 "libmagic:mime_type@text/plain" "z:V_ARGS:testmagic";
    security_rule id:1119 "libmagic:!mime_type@text/plain" "z:V_ARGS:testmagicnot";
    security_rule id:1020 "libmagic:mime_type@error" "z:V_ARGS:testmagicerror";
    security_rule id:1120 "libmagic:!mime_type@error" "z:V_ARGS:testmagicerrornot";
    security_rule id:1501 "hash:md5@32269ae63a25306bb46a03d6f38bd2b7" "z:V_ARGS:testmd5";
    security_rule id:1502 "hash:!md5@4935f6e27eff994304a1a72768581ce5" "z:V_ARGS:testnotmd5";
    security_rule id:1503 "hash:crc32@4160194954" "z:V_ARGS:testcrc32";
    security_rule id:1504 "hash:crc32_long@800313341" "z:V_ARGS:testcrc32_long";

    security_rule id:1601 "str:decode_url|eq@xx&yy zz" "z:V_ARGS:testdecodeurl";
    security_rule id:1602 "str:decode_base64|decode_url|eq@xx&yy zz" "z:V_ARGS:testdecodebase64url";
    security_rule id:1603 "str:decode_base64|decode_base64|eq@testdecodebase64base64" "z:V_ARGS:testdecodebase64base64";
    security_rule id:1604 "str:decode_url|decode_url|ct@xx&yy ZZ" "z:V_ARGS:testdecodeurlurl";
    security_rule id:1605 "libinj:decode_base64|xss" "z:V_ARGS:testdecodebase64xss";
    security_rule id:1606 "libinj:decode_base64|decode_url|xss" "z:V_ARGS:testdecodebase64urlxss";
    security_rule id:1607 "libinj:decode_url|decode_url|xss" "z:V_ARGS:testdecodeurlurlxss";

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
    security_rule id:7003 "str:eq@multibar" "z:V_BODY:multifoo";

    security_rule id:8001 "str:ct@eval" "z:#FILE";
    security_rule id:8002 "str:ct@testphp" "z:X_FILE:^[a-z]{1,5}\.php$";

    security_rule id:9001 "str:eq@testscorecheck" "s:$TESTCHK:10" "z:V_ARGS:foo";


    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        large_client_header_buffers 4 2k;

        location / {
            security_waf on;
            security_timeout 100ms;

            client_body_buffer_size 8k;

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


$t->try_run('no waf')->plan(136);

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
like(http_get("/?Teststrnotct=hello world"),
    qr/403 Forbidden/, 'waf_1110: test not case contain ok');
like(http_get("/?Teststrnotct=hello TestCT world"),
    qr/200 OK/, 'waf_1110: test not case contain ok');

like(http_get("/?teststr=testeq"),
    qr/403 Forbidden/, 'waf_1011: test equal block');
like(http_get("/?teststr=testequal"),
    qr/200 OK/, 'waf_1011: test equal ok');
like(http_get("/?teststrnoteq=testeq"),
    qr/200 OK/, 'waf_1111: test notequal ok');
like(http_get("/?teststrNotEQ=testequal"),
    qr/403 Forbidden/, 'waf_1111: test notequal block');

like(http_get("/?teststr=testsw world"),
    qr/403 Forbidden/, 'waf_1012: test startwith block');
like(http_get("/?teststr=hello testsw world"),
    qr/200 OK/, 'waf_1012: test startwith ok');
like(http_get("/?teststrnotsw=testsw world"),
    qr/200 OK/, 'waf_1112: test startwith ok');
like(http_get("/?teststrnotsw=hello testsw world"),
    qr/403 Forbidden/, 'waf_1112: test startwith block');

like(http_get("/?teststr=hello testew"),
    qr/403 Forbidden/, 'waf_1013: test endwith block');
like(http_get("/?teststr=hello testew world"),
    qr/200 OK/, 'waf_1013: test endwith ok');
like(http_get("/?teststrnotew=hello testew"),
    qr/200 OK/, 'waf_1113: test endwith ok');
like(http_get("/?teststrnotew=hello testew world"),
    qr/403 Forbidden/, 'waf_1113: test endwith block');

like(http_get("/?teststr=test-abc-done"),
    qr/403 Forbidden/, 'waf_1014: test regex block');
like(http_get("/?teststr=test-abcd-done"),
    qr/200 OK/, 'waf_1014: test regex ok');
like(http_get("/?teststrnotrx=test-abc-done"),
    qr/200 OK/, 'waf_1114: test regex ok');
like(http_get("/?teststrnotrx=test-abcd-done"),
    qr/403 Forbidden/, 'waf_1114: test regex block');

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
like(http_get("/?testge=a"),
    qr/200 OK/, 'waf_1017: test ge ok');

like(http_get("/?testnotge=e"),
    qr/200 OK/, 'waf_1117: test notge ok');
like(http_get("/?testnotge=d"),
    qr/403 Forbidden/, 'waf_1117: test notge block');

like(http_get("/?testle=de"),
    qr/403 Forbidden/, 'waf_1018: test lt block');
like(http_get("/?testle=def"),
    qr/403 Forbidden/, 'waf_1018: test le block');
like(http_get("/?testle=d"),
    qr/403 Forbidden/, 'waf_1018: test lt block');
like(http_get("/?testle=e"),
    qr/200 OK/, 'waf_1018: test le ok');
like(http_get("/?testle=a"),
    qr/403 Forbidden/, 'waf_1018: test le block');


like(http_get("/?testmagic=xxx"),
    qr/403 Forbidden/, 'waf_1019: test magic block');
like(http_get("/?testmagicnot=xxx"),
    qr/200 OK/, 'waf_1019: test magic ok');
like(http_get("/?testmagicerror=xxx"),
    qr/200 OK/, 'waf_1020: test magic ok');
like(http_get("/?testmagicerrornot=xxx"),
    qr/403 Forbidden/, 'waf_1120: test magic block');

like(http_get("/?testmd5=testmd5"),
    qr/403 Forbidden/, 'waf_1501: test md5 hash block');
like(http_get("/?testmd5=testmd5xx"),
    qr/200 OK/, 'waf_1501: test md5 hash ok');

like(http_get("/?testnotmd5=testnotmd5xx"),
    qr/403 Forbidden/, 'waf_1502: test hash not md5 block');
like(http_get("/?testnotmd5=testnotmd5"),
    qr/200 OK/, 'waf_1502: test hash not md5 ok');

like(http_get("/?testcrc32=testcrc32"),
    qr/403 Forbidden/, 'waf_1503: test hash crc32 block');
like(http_get("/?testcrc32=testcrc32xx"),
    qr/200 OK/, 'waf_1503: test hash crc32 ok');

like(http_get("/?testcrc32_long=testcrc32long"),
    qr/403 Forbidden/, 'waf_1504: test hash crc32_long block');
like(http_get("/?testcrc32_long=testcrc32longxx"),
    qr/200 OK/, 'waf_1504: test hash crc32_long ok');

like(http_get("/?testdecodeurl=xx%26yy+zz"),
    qr/403 Forbidden/, 'waf_1601: test decode url block');
like(http_get("/?testdecodeurl=xx%26yyzz"),
    qr/200 OK/, 'waf_1601: test decode url ok');

like(http_get("/?testdecodebase64url=eHglMjZ5eSt6eg=="),
    qr/403 Forbidden/, 'waf_1602: test decode base64 and url block');
like(http_get("/?testdecodebase64url=eHglMjZ5eSt6e=="),
    qr/200 OK/, 'waf_1602: test decode base64 and url ok');

like(http_get("/?testdecodebase64base64=ZEdWemRHUmxZMjlrWldKaGMyVTJOR0poYzJVMk5BPT0="),
    qr/403 Forbidden/, 'waf_1603: test decode base64 and url block');
like(http_get("/?testdecodebase64base64=dGVzdGRlY29kZWJhc2U2NGJhc2U2NA=="),
    qr/200 OK/, 'waf_1603: test decode base64 and url ok');

like(http_get("/?testdecodeurlurl=xx%2526yy%2bZZxyz"),
    qr/403 Forbidden/, 'waf_1604: test decode url and url block');
like(http_get("/?testdecodeurlurl=yy%256yy%2bZZxyz"),
    qr/200 OK/, 'waf_1604: test decode url and url ok');

like(http_get("/?testdecodebase64xss=PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="),
    qr/403 Forbidden/, 'waf_1605: test decode base64 xss block');
like(http_get("/?testdecodebase64xss=xxNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="),
    qr/200 OK/, 'waf_1605: test decode base64 xss ok');

like(http_get("/?testdecodebase64urlxss=JTNDc2NyaXB0JTNFYWxlcnQoMSkrJTNDL3NjcmlwdCUzRQ=="),
    qr/403 Forbidden/, 'waf_1606: test decode base64 url xss block');
like(http_get("/?testdecodebase64urlxss=XXNDc2NyaXB0JTNFYWxlcnQoMSkrJTNDL3NjcmlwdCUzRQ=="),
    qr/200 OK/, 'waf_1606: test decode base64 url xss ok');

like(http_get("/?testdecodeurlurlxss=%253Cimg%2520src=1%2520onerror=alert(1)%253E"),
    qr/403 Forbidden/, 'waf_1607: test decode url url xss block');
like(http_get("/?testdecodeurlurlxss=%253Cimg%2520src=%2520onerror%253E"),
    qr/200 OK/, 'waf_1607: test decode url url xss ok');

like(http_get("/?testnotle=d"),
    qr/200 OK/, 'waf_1118: test notlt ok');
like(http_get("/?testnotle=e"),
    qr/403 Forbidden/, 'waf_1118: test notle block');
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
    "a_b_c_d: bbb" . CRLF .
    "de_fg: cc" . CRLF .
    "hi_j_k: 1234567890abcdefghijkmlnopqrstuvwxyz" . CRLF .
    "a_x_y_z: yyy" . CRLF .
    "b_x_y_z: xxx" . CRLF .
    "c_x_y_z: zzz" . CRLF .
    "d_x_y_z: ooo" . CRLF .
    "e_x_y_z: ppp" . CRLF .
    "f_x_y_z: qqq" . CRLF .
    "x_y_z: rrr" . CRLF .
    "x_y_z: sss" . CRLF .
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
    "Content-Length: 410" . CRLF .
    "Connection: close" . CRLF .
    CRLF .
    "------WebKitFormBoundaryoWJTVDAYOLw4Tlo4" . CRLF .
    "Content-Disposition: form-data; name='MAX_FILE_SIZE'" . CRLF .
    CRLF .
    "100000" . CRLF .
    "------WebKitFormBoundaryoWJTVDAYOLw4Tlo4" . CRLF .
    "Content-Disposition: form-data; name='uploaded'; filename='ttt'" . CRLF .
    "Content-Type: application/octet-stream" . CRLF .
    CRLF .
    "<?php \@test(\$_POST['pass']);?>" . CRLF .
    "------WebKitFormBoundaryoWJTVDAYOLw4Tlo4" . CRLF .
    "Content-Disposition: form-data; name='multifoo'" . CRLF .
    CRLF .
    "multibar" . CRLF .
    "------WebKitFormBoundaryoWJTVDAYOLw4Tlo4--" . CRLF
), qr/403 Forbidden/, 'waf_7003: test body multipart block');


like(http(
    "POST / HTTP/1.1" . CRLF .
    "Host: localhost" . CRLF .
    "Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryoWJTVDAYOLw4Tlo4" . CRLF .
    "Content-Length: 410" . CRLF .
    "Connection: close" . CRLF .
    CRLF .
    "------WebKitFormBoundaryoWJTVDAYOLw4Tlo4" . CRLF .
    "Content-Disposition: form-data; name='MAX_FILE_SIZE'" . CRLF .
    CRLF .
    "100000" . CRLF .
    "------WebKitFormBoundaryoWJTVDAYOLw4Tlo4" . CRLF .
    "Content-Disposition: form-data; name='uploaded'; filename='ttt'" . CRLF .
    "Content-Type: application/octet-stream" . CRLF .
    CRLF .
    "<?php \@test(\$_POST['pass']);?>" . CRLF .
    "------WebKitFormBoundaryoWJTVDAYOLw4Tlo4" . CRLF .
    "Content-Disposition: form-data; name='multifoo'" . CRLF .
    CRLF .
    "multifoo" . CRLF .
    "------WebKitFormBoundaryoWJTVDAYOLw4Tlo4--" . CRLF
), qr/200 OK/, 'waf_7003: test body multipart block');


like(http(
    "POST / HTTP/1.1" . CRLF .
    "Host: localhost" . CRLF .
    "Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryoWJTVDAYOLw4Tlo4" . CRLF .
    "Content-Length: 430" . CRLF .
    "Connection: close" . CRLF .
    CRLF .
    "------WebKitFormBoundaryoWJTVDAYOLw4Tlo4" . CRLF .
    "Content-Disposition: form-data; name='MAX_FILE_SIZE'" . CRLF .
    CRLF .
    "100000" . CRLF .
    "------WebKitFormBoundaryoWJTVDAYOLw4Tlo4" . CRLF .
    "Content-Disposition: form-data; name='uploaded'; filename='ttt'" . CRLF .
    "Content-Type: application/octet-stream" . CRLF .
    CRLF .
    "<?php \@eval(\$_POST['pass']);?>" . CRLF .
    "------WebKitFormBoundaryoWJTVDAYOLw4Tlo4" . CRLF .
    "Content-Disposition: form-data; name='Upload'" . CRLF .
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
    "Content-Disposition: form-data; name='MAX_FILE_SIZE'" . CRLF .
    CRLF .
    "100000" . CRLF .
    "------WebKitFormBoundaryoWJTVDAYOLw4Tlo4" . CRLF .
    "Content-Disposition: form-data; name='uploaded'; filename='ttt'" . CRLF .
    "Content-Type: application/octet-stream" . CRLF .
    CRLF .
    "<?php \@test(\$_POST['pass']);?>" . CRLF .
    "------WebKitFormBoundaryoWJTVDAYOLw4Tlo4" . CRLF .
    "Content-Disposition: form-data; name='Upload'" . CRLF .
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
    "Content-Disposition: form-data; name='MAX_FILE_SIZE'" . CRLF .
    CRLF .
    "100000" . CRLF .
    "------WebKitFormBoundaryoWJTVDAYOLw4Tlo4" . CRLF .
    "Content-Disposition: form-data; filename=xxx; name='uploaded'; filename='empty'" . CRLF .
    "Content-Type: application/octet-stream" . CRLF .
    CRLF .
    "test eval" . CRLF .
    "------WebKitFormBoundaryoWJTVDAYOLw4Tlo4" . CRLF .
    "Content-Disposition: form-data; name='Upload'" . CRLF .
    CRLF .
    "Upload" . CRLF .
    "------WebKitFormBoundaryoWJTVDAYOLw4Tlo4--" . CRLF
), qr/403 Forbidden/, 'waf_8001: test body multipart block');


like(http(
    "POST / HTTP/1.1" . CRLF .
    "Host: localhost" . CRLF .
    "Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryoWJTVDAYOLw4Tlxx" . CRLF .
    "Content-Length: 430" . CRLF .
    "Connection: close" . CRLF .
    CRLF .
    "------WebKitFormBoundaryoWJTVDAYOLw4Tlxx" . CRLF .
    "Content-Disposition: form-data; name='MAX_FILE_SIZE'" . CRLF .
    CRLF .
    "100000" . CRLF .
    "------WebKitFormBoundaryoWJTVDAYOLw4Tlxx" . CRLF .
    "Content-Disposition: form-data; name='uploaded'; filename='ttt.php'" . CRLF .
    "Content-Type: application/octet-stream" . CRLF .
    CRLF .
    "hello testphp xxxxxxxxxxxxxxxxx" . CRLF .
    "------WebKitFormBoundaryoWJTVDAYOLw4Tlxx" . CRLF .
    "Content-Disposition: form-data; name=Upload" . CRLF .
    CRLF .
    "Upload" . CRLF .
    "------WebKitFormBoundaryoWJTVDAYOLw4Tlxx--" . CRLF
), qr/403 Forbidden/, 'waf_8002: test specify filename body multipart block');


like(http(
    "POST / HTTP/1.1" . CRLF .
    "Host: localhost" . CRLF .
    "Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryoWJTVDAYOLw4Tlo4" . CRLF .
    "Content-Length: 430" . CRLF .
    "Connection: close" . CRLF .
    CRLF .
    "------WebKitFormBoundaryoWJTVDAYOLw4Tlo4" . CRLF .
    "Content-Disposition: form-data; name='MAX_FILE_SIZE'" . CRLF .
    CRLF .
    "100000" . CRLF .
    "------WebKitFormBoundaryoWJTVDAYOLw4Tlo4" . CRLF .
    "Content-Disposition: form-data; name='uploaded'; filename='ttt'" . CRLF .
    "Content-Type: application/octet-stream" . CRLF .
    CRLF .
    "hello testphp xxxxxxxxxxxxxxxxxx" . CRLF .
    "------WebKitFormBoundaryoWJTVDAYOLw4Tlo4" . CRLF .
    "Content-Disposition: form-data; name='Upload'" . CRLF .
    CRLF .
    "Upload" . CRLF .
    "------WebKitFormBoundaryoWJTVDAYOLw4Tlo4--" . CRLF
), qr/200 OK/, 'waf_8002: test specify filename body multipart ok');


like(http(
    "POST / HTTP/1.1" . CRLF .
    "Host: localhost" . CRLF .
    "Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryoWJTVDAYOLw4Tlo4" . CRLF .
    "Content-Length: 3700" . CRLF .
    "Connection: close" . CRLF .
    CRLF .
    "------WebKitFormBoundaryoWJTVDAYOLw4Tlo4" . CRLF .
    "Content-Disposition: form-data; name='MAX_FILE_SIZE'" . CRLF .
    CRLF .
    "100000" . CRLF .
    "------WebKitFormBoundaryoWJTVDAYOLw4Tlo4" . CRLF .
    "Content-Disposition: form-data; name='uploaded'; filename=aaa; filename='empty'" . CRLF .
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
    "Content-Disposition: form-data; name='Upload'" . CRLF .
    CRLF .
    "Upload" . CRLF .
    "------WebKitFormBoundaryoWJTVDAYOLw4Tlo4--" . CRLF
), qr/403 Forbidden/, 'waf_8001: test body multipart block');



like(http(
    "POST / HTTP/1.1" . CRLF .
    "Host: localhost" . CRLF .
    "Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryoWJTVDAYOLw4Tlo4" . CRLF .
    "Content-Length: 12500" . CRLF .
    "Connection: close" . CRLF .
    CRLF .
    "------WebKitFormBoundaryoWJTVDAYOLw4Tlo4" . CRLF .
    "Content-Disposition: form-data; name='MAX_FILE_SIZE'" . CRLF .
    CRLF .
    "100000" . CRLF .
    "------WebKitFormBoundaryoWJTVDAYOLw4Tlo4" . CRLF .
    "Content-Disposition: form-data; name='uploaded'; filename=aaa; filename='empty'" . CRLF .
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
    "Content-Disposition: form-data; name='Upload'" . CRLF .
    CRLF .
    "Upload" . CRLF .
    "------WebKitFormBoundaryoWJTVDAYOLw4Tlo4--" . CRLF
), qr/200 OK/, 'waf_8001: test body multipart overflow');


like(http_get("/?foo=testscorecheck"),
    qr/200 OK/, 'waf_9001: test empty score check ok');
###############################################################################
