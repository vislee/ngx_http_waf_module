#!/usr/bin/perl

# CRS exact-regex rule families in rules/waf-default.conf.
#
# Unlike waf_semantic.t (which inlines its own rules), this test READS
# rules/waf-default.conf and inlines it verbatim, so the default
# ruleset itself is what gets tested. A family missing from the
# default file fails here (TDD red).
#
# Layout: this file is copied to a sibling nginx-tests/ dir, so the
# module source lives at <dirname-of-this-file>/../ngx_http_waf_module
# (CI layout) or the .t runs in place under t/ (dev layout).

use warnings;
use strict;

use Test::More;
use File::Basename qw(dirname);
use IO::Socket::INET;
use FindBin qw($RealBin);

BEGIN { chdir($RealBin); }
use lib 'lib';
use Test::Nginx;my @conf_candidates = (
    "$RealBin/../rules/waf-default.conf",                                  # t/ in-tree
    dirname($RealBin) . "/ngx_http_waf_module/rules/waf-default.conf",    # CI sibling
);

my $conf_path;
for my $c (@conf_candidates) {
    if (-f $c) { $conf_path = $c; last; }
}

if (!$conf_path) {
    plan skip_all => "rules/waf-default.conf not found near $RealBin";
}

my $default_conf = do {
    open my $fh, '<', $conf_path or die "open $conf_path: $!\n";
    local $/; <$fh>;
};
$default_conf =~ s/^\s*#.*$//mg;   # strip comment lines (conf include safety)

# ---------------------------------------------------------------------------
# minimal app config: the checks mirror the README location snippet,
# restricted to the tags this test exercises.
# ---------------------------------------------------------------------------

my $t = Test::Nginx->new()->has(qw/http rewrite/);

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

load_module /tmp/nginx/modules/ngx_http_waf_module.so;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

@@DEFAULT_RULES@@

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        location / {
            security_waf on;
            security_log off;

            security_check $RECON>4 BLOCK;
            security_check $RFI>4 BLOCK;
            security_check $PHP>4 BLOCK;
        }
    }
}

EOF
my $conf = $t->read_file('nginx.conf');
$conf =~ s/\@\@DEFAULT_RULES\@\@/$default_conf/;
$t->write_file('nginx.conf', $conf);

# static location needs an index, otherwise "/" returns nginx's own 403
# ("directory index is forbidden") which would mask WAF verdicts.
$t->write_file('index.html', 'ok');

$t->run()->plan(24);

# fresh connection per request so a BLOCK cannot poison the next one
sub crs_get {
    my ($url) = @_;
    my $sock = IO::Socket::INET->new(
        Proto => 'tcp', PeerAddr => '127.0.0.1:' . port(8080)
    ) or die "can't connect: $!\n";
    return http_get($url, socket => $sock);
}

sub crs_get_ua {
    my ($url, $ua) = @_;
    my $req = "GET $url HTTP/1.1\r\nHost: localhost\r\n"
        . "User-Agent: $ua\r\nConnection: close\r\n\r\n";
    my $sock = IO::Socket::INET->new(
        Proto => 'tcp', PeerAddr => '127.0.0.1:' . port(8080)
    ) or die "can't connect: $!\n";
    return http($req, socket => $sock);
}

# ---------------------------------------------------------------------------
# 913100: security scanner User-Agents (CRS scanners-user-agents.data)
# ---------------------------------------------------------------------------
like(crs_get_ua('/', 'sqlmap/1.4.2#stable (http://sqlmap.org)'),
    qr/403 Forbidden/, '913100: sqlmap UA blocked');
like(crs_get_ua('/', 'Nikto/2.1.6'),
    qr/403 Forbidden/, '913100: nikto UA blocked');
like(crs_get_ua('/', 'Mozilla/5.0 (compatible; Nmap Scripting Engine)'),
    qr/403 Forbidden/, '913100: nmap UA blocked');
like(crs_get_ua('/', 'Havij/1.5 Advanced SQL Injection Tool'),
    qr/403 Forbidden/, '913100: havij UA blocked');
like(crs_get_ua('/', 'masscan/1.3.3'),
    qr/403 Forbidden/, '913100: masscan UA blocked');
like(crs_get_ua('/', 'Acunetix-Scanner'),
    qr/403 Forbidden/, '913100: acunetix UA blocked');
unlike(crs_get_ua('/', 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) '
        . 'AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36'),
    qr/403 Forbidden/, '913100: normal browser UA passes');
unlike(crs_get_ua('/', 'curl/8.4.0'),
    qr/403 Forbidden/, '913100: curl UA passes');

# ---------------------------------------------------------------------------
# 931100/931120: remote file inclusion (ARGS)
# ---------------------------------------------------------------------------
like(crs_get('/?q=file%3A%2F%2F%2Fetc%2Fpasswd'),
    qr/403 Forbidden/, '931100: file:// URI with path blocked');
like(crs_get('/?q=https%3A%2F%2F127.0.0.1%2Fshell.php'),
    qr/403 Forbidden/, '931100: https URL with IP host blocked');
like(crs_get('/?q=ssh%3A%2F%2F10.0.0.1%2Fetc%2Fpasswd'),
    qr/403 Forbidden/, '931100: ssh URL with IP host blocked');
unlike(crs_get('/?q=https%3A%2F%2Fexample.com%2Fpage%3Fid%3D42'),
    qr/403 Forbidden/, '931100: benign https URL passes');
like(crs_get('/?q=file%3A%2F%2F%2Fetc%2Fpasswd%3F'),
    qr/403 Forbidden/, '931120: file URI ending with ? blocked');
like(crs_get('/?q=http%3A%2F%2Fexample.com%2F%3F'),
    qr/403 Forbidden/, '931120: http URL ending with ? blocked');
unlike(crs_get('/?q=http%3A%2F%2Fexample.com%2Findex'),
    qr/403 Forbidden/, '931120: http URL without trailing ? passes');

# ---------------------------------------------------------------------------
# 933100/933110/933111: PHP code injection (ARGS)
# ---------------------------------------------------------------------------
like(crs_get('/?q=%3C%3Fphp%20phpinfo%28%29%3B'),
    qr/403 Forbidden/, '933100: <?php tag blocked');
like(crs_get('/?q=%3C%3F%3D%20eval%28%24_GET%5Bcmd%5D%29%20%3F%3E'),
    qr/403 Forbidden/, '933100: <?= short tag blocked');
like(crs_get('/?q=%24_GET%5Bcmd%5D'),
    qr/403 Forbidden/, '933110: $_GET superglobal blocked');
like(crs_get('/?q=%24_SERVER%5BREQUEST_URI%5D'),
    qr/403 Forbidden/, '933110: $_SERVER superglobal blocked');
unlike(crs_get('/?q=%24GET'),
    qr/403 Forbidden/, '933110: bare $GET (no underscore) passes');
like(crs_get('/?q=eval%28%24_GET%5Bcmd%5D%29'),
    qr/403 Forbidden/, '933111: eval() blocked');
like(crs_get('/?q=system%28%27id%27%29'),
    qr/403 Forbidden/, '933111: system() blocked');
unlike(crs_get('/?q=evaluated+expression'),
    qr/403 Forbidden/, '933111: word containing eval passes');
unlike(crs_get('/?q=systematic+review'),
    qr/403 Forbidden/, '933111: word containing system passes');

# ---------------------------------------------------------------------------
