/**
 * Copyright 2012-2026 Nick Galbreath / libinjection contributors
 * nickg@client9.com
 * BSD License -- see `COPYING.txt` for details
 */

#include <string.h>

#include "libinjection_ssrf.h"

#define ISDIGIT(a) ((unsigned)((a) - '0') <= 9)

#ifndef TRUE
#define TRUE 1
#endif
#ifndef FALSE
#define FALSE 0
#endif

/*
 * always suspicious: cloud metadata endpoints and schemes that only
 * exist to talk to internal services
 */
static const char* ALWAYS[] = {
    "169.254.169.254"          /* AWS/GCP/OpenStack metadata */
    , "169.254.170.2"          /* ECS task metadata */
    , "100.100.100.200"        /* Alibaba metadata */
    , "metadata.google.internal"
    , "metadata.goog"
    , "instance-data"
    , "gopher://"
    , "dict://"
    , "tftp://"
    , NULL
};

/*
 * loopback/private targets: only flagged in URL-shaped positions
 * (after '=', '/', quote), so prose like "ping 127.0.0.1" or
 * "version 10.04" stays benign
 */
/*
 * numeric IP obfuscation straight after a scheme://: dotless decimal
 * (http://2852039166) and dotted hex (http://0xA9.0xFE.0xA9.0xFE)
 */
static char lower(char c);

static int numeric_ip_after_scheme(const char* s, size_t len)
{
    size_t k;

    for (k = 0; k + 9 <= len; ++k) {
        size_t digits = 0;
        size_t j;
        int hex = FALSE;
        int hexany = FALSE;

        if (! (s[k] == ':' && s[k + 1] == '/' && s[k + 2] == '/')) {
            continue;
        }
        j = k + 3;
        while (j < len) {
            char c = lower(s[j]);
            if (c >= '0' && c <= '9') {
                digits += 1;
                j += 1;
            } else if (c == 'x' && j == k + 3) {
                hex = TRUE;
                hexany = TRUE;
                j += 1;
            } else if (hex && ((c >= 'a' && c <= 'f') || c == '.')) {
                hexany = TRUE;
                j += 1;
            } else {
                break;
            }
        }
        if (digits >= 7 && digits <= 10) {
            return TRUE;
        }
        if (hex && hexany && j > k + 5) {
            return TRUE;
        }
    }
    return FALSE;
}

/*
 * illegal dotted-quad straight after a scheme:// (a segment above 255
 * or an octal-style zero-padded segment) is an IPv4 obfuscation probe
 */
static int illegal_ipv4_after_scheme(const char* s, size_t len)
{
    size_t k;

    for (k = 0; k + 7 <= len; ++k) {
        size_t seg;
        size_t pos;
        int segments = 0;
        int illegal = FALSE;
        size_t q;

        if (! (s[k] == ':' && s[k + 1] == '/' && s[k + 2] == '/')) {
            continue;
        }
        pos = k + 3;
        for (seg = 0; seg < 4; ++seg) {
            size_t dstart = pos;
            size_t dlen = 0;
            while (pos < len && s[pos] >= '0' && s[pos] <= '9' &&
                   dlen < 10) {
                pos += 1;
                dlen += 1;
            }
            if (dlen == 0) {
                break;
            }
            segments += 1;
            if (dlen > 3) {
                illegal = TRUE;                 /* overflow segment */
            }
            if (dlen > 1 && s[dstart] == '0') {
                illegal = TRUE;                 /* zero-padded octal */
            }
            if (pos < len && s[pos] == '.') {
                pos += 1;
                continue;
            }
            break;
        }
        if (segments == 4) {
            /* re-scan first segment for value > 255 */
            pos = k + 3;
            for (q = 0; q < 4 && ! illegal; ++q) {
                long value = 0;
                while (pos < len && s[pos] >= '0' && s[pos] <= '9') {
                    value = value * 10 + (s[pos] - '0');
                    if (value > 255) {
                        illegal = TRUE;
                    }
                    pos += 1;
                }
                if (pos < len && s[pos] == '.') {
                    pos += 1;
                }
            }
        }
        if (segments == 4 && illegal) {
            return TRUE;
        }
    }
    return FALSE;
}

static const char* LOCAL_TARGETS[] = {
    "localhost"
    , "127.0.0.1"
    , "127.1"
    , "0.0.0.0"
    , "[::1]"
    , "::1]"
    , "10."
    , "192.168."
    , "172.16."
    , "172.17."
    , "172.18."
    , "172.19."
    , "172.20."
    , "172.21."
    , "172.22."
    , "172.23."
    , "172.24."
    , "172.25."
    , "172.26."
    , "172.27."
    , "172.28."
    , "172.29."
    , "172.30."
    , "172.31."
    , "2130706433"             /* 127.0.0.1 as decimal */
    , "0x7f000001"             /* 127.0.0.1 as hex */
    , "0177.0.0.1"             /* 127.0.0.1 as octal */
    , NULL
};

static char lower(char c)
{
    if (c >= 'A' && c <= 'Z') {
        return (char) (c + 0x20);
    }
    return c;
}

/* after a dotted private-range prefix, require the remaining octets
 * of a full dotted quad so plain decimals and version strings
 * ("price=10.5", "version=10.04", "10.5.1") stay benign */
static int octet_tail_ok(const char* s, size_t len, size_t pos, int need)
{
    int seg;

    for (seg = 0; seg < need; ++seg) {
        size_t dlen = 0;
        while (pos < len && ISDIGIT(s[pos]) && dlen < 3) {
            pos += 1;
            dlen += 1;
        }
        if (dlen == 0) {
            return FALSE;
        }
        if (seg + 1 < need) {
            if (pos >= len || s[pos] != '.') {
                return FALSE;
            }
            pos += 1;
        }
    }
    return TRUE;
}

static int boundary_ok(const char* s, size_t len, size_t pos, size_t nlen,
                       const char* needle)
{
    char prev;
    char next;

    prev = (pos == 0) ? '=' : s[pos - 1];
    if (pos > 0) {
        switch (prev) {
        case '=': case '/': case '\'': case '"': case '&': case '[':
            break;
        case ' ':
            /* "... = 127.0.0.1" with a space after '=' is fine too */
            if (pos < 2 || (s[pos - 2] != '=' && s[pos - 2] != ',')) {
                return FALSE;
            }
            break;
        default:
            /* "110.4" or "version10." style glue: not URL-shaped */
            return FALSE;
        }
    }

    if (pos + nlen >= len) {
        return TRUE;
    }
    next = s[pos + nlen];

    if (pos == 0 && (next == ' ' || next == '\t') &&
        needle[nlen - 1] != '.') {
        /* value itself starts with the word and continues as prose
         * ("localhost development mode") - not URL-shaped */
        return FALSE;
    }

    if (needle[nlen - 1] == '.') {
        /* prefix targets like "192.168." continue with an octet, or
         * are hostnames straight after "//" ("http://10.internal") */
        if (ISDIGIT(next)) {
            /* a dotted-quad continuation must follow: the prefix dots
             * decide how many octets are still needed ("10." -> 3,
             * "192.168." -> 2), so decimals like "price=10.5" and
             * version strings like "10.04" never match */
            int dots = 0;
            size_t q;
            for (q = 0; q < nlen; ++q) {
                if (needle[q] == '.') {
                    dots += 1;
                }
            }
            return octet_tail_ok(s, len, pos + nlen, 4 - dots);
        }
        if ((next >= 'a' && next <= 'z') || (next >= 'A' && next <= 'Z')) {
            return pos >= 2 && s[pos - 1] == '/' && s[pos - 2] == '/';
        }
        return FALSE;
    }

    switch (next) {
    case ':': case '/': case '?': case '#': case '\'': case '"':
    case '&': case ' ': case '\t': case '>': case ',':
        return TRUE;
    default:
        return FALSE;
    }
}

static int contains_ci(const char* hay, size_t hlen, const char* needle)
{
    size_t nlen = strlen(needle);
    size_t i;

    if (nlen == 0 || hlen < nlen) {
        return FALSE;
    }
    for (i = 0; i + nlen <= hlen; ++i) {
        size_t j;
        int match = 1;
        for (j = 0; j < nlen; ++j) {
            if (lower(hay[i + j]) != lower(needle[j])) {
                match = 0;
                break;
            }
        }
        if (match) {
            return TRUE;
        }
    }
    return FALSE;
}

static int contains_url_shaped(const char* hay, size_t hlen, const char* needle)
{
    size_t nlen = strlen(needle);
    size_t i;

    if (nlen == 0 || hlen < nlen) {
        return FALSE;
    }
    for (i = 0; i + nlen <= hlen; ++i) {
        size_t j;
        int match = 1;
        for (j = 0; j < nlen; ++j) {
            if (lower(hay[i + j]) != lower(needle[j])) {
                match = 0;
                break;
            }
        }
        if (match && boundary_ok(hay, hlen, i, nlen, needle)) {
            return TRUE;
        }
    }
    return FALSE;
}

int libinjection_ssrf(const char* s, size_t len)
{
    size_t i;

    if (numeric_ip_after_scheme(s, len)) {
        return TRUE;
    }
    if (illegal_ipv4_after_scheme(s, len)) {
        return TRUE;
    }
    if (contains_ci(s, len, "[::ffff:") ||
        contains_ci(s, len, "[fd00:") ||
        contains_ci(s, len, "[fe80:") ||
        contains_ci(s, len, "ipv6-[::1]")) {
        return TRUE;
    }

    for (i = 0; ALWAYS[i] != NULL; ++i) {
        if (contains_ci(s, len, ALWAYS[i])) {
            return TRUE;
        }
    }

    for (i = 0; LOCAL_TARGETS[i] != NULL; ++i) {
        if (contains_url_shaped(s, len, LOCAL_TARGETS[i])) {
            return TRUE;
        }
    }

    return FALSE;
}
