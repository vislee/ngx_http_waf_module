/**
 * Copyright 2012-2026 Nick Galbreath / libinjection contributors
 * nickg@client9.com
 * BSD License -- see `COPYING.txt` for details
 *
 * Shared input-normalization layer: URL decoding (single pass and
 * iterative) and the shared "scan raw + decoded stages" driver used
 * by libinjection_sqli_url(), libinjection_xss_url() and
 * libinjection_classify().
 */

#include <stdlib.h>
#include <string.h>

#include "libinjection.h"
#include "libinjection_normalize.h"

static int hexval(char ch)
{
    if (ch >= '0' && ch <= '9') {
        return ch - '0';
    } else if (ch >= 'a' && ch <= 'f') {
        return ch - 'a' + 10;
    } else if (ch >= 'A' && ch <= 'F') {
        return ch - 'A' + 10;
    }
    return -1;
}

/*
 * One in-place pass of URL decoding.
 *
 * Decodes %XX, %uXXXX (IIS unicode escapes) and turns '+' into space,
 * which mirrors how query strings are parsed. The decoded value never
 * gets longer than the input, so decoding may be done in place.
 *
 * Returns the new length.
 */
size_t libinjection_urldecode(char* buf, size_t len)
{
    size_t readpos = 0;
    size_t writepos = 0;

    while (readpos < len) {
        char ch = buf[readpos];
        if (ch == '+') {
            buf[writepos++] = ' ';
            readpos += 1;
        } else if (ch == '%' && readpos + 2 < len &&
                   hexval(buf[readpos + 1]) >= 0 &&
                   hexval(buf[readpos + 2]) >= 0) {
            buf[writepos++] = (char) ((hexval(buf[readpos + 1]) << 4) |
                                      hexval(buf[readpos + 2]));
            readpos += 3;
        } else if (ch == '%' && readpos + 5 < len &&
                   (buf[readpos + 1] == 'u' || buf[readpos + 1] == 'U') &&
                   hexval(buf[readpos + 2]) >= 0 &&
                   hexval(buf[readpos + 3]) >= 0 &&
                   hexval(buf[readpos + 4]) >= 0 &&
                   hexval(buf[readpos + 5]) >= 0) {
            /* IIS style %uXXXX: keep the low byte, like most servers did */
            buf[writepos++] = (char) ((hexval(buf[readpos + 4]) << 4) |
                                      hexval(buf[readpos + 5]));
            readpos += 6;
        } else {
            buf[writepos++] = buf[readpos++];
        }
    }
    return writepos;
}

int libinjection_urldecode_has_encoded(const char* buf, size_t len)
{
    return memchr(buf, '%', len) != NULL ||
        memchr(buf, '+', len) != NULL;
}

int libinjection_scan_url(const char* input, size_t slen, int max_rounds,
                          libinjection_scan_fn scan, void* userdata)
{
    char* buf;
    size_t len;
    int round;
    int found;

    found = scan(input, slen, userdata);
    if (found || slen == 0 || max_rounds <= 0) {
        return found;
    }

    buf = (char*) malloc(slen + 1);
    if (buf == NULL) {
        /* no room for decode stages: the raw scan result stands */
        return found;
    }
    memcpy(buf, input, slen);
    len = slen;

    for (round = 0; round < max_rounds; ++round) {
        if (! libinjection_urldecode_has_encoded(buf, len)) {
            /* nothing left to decode: no more encoded layers */
            break;
        }
        len = libinjection_urldecode(buf, len);
        found = scan(buf, len, userdata);
        if (found) {
            break;
        }
    }

    free(buf);
    return found;
}
