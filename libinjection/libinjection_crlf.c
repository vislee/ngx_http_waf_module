/**
 * Copyright 2012-2026 Nick Galbreath / libinjection contributors
 * nickg@client9.com
 * BSD License -- see `COPYING.txt` for details
 */

#include <string.h>

#include "libinjection_crlf.h"

#ifndef TRUE
#define TRUE 1
#endif
#ifndef FALSE
#define FALSE 0
#endif

/* CR-LF pairs: literal or URL-encoded (case-insensitive on the hex) */
static const char* CRLF_PAIRS[] = {
    "\r\n"
    , "\n\r"                  /* decoded %0a%0d */
    , "%0d%0a"
    , "%0a%0d"
    , "%0d%0d%0a"
    , NULL
};

/* HTTP header syntax that must follow the pair to be an attack */
static const char* HEADER_MARKERS[] = {
    "http/1"
    , "location:"
    , "set-cookie:"
    , "content-length"
    , "content-type"
    , "content-disposition"
    , "transfer-encoding"
    , "x-forwarded"
    , "refresh:"
    , NULL
};

static char lower(char c)
{
    if (c >= 'A' && c <= 'Z') {
        return (char) (c + 0x20);
    }
    return c;
}

/*
 * find a CR-LF pair, return the index just past it, or 0
 */
static size_t find_crlf(const char* s, size_t len)
{
    size_t n;
    size_t i;
    size_t j;

    for (n = 0; CRLF_PAIRS[n] != NULL; ++n) {
        size_t nlen = strlen(CRLF_PAIRS[n]);
        if (len < nlen) {
            continue;
        }
        for (i = 0; i + nlen <= len; ++i) {
            int match = 1;
            for (j = 0; j < nlen; ++j) {
                if (lower(s[i + j]) != lower(CRLF_PAIRS[n][j])) {
                    match = 0;
                    break;
                }
            }
            if (match) {
                return i + nlen;
            }
        }
    }
    return 0;
}

int libinjection_crlf(const char* s, size_t len)
{
    size_t after;
    size_t window;
    size_t i;
    size_t n;

    /*
     * LF-only servers: a bare newline directly before HTTP/1.x
     * (checked first: these inputs have no CR at all)
     */
    for (i = 0; i + 7 <= len; ++i) {
        if (s[i] == '\n' && lower(s[i + 1]) == 'h' && lower(s[i + 2]) == 't' &&
            lower(s[i + 3]) == 't' && lower(s[i + 4]) == 'p' &&
            s[i + 5] == '/') {
            return TRUE;
        }
    }

    after = find_crlf(s, len);
    if (after == 0) {
        return FALSE;
    }

    /*
     * header forgery: a known header marker must start within a short
     * window after the injected CRLF
     */
    window = after + 48;
    if (window > len) {
        window = len;
    }
    for (n = 0; HEADER_MARKERS[n] != NULL; ++n) {
        size_t nlen = strlen(HEADER_MARKERS[n]);
        for (i = after; i + nlen <= window; ++i) {
            size_t j;
            int match = 1;
            for (j = 0; j < nlen; ++j) {
                if (lower(s[i + j]) != lower(HEADER_MARKERS[n][j])) {
                    match = 0;
                    break;
                }
            }
            if (match) {
                return TRUE;
            }
        }
    }

    return FALSE;
}
