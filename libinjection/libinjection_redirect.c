/**
 * Copyright 2012-2026 Nick Galbreath / libinjection contributors
 * nickg@client9.com
 * BSD License -- see `COPYING.txt` for details
 *
 * Open / arbitrary redirect payloads (OWASP A01 style) at the
 * parameter-value level: script-scheme URIs, protocol-relative
 * targets and userinfo tricks in absolute URLs.  Inputs may be whole
 * "key=value" pairs or query strings; each &-separated segment is
 * checked at its value position.
 *
 * Deliberately conservative: whether a redirect target is *allowed*
 * needs the site's domain whitelist, which only the integrator knows.
 * This detector fires on shapes that are malicious on their face;
 * everything else is the integration's policy decision.
 */

#include <string.h>

#include "libinjection_redirect.h"

#ifndef TRUE
#define TRUE 1
#endif
#ifndef FALSE
#define FALSE 0
#endif

static char lower(char c)
{
    if (c >= 'A' && c <= 'Z') {
        return (char) (c + 0x20);
    }
    return c;
}

/* case-insensitive prefix check on [pos, end) */
static int ci_starts_with(const char* s, size_t pos, size_t end,
                          const char* prefix)
{
    size_t n = strlen(prefix);
    size_t j;

    if (pos + n > end) {
        return FALSE;
    }
    for (j = 0; j < n; ++j) {
        if (lower(s[pos + j]) != lower(prefix[j])) {
            return FALSE;
        }
    }
    return TRUE;
}

static int is_scheme_uri(const char* s, size_t pos, size_t end)
{
    static const char* SCHEMES[] = {
        "javascript:"
        , "vbscript:"
        , "jscript:"
        , "data:text"
        , "data:application"
        , NULL
    };
    int n;

    for (n = 0; SCHEMES[n] != NULL; ++n) {
        if (ci_starts_with(s, pos, end, SCHEMES[n])) {
            return TRUE;
        }
    }
    return FALSE;
}

/* skip whitespace/quotes at the start of a value */
static size_t value_start(const char* s, size_t pos, size_t end)
{
    while (pos < end && (s[pos] == ' ' || s[pos] == '\t' ||
                         s[pos] == '\'' || s[pos] == '"')) {
        pos += 1;
    }
    return pos;
}

/* check one value span [pos, end) */
static int check_value(const char* s, size_t pos, size_t end)
{
    size_t i;

    pos = value_start(s, pos, end);
    if (pos >= end) {
        return FALSE;
    }

    /* script/data URIs */
    if (is_scheme_uri(s, pos, end)) {
        return TRUE;
    }

    /* protocol-relative "//evil.com" */
    /* protocol-relative "//evil.com": skip all leading slashes (a
     * browser normalizes "///host" like "//host"), then require a
     * dotted-host shape so "//todo" style comments stay benign */
    {
        size_t q;
        int dot = 0;
        size_t h = pos;
        while (h < end && s[h] == '/') {
            h += 1;
        }
        if (h - pos >= 2 && h < end) {
            for (q = h; q < end; ++q) {
                if (s[q] == '.') {
                    dot = 1;
                    break;
                }
                if (s[q] == '/' || s[q] == '?' || s[q] == '#' ||
                    s[q] == ' ' || s[q] == '\t') {
                    break;
                }
            }
            if (dot) {
                return TRUE;
            }
        }
    }

    /* userinfo trick: "http://login@evil.com/" — '@' must sit in the
     * authority, i.e. before the first path slash after the scheme */
    if (ci_starts_with(s, pos, end, "http://")) {
        i = pos + 7;
    } else if (ci_starts_with(s, pos, end, "https://")) {
        i = pos + 8;
    } else {
        return FALSE;
    }
    while (i < end && s[i] != '/') {
        if (s[i] == '@') {
            return TRUE;
        }
        i += 1;
    }
    return FALSE;
}

int libinjection_redirect(const char* s, size_t len)
{
    size_t seg;

    if (s == NULL || len == 0) {
        return FALSE;
    }

    /* each &-separated segment may be "key=value" or a bare value */
    seg = 0;
    while (seg <= len) {
        size_t end = seg;
        size_t eq;

        while (end < len && s[end] != '&') {
            end += 1;
        }
        /* check the whole segment as a bare value first: base64
         * padding ("data:...==") must not hide behind key=value
         * splitting */
        if (check_value(s, seg, end)) {
            return TRUE;
        }
        eq = seg;
        while (eq < end && s[eq] != '=') {
            eq += 1;
        }
        if (check_value(s, (eq < end) ? eq + 1 : seg, end)) {
            return TRUE;
        }
        if (end >= len) {
            break;
        }
        seg = end + 1;
    }
    return FALSE;
}
