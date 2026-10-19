/**
 * Copyright 2012-2026 Nick Galbreath / libinjection contributors
 * nickg@client9.com
 * BSD License -- see `COPYING.txt` for details
 *
 * NoSQL injection: a MongoDB operator ($ne, $gt, $where, ...) in a
 * bracket/JSON/quote context (login[$ne]=, {"$gt":""}, {$where: ...),
 * or JavaScript boolean probes (' || '1'=='1').
 */

#include <string.h>

#include "libinjection_nosql.h"

#ifndef TRUE
#define TRUE 1
#endif
#ifndef FALSE
#define FALSE 0
#endif

static const char* OPERATORS[] = {
    "ne", "gt", "gte", "lt", "lte", "in", "nin", "regex", "where"
    , "options", "not", "mod", "type", "all", "size", "elemmatch"
    , "func", NULL
};

static char lower(char c)
{
    if (c >= 'A' && c <= 'Z') {
        return (char) (c + 0x20);
    }
    return c;
}

static int contains_ci(const char* hay, size_t hlen, const char* needle)
{
    size_t nlen = strlen(needle);
    size_t i;
    size_t j;

    if (nlen == 0 || hlen < nlen) {
        return FALSE;
    }
    for (i = 0; i + nlen <= hlen; ++i) {
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

int libinjection_nosql(const char* s, size_t len)
{
    size_t o;
    size_t i;

    for (o = 0; OPERATORS[o] != NULL; ++o) {
        size_t olen = strlen(OPERATORS[o]);
        /* "$op" plus one context char before */
        for (i = 1; i + 1 + olen <= len; ++i) {
            size_t j;
            int match;
            char prev;
            char after;

            if (s[i] != '$') {
                continue;
            }
            match = 1;
            for (j = 0; j < olen; ++j) {
                if (lower(s[i + 1 + j]) != OPERATORS[o][j]) {
                    match = 0;
                    break;
                }
            }
            if (! match) {
                continue;
            }
            prev = s[i - 1];
            if (prev != '[' && prev != '{' && prev != '"' && prev != '\'' &&
                prev != ',' && prev != '(' && prev != '=' && prev != ' ') {
                continue;
            }
            if (prev == ' ') {
                /* " $where:" / " $or: [" operator shapes; " $ne"
                 * alone stays benign */
                size_t j = i + 1 + olen;
                while (j < len && s[j] == ' ') {
                    j += 1;
                }
                if (j >= len || s[j] != ':') {
                    continue;
                }
            }
            /* word boundary after the operator */
            after = (i + 1 + olen < len) ? s[i + 1 + olen] : ']';
            switch (after) {
            case ']': case '}': case '"': case '\'': case ':': case ',':
            case '=': case ' ': case '\t': case '&': case ')':
                return TRUE;
            default:
                continue;
            }
        }
    }

    /* MongoDB blind injection: ' && this.password.match(...) */
    if (contains_ci(s, len, "&& this.") || contains_ci(s, len, "&&this.")) {
        return TRUE;
    }
    /* ';sleep(5000); and JS timing probes after quote break */
    if (contains_ci(s, len, "';sleep") || contains_ci(s, len, "';return") ||
        contains_ci(s, len, "\";sleep")) {
        return TRUE;
    }
    /* collection API probes */
    if (contains_ci(s, len, "mapreduce(") ||
        contains_ci(s, len, ".insert({")) {
        return TRUE;
    }

    /* ' || '1'=='1  (spaces around || vary) */
    if (contains_ci(s, len, "||") && contains_ci(s, len, "'=='")) {
        return TRUE;
    }

    /* JS boolean probes typical for MongoDB auth bypass */
    if (len >= 5) {
        size_t k;
        for (k = 0; k + 2 < len; ++k) {
            if (s[k] == '|' && s[k + 1] == '|' && s[k + 2] != '|') {
                size_t rest = len - (k + 2);
                static const char* PROBES[] = {
                    "1==1", " 1==1", "'1'=='1", "true", " true",
                    NULL
                };
                size_t n;
                for (n = 0; PROBES[n] != NULL; ++n) {
                    size_t plen = strlen(PROBES[n]);
                    if (plen <= rest &&
                        memcmp(s + k + 2, PROBES[n], plen) == 0) {
                        return TRUE;
                    }
                    /* case-insensitive check for 'true' */
                    if ((PROBES[n][0] == 't' || PROBES[n][0] == ' ') &&
                        plen <= rest) {
                        size_t z;
                        int match = 1;
                        for (z = 0; z < plen; ++z) {
                            if (lower(s[k + 2 + z]) != PROBES[n][z]) {
                                match = 0;
                                break;
                            }
                        }
                        if (match) {
                            return TRUE;
                        }
                    }
                }
            }
        }
    }

    /* PHP-style Mongo bypass: '; return ... ; var x=' */
    if (len >= 10) {
        size_t k;
        for (k = 0; k + 9 < len; ++k) {
            if ((s[k] == '\'' || s[k] == '"') && s[k + 1] == ';' &&
                lower(s[k + 2]) == ' ' && lower(s[k + 3]) == 'r' &&
                lower(s[k + 4]) == 'e' && lower(s[k + 5]) == 't' &&
                lower(s[k + 6]) == 'u' && lower(s[k + 7]) == 'r' &&
                lower(s[k + 8]) == 'n') {
                return TRUE;
            }
        }
    }

    return FALSE;
}
