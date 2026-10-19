/**
 * Copyright 2012-2026 Nick Galbreath / libinjection contributors
 * nickg@client9.com
 * BSD License -- see `COPYING.txt` for details
 *
 * SSTI: a template-expression marker ({{ ${ <% #{ {%) near a
 * dangerous semantic (arithmetic probe, attribute climbing, engine
 * call).  Plain placeholders ({{name}}, ${user.id}) stay benign.
 */

#include <string.h>

#include "libinjection_ssti.h"

#ifndef TRUE
#define TRUE 1
#endif
#ifndef FALSE
#define FALSE 0
#endif

static const char* MARKERS[] = {
    "{{", "${", "<%", "#{", "{%", NULL
};

static const char* DANGER[] = {
    "__class__"
    , "__mro__"
    , "__subclasses__"
    , "__globals__"
    , "__builtins__"
    , "__import__"
    , "constructor."
    , "getclass"
    , "forname"
    , "popen("
    , "phpinfo("
    , "7*'7'"
    , "__context"
    , "settings."
    , "secret_key"
    , "constant("
    , "smarty."
    , "import os"
    , "import sys"
    , "template.utility"
    , "freemarker.template"
    , NULL
};

static char lower(char c)
{
    if (c >= 'A' && c <= 'Z') {
        return (char) (c + 0x20);
    }
    return c;
}

int libinjection_ssti(const char* s, size_t len)
{
    size_t m;
    size_t d;
    size_t i;

    for (m = 0; MARKERS[m] != NULL; ++m) {
        size_t mlen = strlen(MARKERS[m]);
        for (i = 0; i + mlen <= len; ++i) {
            size_t j;
            int match = 1;
            for (j = 0; j < mlen; ++j) {
                if (lower(s[i + j]) != MARKERS[m][j]) {
                    match = 0;
                    break;
                }
            }
            if (! match) {
                continue;
            }
            /*
             * danger must sit in the same expression: search a
             * bounded window after the marker
             */
            {
                size_t window = i + mlen + 64;
                size_t k;
                if (window > len) {
                    window = len;
                }
                /* arithmetic oracle: digit * digit or digit / digit
                 * (7*7, 42*42, 1/0 ...) */
                for (k = i + mlen + 1; k + 1 < window; ++k) {
                    if (s[k] == '*' &&
                        s[k - 1] >= '0' && s[k - 1] <= '9' &&
                        s[k + 1] >= '0' && s[k + 1] <= '9') {
                        return TRUE;
                    }
                    if (s[k] == '/' &&
                        s[k - 1] >= '0' && s[k - 1] <= '9' &&
                        s[k + 1] >= '0' && s[k + 1] <= '9') {
                        return TRUE;
                    }
                }
                for (d = 0; DANGER[d] != NULL; ++d) {
                    size_t dlen = strlen(DANGER[d]);
                    size_t k;
                    if (dlen > window - (i + mlen)) {
                        continue;
                    }
                    for (k = i + mlen; k + dlen <= window; ++k) {
                        int dmatch = 1;
                        size_t z;
                        for (z = 0; z < dlen; ++z) {
                            char a = s[k + z];
                            char b = DANGER[d][z];
                            if (b >= 'a' && b <= 'z' && a >= 'A' && a <= 'Z') {
                                a = (char) (a + 0x20);
                            }
                            if (a != b) {
                                dmatch = 0;
                                break;
                            }
                        }
                        if (dmatch) {
                            return TRUE;
                        }
                    }
                }
            }
        }
    }

    /* {{config}} / {{ config }} - the classic Jinja2 probe */
    for (i = 0; i + 4 <= len; ++i) {
        size_t j;
        size_t k;
        if (s[i] != '{' || s[i + 1] != '{') {
            continue;
        }
        j = i + 2;
        while (j < len && (s[j] == ' ' || s[j] == '\t')) {
            j += 1;
        }
        if (j + 6 > len) {
            continue;
        }
        if (lower(s[j]) == 'c' && lower(s[j + 1]) == 'o' &&
            lower(s[j + 2]) == 'n' && lower(s[j + 3]) == 'f' &&
            lower(s[j + 4]) == 'i' && lower(s[j + 5]) == 'g') {
            k = j + 6;
            while (k < len && (s[k] == ' ' || s[k] == '\t')) {
                k += 1;
            }
            if (k + 1 < len && s[k] == '}' && s[k + 1] == '}') {
                return TRUE;
            }
        }
    }

    return FALSE;
}
