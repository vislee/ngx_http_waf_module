/**
 * Copyright 2012-2026 Nick Galbreath / libinjection contributors
 * nickg@client9.com
 * BSD License -- see `COPYING.txt` for details
 */

#include <string.h>

#include "libinjection_trav.h"

#ifndef TRUE
#define TRUE 1
#endif
#ifndef FALSE
#define FALSE 0
#endif

#define ISDIGIT(a) ((unsigned)((a) - '0') <= 9)
#define ISALNUM(a) (ISDIGIT(a) || \
    ((unsigned)((a) | 0x20) - 'a' <= ('z' - 'a')))

/* case-insensitive substring search, ASCII only */
static int ci_contains(const char* hay, size_t hlen, const char* needle)
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
            char a = hay[i + j];
            char b = needle[j];
            if (a >= 'A' && a <= 'Z') {
                a = (char) (a + 0x20);
            }
            if (b >= 'A' && b <= 'Z') {
                b = (char) (b + 0x20);
            }
            if (a != b) {
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

static size_t ci_count(const char* hay, size_t hlen, const char* needle)
{
    size_t nlen = strlen(needle);
    size_t count = 0;
    size_t i;
    size_t j;

    if (nlen == 0 || hlen < nlen) {
        return 0;
    }
    for (i = 0; i + nlen <= hlen; ++i) {
        int match = 1;
        for (j = 0; j < nlen; ++j) {
            char a = hay[i + j];
            char b = needle[j];
            if (a >= 'A' && a <= 'Z') {
                a = (char) (a + 0x20);
            }
            if (b >= 'A' && b <= 'Z') {
                b = (char) (b + 0x20);
            }
            if (a != b) {
                match = 0;
                break;
            }
        }
        if (match) {
            count += 1;
            i += nlen - 1;
        }
    }
    return count;
}

/* sensitive files/paths whose mere presence in a value is a probe */
static const char* SENSITIVE_PATHS[] = {
    "/etc/passwd"
    , "/etc/shadow"
    , "/etc/hosts"
    , "boot.ini"
    , "win.ini"
    , "system32/config/sam"
    , "system32\\config\\sam"
    , "/proc/self/environ"
    , "/proc/self/cmdline"
    , "id_rsa"
    , "id_dsa"
    , ".aws/credentials"
    , "authorized_keys"
    , "web.config"
    , ".bash_history"
    , NULL
};

/* stream wrappers whose presence in a value is an LFI probe */
static const char* WRAPPER_SCHEMES[] = {
    "php://"
    , "file://"
    , "zip://"
    , "phar://"
    , "expect://"
    , "data://text"
    , "glob://"
    , NULL
};

/* traversal fragments in raw or URL-encoded form */
static const char* UP_FRAGMENTS[] = {
    "../"
    , "..\\"
    , "%2e%2e%2f"
    , "%2e%2e/"
    , "..%2f"
    , "..%5c"
    , "%252e%252e"
    , "..%c0%af"
    , "..\xc0\xaf"          /* decoded UTF-8 overlong slash */
    , NULL
};

int libinjection_trav(const char* s, size_t len)
{
    size_t i;
    size_t ups = 0;

    if (len > 0) {
        /*
         * null bytes (literal or %00) terminate strings in C-based
         * stacks: a classic bypass/enumeration probe, and an editor
         * backup suffix ("page.asp~", "file.php~") is a file
         * enumeration probe.  Both are attacks in a parameter value.
         */
        if (memchr(s, 0, len) != NULL || ci_contains(s, len, "%00")) {
            return TRUE;
        }
        if (s[len - 1] == '~' && len >= 2 &&
            (ISALNUM(s[len - 2]) || s[len - 2] == '.')) {
            return TRUE;
        }
    }

    for (i = 0; UP_FRAGMENTS[i] != NULL; ++i) {
        ups += ci_count(s, len, UP_FRAGMENTS[i]);
    }
    if (ups >= 2) {
        return TRUE;
    }

    for (i = 0; SENSITIVE_PATHS[i] != NULL; ++i) {
        if (ci_contains(s, len, SENSITIVE_PATHS[i])) {
            return TRUE;
        }
    }

    for (i = 0; WRAPPER_SCHEMES[i] != NULL; ++i) {
        if (ci_contains(s, len, WRAPPER_SCHEMES[i])) {
            return TRUE;
        }
    }

    /*
     * a single traversal fragment is only interesting together with
     * a sensitive target; a lone "../" stays benign (changelogs,
     * relative doc links, ...)
     */
    return FALSE;
}
