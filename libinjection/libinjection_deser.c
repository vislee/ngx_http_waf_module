/**
 * Copyright 2012-2026 Nick Galbreath / libinjection contributors
 * nickg@client9.com
 * BSD License -- see `COPYING.txt` for details
 */

#include <string.h>

#include "libinjection_deser.h"

#ifndef TRUE
#define TRUE 1
#endif
#ifndef FALSE
#define FALSE 0
#endif

#define ISDIGIT(a) ((unsigned)((a) - '0') <= 9)

/* case-sensitive needles: base64 magic prefixes and Java class names */
static const char* CS_NEEDLES[] = {
    "rO0AB"                    /* java.io.Serializable magic, base64 */
    , "gASV"                   /* python pickle protocol 4, base64 */
    , "Runtime.getRuntime"
    , "ysoserial"
    , "org.apache.commons.collections.functors"
    , "com.sun.rowset.JdbcRowSetImpl"
    , "org.apache.naming.factory.BeanFactory"
    , "org.apache.xalan.internal.xsltc"
    , "cos\nsystem"            /* pickle global (real newlines) */
    , "__reduce__"
    , "copyreg"
    , NULL
};

/* case-insensitive needles: names and schemes */
static const char* CI_NEEDLES[] = {
    "jndi:"                    /* covers ${jndi:ldap|rmi|dns... */
    , "${"                     /* used with the jndi check below */
    , "j}ndi"                  /* ${::-j}ndi split obfuscation */
    , "n}di"                   /* ${lower:n}di split obfuscation */
    , NULL
};

static char lower(char c)
{
    if (c >= 'A' && c <= 'Z') {
        return (char) (c + 0x20);
    }
    return c;
}

static int contains_cs(const char* hay, size_t hlen, const char* needle)
{
    size_t nlen = strlen(needle);
    size_t i;

    if (nlen == 0 || hlen < nlen) {
        return FALSE;
    }
    for (i = 0; i + nlen <= hlen; ++i) {
        if (memcmp(hay + i, needle, nlen) == 0) {
            return TRUE;
        }
    }
    return FALSE;
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

/*
 * PHP serialized object header:  O:<digits>:"   e.g. O:8:"stdClass"
 */
static int has_php_object(const char* s, size_t len)
{
    size_t i = 0;
    size_t j;

    while (i + 3 < len) {
        if (s[i] == 'O' && s[i + 1] == ':' && ISDIGIT(s[i + 2])) {
            j = i + 2;
            while (j < len && ISDIGIT(s[j])) {
                j += 1;
            }
            if (j + 1 < len && s[j] == ':' && s[j + 1] == '"') {
                return TRUE;
            }
        }
        i += 1;
    }
    return FALSE;
}

int libinjection_deser(const char* s, size_t len)
{
    size_t i;
    int has_dollar_brace = FALSE;
    int has_jndi = FALSE;

    for (i = 0; CS_NEEDLES[i] != NULL; ++i) {
        if (contains_cs(s, len, CS_NEEDLES[i])) {
            return TRUE;
        }
    }

    for (i = 0; CI_NEEDLES[i] != NULL; ++i) {
        if (contains_ci(s, len, CI_NEEDLES[i])) {
            if (i == 0) {
                /* "jndi:" is specific enough on its own */
                return TRUE;
            } else if (i == 1) {
                has_dollar_brace = TRUE;
            } else if (i == 2 || i == 3) {
                return TRUE;
            }
        }
    }
    has_jndi = contains_ci(s, len, "jndi");
    if (has_dollar_brace && has_jndi) {
        /* ${${lower:j}ndi:...} style nesting */
        return TRUE;
    }

    if (has_php_object(s, len)) {
        return TRUE;
    }

    return FALSE;
}
