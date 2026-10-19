/**
 * Copyright 2012-2026 Nick Galbreath / libinjection contributors
 * nickg@client9.com
 * BSD License -- see `COPYING.txt` for details
 *
 * LDAP: the ")( " filter-boundary plus an attribute assignment or a
 * filter tree (|(  (&(  =* ).  XPath: node unions and functions that
 * only exist inside a query.
 */

#include <string.h>

#include "libinjection_ldap.h"

#ifndef TRUE
#define TRUE 1
#endif
#ifndef FALSE
#define FALSE 0
#endif

static const char* LDAP_NEEDLES[] = {
    ")(uid"
    , ")(cn"
    , ")(sn"
    , ")(mail"
    , ")(objectclass"
    , ")(givenname"
    , ")(password"
    , ")(|(uid"
    , "|(cn="
    , "|(uid="
    , "|(mail="
    , "(&(password="
    , NULL
};

static const char* XPATH_NEEDLES[] = {
    "'] | //"
    , "\"] | //"
    , "'|//"
    , "count(/*"
    , "string-length("
    , "//user["
    , "//account["
    , "//staff["
    , "//employee["
    , "//*[contains("
    , NULL
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

int libinjection_ldap(const char* s, size_t len)
{
    size_t i;

    for (i = 0; LDAP_NEEDLES[i] != NULL; ++i) {
        if (contains_ci(s, len, LDAP_NEEDLES[i])) {
            return TRUE;
        }
    }

    /* generic filter-boundary shapes:  ")(|(attr"  "*)(&"  ")(|"  */
    {
        size_t k;
        for (k = 0; k + 3 <= len; ++k) {
            if (s[k] == ')' && s[k + 1] == '(' &&
                (s[k + 2] == '|' || s[k + 2] == '&')) {
                return TRUE;
            }
            if (s[k] == '*' && s[k + 1] == '(' && s[k + 2] == '|' &&
                k + 3 < len && s[k + 3] == '(') {
                return TRUE;
            }
        }
    }

    for (i = 0; XPATH_NEEDLES[i] != NULL; ++i) {
        if (contains_ci(s, len, XPATH_NEEDLES[i])) {
            return TRUE;
        }
    }

    return FALSE;
}
