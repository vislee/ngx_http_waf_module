/**
 * Copyright 2012-2026 Nick Galbreath / libinjection contributors
 * nickg@client9.com
 * BSD License -- see `COPYING.txt` for details
 *
 * Recon / probe detection: scanner fingerprints, sensitive-file and
 * webshell path probes, admin-panel probes.  Table-driven like the
 * other context modules; keep every needle high-precision and add a
 * red-team + benign fixture when extending the tables.
 */

#include <string.h>

#include "libinjection_recon.h"

#ifndef TRUE
#define TRUE 1
#endif
#ifndef FALSE
#define FALSE 0
#endif

#define ISALNUM(a) (((unsigned)((a) - '0') <= 9) || \
    ((unsigned)(((a) | 0x20)) - 'a' <= ('z' - 'a')))

/* scanner tool fingerprints: user agents and probe markers */
static const char* SCANNER_WORDS[] = {
    "sqlmap"
    , "nikto"
    , "nessus"
    , "openvas"
    , "acunetix"
    , "netsparker"
    , "appscan"
    , "webinspect"
    , "arachni"
    , "w3af"
    , "havij"
    , "dirbuster"
    , "dirb"
    , "gobuster"
    , "wfuzz"
    , "ffuf"
    , "masscan"
    , "zgrab"
    , "whatweb"
    , "wpscan"
    , "burpsuite"
    , "burp suite"
    , "paros"
    , "qualysguard"
    , "wvs"
    , NULL
};

/* sensitive files, backups and webshell paths */
static const char* SENSITIVE_PATHS[] = {
    "/etc/passwd"
    , "/etc/shadow"
    , "/etc/hosts"
    , "/proc/self/environ"
    , "/windows/win.ini"
    , "\\windows\\win.ini"
    , "/boot.ini"
    , "\\boot.ini"
    , "web.config"
    , ".htaccess"
    , ".htpasswd"
    , ".git/config"
    , ".git/head"
    , ".svn/entries"
    , ".aws/credentials"
    , ".ds_store"
    , ".bash_history"
    , ".ssh/id_rsa"
    , "id_rsa"
    , ".env"
    , ".mysql_history"
    , "dump.sql"
    , "phpinfo.php"
    , "wso.php"
    , "c99.php"
    , "r57.php"
    , "b374k.php"
    , "phpspy.php"
    , "shell.asp"
    , "cmd.jsp"
    , "alfa.php"
    , NULL
};

/* admin panels and debug endpoints commonly probed blind */
static const char* ADMIN_PATHS[] = {
    "phpmyadmin"
    , "/actuator"
    , "/manager/html"
    , "/wp-login"
    , "/wp-setup"
    , "/adminer"
    , "/druid/index.html"
    , "/console/login"
    , "/jenkins/script"
    , "/solr/admin"
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
 * Case-insensitive needle search that only accepts matches bounded by
 * non-alphanumeric characters (or the string edges).
 */
static int contains_word(const char* s, size_t len, const char* needle)
{
    size_t nlen = strlen(needle);
    size_t i;
    size_t j;

    if (len < nlen || nlen == 0) {
        return FALSE;
    }
    for (i = 0; i + nlen <= len; ++i) {
        int match = 1;
        if (i > 0 && ISALNUM(s[i - 1])) {
            continue;
        }
        for (j = 0; j < nlen; ++j) {
            if (lower(s[i + j]) != lower(needle[j])) {
                match = 0;
                break;
            }
        }
        if (match && (i + nlen == len || ! ISALNUM(s[i + nlen]))) {
            return TRUE;
        }
    }
    return FALSE;
}

static int scan_table(const char* s, size_t len, const char* table[])
{
    int n;
    for (n = 0; table[n] != NULL; ++n) {
        if (contains_word(s, len, table[n])) {
            return TRUE;
        }
    }
    return FALSE;
}

int libinjection_recon(const char* s, size_t len)
{
    if (s == NULL || len == 0) {
        return FALSE;
    }
    if (scan_table(s, len, SCANNER_WORDS)) {
        return TRUE;
    }
    if (scan_table(s, len, SENSITIVE_PATHS)) {
        return TRUE;
    }
    if (scan_table(s, len, ADMIN_PATHS)) {
        return TRUE;
    }
    return FALSE;
}
