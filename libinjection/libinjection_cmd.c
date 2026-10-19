/**
 * Copyright 2012-2026 Nick Galbreath / libinjection contributors
 * nickg@client9.com
 * BSD License -- see `COPYING.txt` for details
 *
 * OS command injection: a shell metacharacter (or encoded newline)
 * directly adjacent to a known command word, or a command inside
 * $( ) / ` ` substitution.  A word after a metachar that is followed
 * by '=' (&sort=asc, &cat=5) is treated as a query-string key, not a
 * command.
 */

#include <string.h>

#include "libinjection_cmd.h"

#ifndef TRUE
#define TRUE 1
#endif
#ifndef FALSE
#define FALSE 0
#endif

#define ISALNUM(a) (((unsigned)((a) - '0') <= 9) || \
    ((unsigned)(((a) | 0x20)) - 'a' <= ('z' - 'a')))
#define ISDIGIT(a) ((unsigned)((a) - '0') <= 9)

static char lower(char c)
{
    if (c >= 'A' && c <= 'Z') {
        return (char) (c + 0x20);
    }
    return c;
}

static const char* COMMAND_WORDS[] = {
    /* posix */
    "cat", "ls", "id", "whoami", "pwd", "uname", "wget", "curl", "echo"
    , "nc", "ncat", "netcat", "bash", "sh", "zsh", "dash", "ksh"
    , "python", "python3", "perl", "ruby", "php", "ping", "sleep"
    , "chmod", "chown", "rm", "mv", "cp", "kill", "ps", "netstat"
    , "ifconfig", "arp", "find", "grep", "sed", "awk", "touch"
    , "mkdir", "dd", "mount", "useradd", "vi", "nano", "tar", "gzip"
    , "gunzip", "make", "gcc", "ssh", "scp", "telnet", "head", "tail"
    , "wc", "sort", "uniq", "cut", "xargs", "tee", "crontab"
    , "shutdown", "reboot", "poweroff", "systemctl", "service"
    , "apt", "yum", "rpm", "dpkg", "pip", "npm", "node", "java"
    /* windows */
    , "dir", "type", "del", "copy", "move", "rd", "cls", "ipconfig"
    , "net", "netsh", "tasklist", "taskkill", "reg", "wmic"
    , "powershell", "cmd", "certutil", "bitsadmin", "msiexec"
    , "attrib", "icacls", "runas", "schtasks", "psexec"
    , NULL
};

/* chars skipped when walking between a metachar and a command word */
static int is_filler(char c)
{
    switch (c) {
    case ' ': case '\t': case '\'': case '"': case '(': case ')':
    case '{': case '}': case '/': case '\\': case '@': case '*':
    case '?': case '#': case '%':
        return TRUE;
    default:
        return FALSE;
    }
}

/* common English words on the command list: they only count as
 * commands with a shell-argument shape after them ("; sleep 5",
 * "; cat /etc/passwd"), not in prose ("wait; sleep tight") */
static const char* AMBIGUOUS_WORDS[] = {
    "cat", "sleep", "head", "tail", "wc", "sort", "uniq", "cut"
    , "find", "type", "echo", "touch", "net", "make", "tar"
    , NULL
};

static int is_ambiguous_word(const char* s, size_t pos, size_t wlen)
{
    int i;
    size_t j;
    for (i = 0; AMBIGUOUS_WORDS[i] != NULL; ++i) {
        if (strlen(AMBIGUOUS_WORDS[i]) != wlen) {
            continue;
        }
        if (lower(s[pos]) != AMBIGUOUS_WORDS[i][0]) {
            continue;
        }
        for (j = 1; j < wlen; ++j) {
            if (lower(s[pos + j]) != AMBIGUOUS_WORDS[i][j]) {
                break;
            }
        }
        if (j == wlen) {
            return TRUE;
        }
    }
    return FALSE;
}

/* true when a shell-argument shape (number, flag, path, substitution)
 * starts at s[end] modulo spaces and quotes */
static int argument_follows(const char* s, size_t len, size_t end)
{
    size_t i = end;

    while (i < len && (s[i] == ' ' || s[i] == '\t' ||
                       s[i] == '\'' || s[i] == '"')) {
        i += 1;
    }
    if (i >= len) {
        return FALSE;
    }
    if (ISDIGIT(s[i])) {
        return TRUE;                      /* "; sleep 5" */
    }
    /* windows drive path: "type C:\\Windows\\..." */
    if (((s[i] | 0x20) >= 'a' && (s[i] | 0x20) <= 'z') &&
        i + 1 < len && s[i + 1] == ':') {
        return TRUE;
    }
    switch (s[i]) {
    case '-':                             /* "; sort -u" */
    case '/':                             /* "; cat /etc/passwd" */
    case '.':                             /* "; cat ./x" */
    case '~':                             /* "; cat ~/.ssh" */
    case '$':                             /* "; echo $HOME" */
    case '`':                             /* "; echo `id`" */
        return TRUE;
    default:
        return FALSE;
    }
}

static int is_meta(char c)
{
    return c == ';' || c == '|' || c == '&' || c == '`' ||
        c == '\n' || c == '\r';
}

/*
 * walking backwards from a word start: is there a metacharacter
 * before the first letter/digit?  '%0a'/'%0d' count as newline.
 */
static int meta_before(const char* s, size_t start)
{
    size_t i = start;

    while (i > 0) {
        char c = s[i - 1];
        if (is_meta(c)) {
            return TRUE;
        }
        if (i >= 3 && (c == 'a' || c == 'A') && s[i - 2] == '0' &&
            s[i - 3] == '%') {
            return TRUE;                       /* encoded \n or \r */
        }
        if (is_filler(c)) {
            i -= 1;
            continue;
        }
        if (ISALNUM(c) || c == '.' || c == '_' || c == '-') {
            /* path segment "/bin/cat": skip the whole segment and
             * require a separator behind it, else it is word glue
             * ("concat") */
            size_t j = i;
            while (j > 0 && (ISALNUM(s[j - 1]) || s[j - 1] == '.' ||
                             s[j - 1] == '_' || s[j - 1] == '-')) {
                j -= 1;
            }
            if (j > 0 && (s[j - 1] == '/' || s[j - 1] == '\\')) {
                i = j - 1;
                continue;
            }
            return FALSE;
        }
        return FALSE;                          /* letter/digit glue */
    }
    return FALSE;
}

/*
 * walking forwards from a word end: a metacharacter before the next
 * letter/digit ("cat; rm", "ls|wc")
 */
static int meta_after(const char* s, size_t len, size_t end)
{
    size_t i = end;

    while (i < len) {
        char c = s[i];
        if (is_meta(c)) {
            if (c == '&' || c == ';') {
                /* "&password=" / ";type=x": a query-string separator
                 * followed by key= is not a shell context */
                size_t j = i + 1;
                while (j < len && lower(s[j]) >= 'a' && lower(s[j]) <= 'z') {
                    j += 1;
                }
                if (j > i + 1 && j < len && s[j] == '=') {
                    i = j + 1;
                    continue;
                }
            }
            /* the metacharacter must be followed by a command word:
             * "; x" alone is prose, ";id" is not */
            {
                size_t j = i + 1;
                size_t tstart;
                size_t tlen;
                size_t k2;
                int is_word = FALSE;
                while (j < len && is_filler(s[j])) {
                    j += 1;
                }
                tstart = j;
                while (j < len && ISALNUM(s[j]) && j - tstart < 24) {
                    j += 1;
                }
                tlen = j - tstart;
                for (k2 = 0; COMMAND_WORDS[k2] != NULL; ++k2) {
                    if (strlen(COMMAND_WORDS[k2]) == tlen) {
                        size_t z;
                        int match = 1;
                        for (z = 0; z < tlen; ++z) {
                            if (lower(s[tstart + z]) !=
                                COMMAND_WORDS[k2][z]) {
                                match = 0;
                                break;
                            }
                        }
                        if (match) {
                            is_word = TRUE;
                            break;
                        }
                    }
                }
                if (is_word) {
                    return TRUE;
                }
                return FALSE;
            }
        }
        if (is_filler(c)) {
            i += 1;
            continue;
        }
        return FALSE;
    }
    return FALSE;
}

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
 * does [from, min(to, hlen)) contain a command word?
 */
static int window_has_word(const char* s, size_t hlen, size_t from, size_t to)
{
    size_t w;

    if (to > hlen) {
        to = hlen;
    }
    for (w = 0; COMMAND_WORDS[w] != NULL; ++w) {
        size_t wlen = strlen(COMMAND_WORDS[w]);
        size_t i;
        if (wlen > to - from) {
            continue;
        }
        for (i = from; i + wlen <= to; ++i) {
            size_t j;
            int match = 1;
            for (j = 0; j < wlen; ++j) {
                if (lower(s[i + j]) != COMMAND_WORDS[w][j]) {
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

int libinjection_cmd(const char* s, size_t len)
{
    size_t i;
    size_t w;
    int has_meta = FALSE;

    /* obfuscation signatures */
    if (ci_contains(s, len, "/dev/tcp") || ci_contains(s, len, "/dev/udp") ||
        ci_contains(s, len, "base64 -d") || ci_contains(s, len, "xxd -r") ||
        ci_contains(s, len, "printf \\x") ||
        ci_contains(s, len, "iex(") ||
        ci_contains(s, len, "invoke-expression") ||
        ci_contains(s, len, "downloadstring")) {
        return TRUE;
    }


    /* command substitution: $(cmd) and `cmd` (cheap enough to run
     * before the metacharacter prefilter: "$(" is rare in input) */
    for (i = 0; i + 1 < len; ++i) {
        if (s[i] == '$' && s[i + 1] == '(' &&
            window_has_word(s, len, i + 2, i + 2 + 48)) {
            return TRUE;
        }
        if (s[i] == '`' && window_has_word(s, len, i + 1, i + 1 + 48)) {
            return TRUE;
        }
    }

    /* fast path: no shell metacharacters anywhere */
    for (i = 0; i < len; ++i) {
        if (is_meta(s[i])) {
            has_meta = TRUE;
            break;
        }
    }
    if (! has_meta && ! ci_contains(s, len, "%0a") &&
        ! ci_contains(s, len, "%0d")) {
        return FALSE;
    }

    /* metacharacter directly (via fillers) next to a command word */
    for (w = 0; COMMAND_WORDS[w] != NULL; ++w) {
        size_t wlen = strlen(COMMAND_WORDS[w]);
        for (i = 0; i + wlen <= len; ++i) {
            size_t j;
            int match;
            if (lower(s[i]) != COMMAND_WORDS[w][0]) {
                continue;
            }
            match = 1;
            for (j = 0; j < wlen; ++j) {
                if (lower(s[i + j]) != COMMAND_WORDS[w][j]) {
                    match = 0;
                    break;
                }
            }
            if (! match) {
                continue;
            }
            /* word boundaries; a preceding %0a/%0d encoded newline is
             * not word glue */
            if (i > 0 && ISALNUM(s[i - 1])) {
                if (! (i >= 3 && (s[i - 1] == 'a' || s[i - 1] == 'A') &&
                       s[i - 2] == '0' && s[i - 3] == '%')) {
                    continue;
                }
            }
            if (i + wlen < len && ISALNUM(s[i + wlen])) {
                continue;
            }
            /* &sort=asc / ;type=x: query-string key, not a command */
            if (i + wlen < len && s[i + wlen] == '=') {
                continue;
            }
            /* common English words need a shell-argument shape after
             * them ("; sleep 5", "; cat /etc/passwd"), so prose like
             * "wait; sleep tight" or "red; cat videos" stays benign */
            if (is_ambiguous_word(s, i, wlen) &&
                ! argument_follows(s, len, i + wlen)) {
                continue;
            }
            if (meta_before(s, i) || meta_after(s, len, i + wlen)) {
                return TRUE;
            }
        }
    }

    return FALSE;
}
