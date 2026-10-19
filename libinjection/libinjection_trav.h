/**
 * Copyright 2012-2026 Nick Galbreath / libinjection contributors
 * nickg@client9.com
 * BSD License -- see `COPYING.txt` for details
 *
 * Path traversal / local file inclusion / wrapper-scheme detection
 * (OWASP A01 / A03).  Detection is on the string as-is; URL-decoded
 * variants are covered by libinjection_classify_url() and callers
 * that decode before scanning.
 */

#ifndef LIBINJECTION_TRAV_H
#define LIBINJECTION_TRAV_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>

/*
 * Returns 1 when the input contains a path-traversal, sensitive-file
 * or wrapper-scheme pattern, 0 otherwise.
 */
int libinjection_trav(const char* s, size_t len);

#ifdef __cplusplus
}
#endif
#endif /* LIBINJECTION_TRAV_H */
