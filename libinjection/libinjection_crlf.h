/**
 * Copyright 2012-2026 Nick Galbreath / libinjection contributors
 * nickg@client9.com
 * BSD License -- see `COPYING.txt` for details
 *
 * CRLF / HTTP response-splitting detection (the input-visible part of
 * OWASP A05): an encoded or literal CR-LF pair followed by HTTP
 * header syntax.
 */

#ifndef LIBINJECTION_CRLF_H
#define LIBINJECTION_CRLF_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>

/*
 * Returns 1 when the input contains a CRLF injection that forges an
 * HTTP header, 0 otherwise.
 */
int libinjection_crlf(const char* s, size_t len);

#ifdef __cplusplus
}
#endif
#endif /* LIBINJECTION_CRLF_H */
