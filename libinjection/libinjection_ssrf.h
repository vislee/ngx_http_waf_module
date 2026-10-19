/**
 * Copyright 2012-2026 Nick Galbreath / libinjection contributors
 * nickg@client9.com
 * BSD License -- see `COPYING.txt` for details
 *
 * Server-Side Request Forgery detection (OWASP A10): cloud metadata
 * addresses, dangerous URL schemes, and loopback/private targets in
 * URL-shaped positions.
 */

#ifndef LIBINJECTION_SSRF_H
#define LIBINJECTION_SSRF_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>

/*
 * Returns 1 when the input looks like an SSRF probe, 0 otherwise.
 */
int libinjection_ssrf(const char* s, size_t len);

#ifdef __cplusplus
}
#endif
#endif /* LIBINJECTION_SSRF_H */
