/**
 * Copyright 2012-2026 Nick Galbreath / libinjection contributors
 * nickg@client9.com
 * BSD License -- see `COPYING.txt` for details
 *
 * Insecure deserialization probes and JNDI/Log4Shell payloads
 * (OWASP A08, and the input-visible part of A06).
 */

#ifndef LIBINJECTION_DESER_H
#define LIBINJECTION_DESER_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>

/*
 * Returns 1 when the input contains a deserialization probe or JNDI
 * lookup payload, 0 otherwise.
 */
int libinjection_deser(const char* s, size_t len);

#ifdef __cplusplus
}
#endif
#endif /* LIBINJECTION_DESER_H */
