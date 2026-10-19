/**
 * Copyright 2012-2026 Nick Galbreath / libinjection contributors
 * nickg@client9.com
 * BSD License -- see `COPYING.txt` for details
 *
 * Server-side template injection detection (OWASP A03).
 */

#ifndef LIBINJECTION_SSTI_H
#define LIBINJECTION_SSTI_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>

/*
 * Returns 1 when the input looks like a server-side template
 * injection probe, 0 otherwise.
 */
int libinjection_ssti(const char* s, size_t len);

#ifdef __cplusplus
}
#endif
#endif /* LIBINJECTION_SSTI_H */
