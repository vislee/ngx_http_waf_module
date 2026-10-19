/**
 * Copyright 2012-2026 Nick Galbreath / libinjection contributors
 * nickg@client9.com
 * BSD License -- see `COPYING.txt` for details
 *
 * LDAP and XPath injection detection (OWASP A03).
 */

#ifndef LIBINJECTION_LDAP_H
#define LIBINJECTION_LDAP_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>

/*
 * Returns 1 when the input looks like an LDAP or XPath injection
 * probe, 0 otherwise.
 */
int libinjection_ldap(const char* s, size_t len);

#ifdef __cplusplus
}
#endif
#endif /* LIBINJECTION_LDAP_H */
