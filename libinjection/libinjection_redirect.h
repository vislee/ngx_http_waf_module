/**
 * Copyright 2012-2026 Nick Galbreath / libinjection contributors
 * nickg@client9.com
 * BSD License -- see `COPYING.txt` for details
 *
 * Open / arbitrary redirect payloads (OWASP A01 style) at the
 * parameter-value level: script-scheme URIs, protocol-relative
 * targets and userinfo tricks in absolute URLs.
 *
 * Deliberately conservative: whether a redirect target is *allowed*
 * needs the site's domain whitelist, which only the integrator knows.
 * This detector fires on shapes that are malicious on their face;
 * everything else is the integration's policy decision.
 */

#ifndef LIBINJECTION_REDIRECT_H
#define LIBINJECTION_REDIRECT_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>

/*
 * Returns 1 when the value looks like a redirect payload
 * (javascript:/data: URI, "//evil.com", "http://good.com@evil.com"),
 * 0 otherwise.
 */
int libinjection_redirect(const char* s, size_t len);

#ifdef __cplusplus
}
#endif
#endif /* LIBINJECTION_REDIRECT_H */
