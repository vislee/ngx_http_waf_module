/**
 * Copyright 2012-2026 Nick Galbreath / libinjection contributors
 * nickg@client9.com
 * BSD License -- see `COPYING.txt` for details
 *
 * Server-side code injection probes (OWASP A03): script open tags
 * and eval-with-string-argument shapes.  <?xml stays benign.
 */

#ifndef LIBINJECTION_CODE_H
#define LIBINJECTION_CODE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>

/*
 * Returns 1 when the input looks like a code injection probe, 0
 * otherwise.
 */
int libinjection_code(const char* s, size_t len);

#ifdef __cplusplus
}
#endif
#endif /* LIBINJECTION_CODE_H */
