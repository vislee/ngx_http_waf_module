/**
 * Copyright 2012-2026 Nick Galbreath / libinjection contributors
 * nickg@client9.com
 * BSD License -- see `COPYING.txt` for details
 *
 * OS command injection detection (OWASP A03).
 */

#ifndef LIBINJECTION_CMD_H
#define LIBINJECTION_CMD_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>

/*
 * Returns 1 when the input looks like an OS command injection, 0
 * otherwise.
 */
int libinjection_cmd(const char* s, size_t len);

#ifdef __cplusplus
}
#endif
#endif /* LIBINJECTION_CMD_H */
