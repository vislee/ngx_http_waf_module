/**
 * Copyright 2012-2026 Nick Galbreath / libinjection contributors
 * nickg@client9.com
 * BSD License -- see `COPYING.txt` for details
 *
 * Recon / probe detection: scanner fingerprints (sqlmap, nikto, ...),
 * sensitive-file and webshell path probes (.env, /etc/passwd,
 * wso.php, ...) and admin-panel probes (phpmyadmin, actuator, ...).
 *
 * All needles require word boundaries (neighbors are not
 * alphanumeric), so ".env" never fires inside "environment" and
 * "nmap" never fires inside "map".
 */

#ifndef LIBINJECTION_RECON_H
#define LIBINJECTION_RECON_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>

/*
 * Returns 1 when the input looks like a scanning / sensitive-file
 * / admin-panel probe, 0 otherwise.
 */
int libinjection_recon(const char* s, size_t len);

#ifdef __cplusplus
}
#endif
#endif /* LIBINJECTION_RECON_H */
