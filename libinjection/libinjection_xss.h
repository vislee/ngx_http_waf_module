#ifndef LIBINJECTION_XSS
#define LIBINJECTION_XSS

#ifdef __cplusplus
extern "C" {
#endif

/**
 * HEY THIS ISN'T DONE
 */

/* pull in size_t */

#include <string.h>

  int libinjection_is_xss(const char* s, size_t len, int flags);

/**
 * Detects XSS in a possibly URL-encoded input: tests the input as-is
 * and after up to three rounds of URL decoding.  Returns 1 if XSS
 * found, 0 if benign.
 */
int libinjection_xss_url(const char* s, size_t len);

#ifdef __cplusplus
}
#endif
#endif
