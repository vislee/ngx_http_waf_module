/**
 * Copyright 2012-2026 Nick Galbreath / libinjection contributors
 * nickg@client9.com
 * BSD License -- see `COPYING.txt` for details
 *
 * Shared input-normalization layer used by the *_url() detection
 * APIs and libinjection_classify().
 */

#ifndef LIBINJECTION_NORMALIZE_H
#define LIBINJECTION_NORMALIZE_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Pull in size_t
 */
#include <string.h>

/*
 * Scan callback: return nonzero when the input matches.
 */
typedef int (*libinjection_scan_fn)(const char* s, size_t len, void* userdata);

/*
 * Runs scan() on the raw input, then on up to max_rounds in-place
 * URL-decoded versions of it (defeating double/triple encoding),
 * stopping as soon as scan() returns nonzero or decoding is a no-op.
 *
 * Returns the first nonzero scan() result, or zero.
 */
int libinjection_scan_url(const char* input, size_t slen, int max_rounds,
                          libinjection_scan_fn scan, void* userdata);

/*
 * TRUE when the buffer contains characters that libinjection_urldecode
 * would change ('%' or '+').
 */
int libinjection_urldecode_has_encoded(const char* buf, size_t len);

#ifdef __cplusplus
}
#endif
#endif /* LIBINJECTION_NORMALIZE_H */
