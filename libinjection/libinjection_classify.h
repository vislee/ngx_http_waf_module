/**
 * Copyright 2012-2026 Nick Galbreath / libinjection contributors
 * nickg@client9.com
 * BSD License -- see `COPYING.txt` for details
 *
 * Multi-class detection API: one entry point that runs the wanted
 * detectors over an input and returns a bitmask of the attack classes
 * found.
 *
 * Expansion roadmap (docs/OWASP_EXPANSION_PLAN.md): bits for OS
 * command injection, path traversal, SSRF, SSTI, NoSQL, LDAP/XPath,
 * deserialization and CRLF injection are reserved and are added as
 * those modules land (P1-P3).
 */

#ifndef LIBINJECTION_CLASSIFY_H
#define LIBINJECTION_CLASSIFY_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>

/*
 * C90-friendly 64-bit mask type (-ansi builds have no stdint.h)
 */
#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 199901L
#include <stdint.h>
typedef uint64_t libinjection_class_mask_t;
#else
__extension__ typedef unsigned long long libinjection_class_mask_t;
#endif

enum libinjection_attack_class {
    LIBINJECTION_CLASS_SQLI  = (((libinjection_class_mask_t) 1) << 0)
    , LIBINJECTION_CLASS_XSS   = (((libinjection_class_mask_t) 1) << 1)
    , LIBINJECTION_CLASS_TRAV  = (((libinjection_class_mask_t) 1) << 3)
    , LIBINJECTION_CLASS_SSRF  = (((libinjection_class_mask_t) 1) << 4)
    , LIBINJECTION_CLASS_DESER = (((libinjection_class_mask_t) 1) << 8)
    , LIBINJECTION_CLASS_CRLF  = (((libinjection_class_mask_t) 1) << 9)
    , LIBINJECTION_CLASS_CMD   = (((libinjection_class_mask_t) 1) << 2)
    , LIBINJECTION_CLASS_SSTI  = (((libinjection_class_mask_t) 1) << 5)
    , LIBINJECTION_CLASS_NOSQL = (((libinjection_class_mask_t) 1) << 6)
    , LIBINJECTION_CLASS_LDAP  = (((libinjection_class_mask_t) 1) << 7)
    , LIBINJECTION_CLASS_CODE  = (((libinjection_class_mask_t) 1) << 10)
    , LIBINJECTION_CLASS_RECON = (((libinjection_class_mask_t) 1) << 11)
    , LIBINJECTION_CLASS_REDIRECT = (((libinjection_class_mask_t) 1) << 12)
};

#define LIBINJECTION_CLASS_ALL \
    (LIBINJECTION_CLASS_SQLI | LIBINJECTION_CLASS_XSS | \
     LIBINJECTION_CLASS_TRAV | LIBINJECTION_CLASS_SSRF | \
     LIBINJECTION_CLASS_DESER | LIBINJECTION_CLASS_CRLF | \
     LIBINJECTION_CLASS_CMD | LIBINJECTION_CLASS_SSTI | \
     LIBINJECTION_CLASS_NOSQL | LIBINJECTION_CLASS_LDAP | \
     LIBINJECTION_CLASS_CODE | LIBINJECTION_CLASS_RECON | \
     LIBINJECTION_CLASS_REDIRECT)

/*
 * Runs the wanted detectors on the input as-is.
 *
 * \param s input, may contain nulls, does not need to be null-terminated
 * \param slen input length
 * \param want_mask bitmask of classes to run; unknown bits are ignored
 * \return bitmask of the attack classes detected
 */
libinjection_class_mask_t libinjection_classify(
    const char* s, size_t slen, libinjection_class_mask_t want_mask);

/*
 * Same as libinjection_classify(), but each detector also runs on up
 * to three rounds of URL decoding (see libinjection_sqli_url), so
 * encoded payloads are attributed to their class.  Detection stops
 * per class as soon as it matches.
 */
libinjection_class_mask_t libinjection_classify_url(
    const char* s, size_t slen, libinjection_class_mask_t want_mask);

#ifdef __cplusplus
}
#endif
#endif /* LIBINJECTION_CLASSIFY_H */
