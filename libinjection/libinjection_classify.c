/**
 * Copyright 2012-2026 Nick Galbreath / libinjection contributors
 * nickg@client9.com
 * BSD License -- see `COPYING.txt` for details
 *
 * Multi-class detection API.  P0 skeleton: SQLI and XSS.  New attack
 * classes register one entry in CLASS_TABLE (see
 * docs/OWASP_EXPANSION_PLAN.md) and get iterative decoding for free.
 */

#include <stdlib.h>
#include <string.h>

#include "libinjection.h"
#include "libinjection_sqli.h"
#include "libinjection_xss.h"
#include "libinjection_trav.h"
#include "libinjection_ssrf.h"
#include "libinjection_deser.h"
#include "libinjection_crlf.h"
#include "libinjection_cmd.h"
#include "libinjection_ssti.h"
#include "libinjection_nosql.h"
#include "libinjection_ldap.h"
#include "libinjection_code.h"
#include "libinjection_recon.h"
#include "libinjection_redirect.h"
#include "libinjection_normalize.h"
#include "libinjection_classify.h"

typedef int (*class_scan_fn)(const char* s, size_t len);

struct class_entry {
    libinjection_class_mask_t bit;
    class_scan_fn fn;
};

static int scan_sqli_simple(const char* s, size_t len)
{
    char fingerprint[32];
    return libinjection_sqli(s, len, fingerprint);
}

static const struct class_entry CLASS_TABLE[] = {
    { LIBINJECTION_CLASS_SQLI, scan_sqli_simple }
    , { LIBINJECTION_CLASS_XSS, libinjection_xss }
    , { LIBINJECTION_CLASS_TRAV, libinjection_trav }
    , { LIBINJECTION_CLASS_SSRF, libinjection_ssrf }
    , { LIBINJECTION_CLASS_DESER, libinjection_deser }
    , { LIBINJECTION_CLASS_CRLF, libinjection_crlf }
    , { LIBINJECTION_CLASS_CMD, libinjection_cmd }
    , { LIBINJECTION_CLASS_SSTI, libinjection_ssti }
    , { LIBINJECTION_CLASS_NOSQL, libinjection_nosql }
    , { LIBINJECTION_CLASS_LDAP, libinjection_ldap }
    , { LIBINJECTION_CLASS_CODE, libinjection_code }
    , { LIBINJECTION_CLASS_RECON, libinjection_recon }
    , { LIBINJECTION_CLASS_REDIRECT, libinjection_redirect }
    , { 0, NULL }
};

/*
 * Runs every wanted (and not-yet-found) class over one buffer.
 */
static libinjection_class_mask_t scan_classes(
    const char* s, size_t len,
    libinjection_class_mask_t want, libinjection_class_mask_t already)
{
    libinjection_class_mask_t found = 0;
    const struct class_entry* entry;

    for (entry = CLASS_TABLE; entry->bit != 0; ++entry) {
        if ((want & entry->bit) && ! (already & entry->bit)) {
            if (entry->fn(s, len)) {
                found |= entry->bit;
            }
        }
    }
    return found;
}

static libinjection_class_mask_t classify_impl(
    const char* s, size_t slen,
    libinjection_class_mask_t want, int decode_rounds)
{
    char* buf;
    size_t len;
    int round;
    libinjection_class_mask_t found;

    if (slen == 0) {
        return 0;
    }

    found = scan_classes(s, slen, want, 0);
    if (decode_rounds <= 0 || found == want) {
        return found;
    }

    buf = (char*) malloc(slen + 1);
    if (buf == NULL) {
        /* no room for decode stages: the raw scan result stands */
        return found;
    }
    memcpy(buf, s, slen);
    len = slen;

    for (round = 0; round < decode_rounds && found != want; ++round) {
        if (! libinjection_urldecode_has_encoded(buf, len)) {
            break;
        }
        len = libinjection_urldecode(buf, len);
        found |= scan_classes(buf, len, want, found);
    }

    free(buf);
    return found;
}

libinjection_class_mask_t libinjection_classify(
    const char* s, size_t slen, libinjection_class_mask_t want_mask)
{
    return classify_impl(s, slen, want_mask, 0);
}

libinjection_class_mask_t libinjection_classify_url(
    const char* s, size_t slen, libinjection_class_mask_t want_mask)
{
    return classify_impl(s, slen, want_mask, 3);
}
