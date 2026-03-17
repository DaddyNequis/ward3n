/**
 * piv.h — PIV applet API
 *
 * Processes ISO 7816-4 APDUs that conform to NIST SP 800-73-4.
 * Returns an APDU response buffer that the CCID layer sends back to the host.
 */

#ifndef WARD3N_PIV_H
#define WARD3N_PIV_H

#include <stdint.h>
#include <stddef.h>

/* ── Lifecycle ──────────────────────────────────────────────────────────────── */

/**
 * Initialise PIV state (call after crypto_backend_init).
 */
void piv_init(void);

/* ── Main entry point ───────────────────────────────────────────────────────── */

/**
 * Process one C-APDU and produce an R-APDU.
 *
 * apdu_in  : raw APDU bytes received from the host
 * in_len   : byte count of apdu_in
 * apdu_out : caller-supplied output buffer
 * out_cap  : capacity of apdu_out
 *
 * Returns the number of bytes written to apdu_out (body + 2 SW bytes).
 * Always returns at least 2 (the SW word).
 */
size_t piv_process_apdu(const uint8_t *apdu_in, size_t in_len,
                         uint8_t *apdu_out, size_t out_cap);

/* ── PIV data object tags (NIST SP 800-73-4 Table 3) ─────────────────────── */
#define PIV_TAG_CCC         "\x5F\xC1\x07"   /* Card Capability Container    */
#define PIV_TAG_CHUID       "\x5F\xC1\x02"   /* Card Holder Unique ID        */
#define PIV_TAG_CERT_9A     "\x5F\xC1\x05"   /* X.509 Cert, PIV Auth (9A)   */
#define PIV_TAG_CERT_9C     "\x5F\xC1\x0A"   /* X.509 Cert, Digital Sig (9C)*/
#define PIV_TAG_CERT_9D     "\x5F\xC1\x0B"   /* X.509 Cert, Key Mgmt (9D)   */
#define PIV_TAG_CERT_9E     "\x5F\xC1\x01"   /* X.509 Cert, Card Auth (9E)  */
#define PIV_TAG_DISCOVERY   "\x7E"            /* Discovery Object             */
#define PIV_TAG_KEY_HISTORY "\x5F\xC1\x0C"   /* Key History Object           */

/* PIV AID (11 bytes) */
#define PIV_AID  \
    "\xA0\x00\x00\x03\x08\x00\x00\x10\x00\x01\x00"
#define PIV_AID_LEN 11u

/* PIN reference */
#define PIV_PIN_REF_GLOBAL  0x00u
#define PIV_PIN_REF_APP     0x80u

/* Dynamic Authentication Template tags */
#define PIV_DAT_TAG         0x7Cu
#define PIV_DAT_RESPONSE    0x82u
#define PIV_DAT_CHALLENGE   0x81u

#endif /* WARD3N_PIV_H */
