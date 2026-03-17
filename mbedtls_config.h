/**
 * mbedtls_config.h — minimal mbedTLS config for ward3n
 *
 * Enables only what we need:
 *   • ECDSA-P256 signing (for PIV GENERAL AUTHENTICATE)
 *   • SHA-256 (hash before signing)
 *   • X.509 certificate writing (self-signed cert generated at first boot)
 *   • DER/ASN.1 encoding helpers
 *   • CTR-DRBG seeded from RP2040 hardware RNG (via rosc_get_rand_byte)
 */

#ifndef MBEDTLS_CONFIG_H
#define MBEDTLS_CONFIG_H

/* ── Platform ──────────────────────────────────────────────────────────────── */
#define MBEDTLS_PLATFORM_C
/* Use standard malloc/free (provided by Pico SDK newlib, heap via PICO_HEAP_SIZE).
 * Do NOT define MBEDTLS_PLATFORM_MEMORY unless you provide mbedtls_platform_set_malloc_free(). */
#define MBEDTLS_NO_PLATFORM_ENTROPY /* we supply our own entropy source  */

/* ── Math ───────────────────────────────────────────────────────────────────── */
#define MBEDTLS_BIGNUM_C

/* ── Message digest ─────────────────────────────────────────────────────────── */
#define MBEDTLS_MD_C
#define MBEDTLS_SHA256_C
/* SHA-1 is required by mbedtls_x509write_crt_set_subject_key_identifier()
 * and mbedtls_x509write_crt_set_authority_key_identifier() — both guarded
 * by MBEDTLS_MD_CAN_SHA1 in mbedtls 3.x.                                  */
#define MBEDTLS_SHA1_C

/* ── Symmetric cipher (needed by CTR-DRBG) ──────────────────────────────────── */
#define MBEDTLS_AES_C
#define MBEDTLS_CIPHER_C
#define MBEDTLS_CTR_DRBG_C
#define MBEDTLS_ENTROPY_C
#define MBEDTLS_ENTROPY_HARDWARE_ALT /* we implement mbedtls_hardware_poll */

/* ── ECC ────────────────────────────────────────────────────────────────────── */
#define MBEDTLS_ECP_C
#define MBEDTLS_ECP_DP_SECP256R1_ENABLED
#define MBEDTLS_ECDSA_C
#define MBEDTLS_ECDSA_DETERMINISTIC  /* RFC 6979 — no extra entropy at sign time */
#define MBEDTLS_HMAC_DRBG_C          /* needed by deterministic ECDSA */

/* ── Public key abstraction ─────────────────────────────────────────────────── */
#define MBEDTLS_PK_C
#define MBEDTLS_PK_WRITE_C           /* key → DER/PEM export */
#define MBEDTLS_PK_PARSE_C           /* required by X509_USE_C and X509_CREATE_C */

/* ── ASN.1 / OID ────────────────────────────────────────────────────────────── */
#define MBEDTLS_ASN1_PARSE_C
#define MBEDTLS_ASN1_WRITE_C
#define MBEDTLS_OID_C

/* ── X.509 certificate WRITE (self-signed cert generation at first boot) ────── */
#define MBEDTLS_X509_CREATE_C
#define MBEDTLS_X509_CRT_WRITE_C
#define MBEDTLS_X509_CRT_PARSE_C    /* for validation / re-read from flash */
#define MBEDTLS_X509_USE_C

/* ── Performance tweaks for RP2040 ─────────────────────────────────────────── */
#define MBEDTLS_ECP_NIST_OPTIM      /* faster NIST curve arithmetic */
/* MBEDTLS_MPI_MAX_SIZE: leave at default (1024 bytes).
 * Setting it to 32 would break X.509 certificate writing which internally
 * uses larger MPIs. Only set this if you strip out X.509 support.
 * Pending validation: tune after profiling RAM usage. */

/* Do NOT manually include mbedtls/check_config.h here.
 * In mbedTLS 3.x it is automatically included AFTER config_adjust_*.h
 * has run. Manually including it causes false "not all prerequisites"
 * errors because the _CAN_* / _HAVE_* computed symbols haven't been
 * defined yet.                                                            */

#endif /* MBEDTLS_CONFIG_H */
