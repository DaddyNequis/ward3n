/**
 * crypto_backend.h — abstract crypto interface
 *
 * The software implementation (crypto_backend_soft.c, mbedTLS) can be
 * replaced by a secure-element backend (e.g., SE050, ATECC608) that
 * implements the same function signatures.
 *
 * All keys are referenced by PIV key reference (e.g., KEY_REF_9A = 0x9A).
 * The backend owns key storage; callers only pass key references.
 */

#ifndef WARD3N_CRYPTO_BACKEND_H
#define WARD3N_CRYPTO_BACKEND_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/* PIV key references */
#define KEY_REF_9A  0x9Au   /* PIV Authentication            */
#define KEY_REF_9C  0x9Cu   /* Digital Signature             */
#define KEY_REF_9D  0x9Du   /* Key Management                */
#define KEY_REF_9E  0x9Eu   /* Card Authentication           */

/* PIV algorithm identifiers (NIST SP 800-73-4 Table 5) */
#define ALG_ECDSA_P256  0x11u

/* ── Lifecycle ──────────────────────────────────────────────────────────────── */

/**
 * Initialise the crypto backend.
 * Loads key material from flash if present; generates and persists new material
 * if flash is blank (first boot).
 * Returns 0 on success, negative on error.
 */
int crypto_backend_init(void);

/* ── Key / certificate accessors ────────────────────────────────────────────── */

/**
 * Copy the DER-encoded X.509 certificate for the given key reference into buf.
 * Returns the number of bytes written, or 0 if the key reference is unknown.
 */
size_t crypto_get_cert_der(uint8_t key_ref, uint8_t *buf, size_t buf_len);

/**
 * Copy the uncompressed public key (04 || X || Y, 65 bytes) for the given
 * key reference into buf.
 * Returns the number of bytes written, or 0 on error.
 */
size_t crypto_get_pubkey(uint8_t key_ref, uint8_t *buf, size_t buf_len);

/* ── Signing ─────────────────────────────────────────────────────────────────── */

/**
 * Sign hash[0..hash_len-1] with key_ref using ECDSA.
 * The output is a DER-encoded SEQUENCE { INTEGER r, INTEGER s }.
 * sig_out must be at least 72 bytes (max DER-encoded P-256 sig).
 * Returns the number of bytes written to sig_out, or 0 on error.
 *
 * For PIV GENERAL AUTHENTICATE: hash_len = 32 (SHA-256 digest passed by host).
 */
size_t crypto_sign(uint8_t key_ref, uint8_t alg,
                   const uint8_t *hash, size_t hash_len,
                   uint8_t *sig_out, size_t sig_out_len);

/* ── Entropy helper (used by mbedTLS entropy source, not by callers) ─────────── */
int crypto_hardware_entropy(void *data, unsigned char *output, size_t len,
                            size_t *olen);

#endif /* WARD3N_CRYPTO_BACKEND_H */
