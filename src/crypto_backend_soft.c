/**
 * crypto_backend_soft.c — mbedTLS 3.x software crypto backend
 *
 * Targets: mbedTLS 3.6.2 (included with Pico SDK 2.2.0)
 *
 * On first boot (flash blank):
 *   1. Seed CTR-DRBG from RP2040 hardware entropy (pico_rand / ROSC).
 *   2. Generate an ECDSA P-256 key pair.
 *   3. Derive the public key from the private key.
 *   4. Create a self-signed X.509 certificate (DER).
 *   5. Persist everything to the last flash sector.
 *
 * On subsequent boots: load from flash.
 *
 * To replace with a secure element: implement crypto_backend.h against
 * the SE driver and swap this file in CMakeLists.txt.
 */

#include "crypto_backend.h"
#include "config.h"

/* mbedTLS 3.x headers */
#include "mbedtls/platform.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/ecp.h"
#include "mbedtls/pk.h"
/* mbedTLS 3.x merged x509write_crt.h into x509_crt.h */
#include "mbedtls/x509_crt.h"
#include "mbedtls/asn1write.h"
#include "mbedtls/oid.h"
#include "mbedtls/md.h"
#include "mbedtls/error.h"

/* Pico SDK */
#include "hardware/flash.h"
#include "hardware/sync.h"
#include "pico/unique_id.h"
/* pico/rand.h not needed — hardware entropy is supplied by pico_mbedtls.c */

#include <string.h>
#include <stdbool.h>

/* ══════════════════════════════════════════════════════════════════════════════
 * In-memory state
 * ══════════════════════════════════════════════════════════════════════════════ */

static mbedtls_entropy_context  _entropy;
static mbedtls_ctr_drbg_context _ctr_drbg;
static mbedtls_pk_context       _pk_9a;

static uint8_t  _cert_9a_der[KS_MAX_CERT_LEN];
static uint16_t _cert_9a_len = 0;

static bool _initialized = false;

/* mbedtls_hardware_poll is already provided by pico_mbedtls (pico_mbedtls.c).
 * It uses the RP2040 ROSC ring oscillator for hardware entropy.
 * We must NOT redefine it here — doing so causes a duplicate symbol error.  */

/* Shim satisfying crypto_backend.h */
int crypto_hardware_entropy(void *data, unsigned char *output,
                             size_t len, size_t *olen)
{
    /* Forward to the Pico SDK's implementation */
    extern int mbedtls_hardware_poll(void *, unsigned char *, size_t, size_t *);
    return mbedtls_hardware_poll(data, output, len, olen);
}

/* ══════════════════════════════════════════════════════════════════════════════
 * Flash persistence
 * ══════════════════════════════════════════════════════════════════════════════ */

static const uint8_t *_flash_ptr(void)
{
    return (const uint8_t *)(XIP_BASE + KEY_STORAGE_OFFSET);
}

static bool _flash_is_initialized(void)
{
    const uint8_t *p = _flash_ptr();
    uint32_t magic;
    memcpy(&magic, p + KS_OFFSET_MAGIC, 4);
    return magic == KEY_STORAGE_MAGIC;
}

static void _flash_save(const uint8_t *privkey,
                         const uint8_t *pubkey_x,
                         const uint8_t *pubkey_y,
                         const uint8_t *cert_der, uint16_t cert_len)
{
    static uint8_t sector[FLASH_SECTOR_SIZE];
    memset(sector, 0xFF, sizeof(sector));

    uint32_t magic = KEY_STORAGE_MAGIC;
    memcpy(sector + KS_OFFSET_MAGIC,    &magic,    4);
    memcpy(sector + KS_OFFSET_PRIVKEY,  privkey,   32);
    memcpy(sector + KS_OFFSET_PUBKEY_X, pubkey_x,  32);
    memcpy(sector + KS_OFFSET_PUBKEY_Y, pubkey_y,  32);
    memcpy(sector + KS_OFFSET_CERT_LEN, &cert_len, 2);
    if (cert_len && cert_len <= KS_MAX_CERT_LEN) {
        memcpy(sector + KS_OFFSET_CERT_DER, cert_der, cert_len);
    }

    /* Flash erase/write must run from RAM with interrupts disabled */
    uint32_t ints = save_and_disable_interrupts();
    flash_range_erase(KEY_STORAGE_OFFSET, FLASH_SECTOR_SIZE);
    flash_range_program(KEY_STORAGE_OFFSET, sector, FLASH_SECTOR_SIZE);
    restore_interrupts(ints);
}

/* ── Load key pair from flash into mbedTLS pk context (mbedTLS 3.x API) ────── */
static int _flash_load(void)
{
    const uint8_t *p = _flash_ptr();

    uint8_t privkey[32];
    uint8_t pubkey_x[32];
    uint8_t pubkey_y[32];
    memcpy(privkey,  p + KS_OFFSET_PRIVKEY,  32);
    memcpy(pubkey_x, p + KS_OFFSET_PUBKEY_X, 32);
    memcpy(pubkey_y, p + KS_OFFSET_PUBKEY_Y, 32);
    memcpy(&_cert_9a_len, p + KS_OFFSET_CERT_LEN, 2);

    if (_cert_9a_len > KS_MAX_CERT_LEN) _cert_9a_len = 0;
    if (_cert_9a_len > 0) {
        memcpy(_cert_9a_der, p + KS_OFFSET_CERT_DER, _cert_9a_len);
    }

    /* Set up pk context */
    mbedtls_pk_free(&_pk_9a);
    mbedtls_pk_init(&_pk_9a);

    int ret = mbedtls_pk_setup(&_pk_9a,
                                mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY));
    if (ret != 0) return ret;

    mbedtls_ecp_keypair *kp = mbedtls_pk_ec(_pk_9a);

    /* mbedTLS 3.x: mbedtls_ecp_read_key handles group + private key */
    ret = mbedtls_ecp_read_key(MBEDTLS_ECP_DP_SECP256R1, kp, privkey, 32);
    if (ret != 0) return ret;

    /* Set public key: build uncompressed point 04 || X || Y */
    uint8_t point[65];
    point[0] = 0x04;
    memcpy(point + 1,  pubkey_x, 32);
    memcpy(point + 33, pubkey_y, 32);

    /* mbedTLS 3.x: use mbedtls_ecp_keypair_calc_public to set Q from d,
     * OR parse the stored public point directly.
     * We parse the stored point using group operations:                      */
    mbedtls_ecp_group grp;
    mbedtls_ecp_point Q;
    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_point_init(&Q);

    mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);
    ret = mbedtls_ecp_point_read_binary(&grp, &Q, point, 65);
    if (ret != 0) {
        mbedtls_ecp_group_free(&grp);
        mbedtls_ecp_point_free(&Q);
        return ret;
    }
    /* Copy Q into the keypair (mbedTLS 3.x still exposes Q via export API) */
    /* Simplest path: re-derive Q from d (avoids direct field access)        */
    mbedtls_ecp_group_free(&grp);
    mbedtls_ecp_point_free(&Q);

    ret = mbedtls_ecp_keypair_calc_public(kp,
                                           mbedtls_ctr_drbg_random,
                                           &_ctr_drbg);
    return ret;
}

/* ══════════════════════════════════════════════════════════════════════════════
 * Key generation + self-signed certificate (mbedTLS 3.x)
 * ══════════════════════════════════════════════════════════════════════════════ */

static int _generate_and_persist(void)
{
    int ret;

    /* Generate key pair */
    mbedtls_pk_free(&_pk_9a);
    mbedtls_pk_init(&_pk_9a);

    ret = mbedtls_pk_setup(&_pk_9a,
                            mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY));
    if (ret != 0) return ret;

    ret = mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1,
                               mbedtls_pk_ec(_pk_9a),
                               mbedtls_ctr_drbg_random, &_ctr_drbg);
    if (ret != 0) return ret;

    /* Export key components using mbedTLS 3.x API */
    mbedtls_ecp_keypair *kp = mbedtls_pk_ec(_pk_9a);

    /* Private key scalar d → 32 bytes (mbedTLS 3.x: write_key_ext) */
    uint8_t privkey[32];
    size_t  priv_olen = 0;
    ret = mbedtls_ecp_write_key_ext(kp, &priv_olen, privkey, sizeof(privkey));
    if (ret != 0) return ret;

    /* Public key point Q → uncompressed 04 || X || Y (65 bytes) */
    uint8_t pubkey_raw[65];
    size_t  pub_olen = 0;
    ret = mbedtls_ecp_write_public_key(kp, MBEDTLS_ECP_PF_UNCOMPRESSED,
                                        &pub_olen, pubkey_raw, sizeof(pubkey_raw));
    if (ret != 0 || pub_olen != 65) return ret ? ret : -1;

    uint8_t *pubkey_x = pubkey_raw + 1;   /* skip 0x04 prefix */
    uint8_t *pubkey_y = pubkey_raw + 33;

    /* ── Self-signed X.509 certificate ─────────────────────────────────────── */
    mbedtls_x509write_cert cert_ctx;
    mbedtls_mpi serial_mpi;
    mbedtls_x509write_crt_init(&cert_ctx);
    mbedtls_mpi_init(&serial_mpi);

    mbedtls_x509write_crt_set_subject_key(&cert_ctx, &_pk_9a);
    mbedtls_x509write_crt_set_issuer_key(&cert_ctx, &_pk_9a);
    mbedtls_x509write_crt_set_version(&cert_ctx, MBEDTLS_X509_CRT_VERSION_3);
    mbedtls_x509write_crt_set_md_alg(&cert_ctx, MBEDTLS_MD_SHA256);

    ret = mbedtls_x509write_crt_set_subject_name(&cert_ctx,
            "CN=ward3n PIV Key,O=ward3n,C=US");
    if (ret != 0) goto cert_cleanup;

    ret = mbedtls_x509write_crt_set_issuer_name(&cert_ctx,
            "CN=ward3n PIV Key,O=ward3n,C=US");
    if (ret != 0) goto cert_cleanup;

    /* Serial number from board UID */
    {
        pico_unique_board_id_t uid;
        pico_get_unique_board_id(&uid);
        ret = mbedtls_mpi_read_binary(&serial_mpi,
                                       uid.id, PICO_UNIQUE_BOARD_ID_SIZE_BYTES);
        if (ret != 0) goto cert_cleanup;
        ret = mbedtls_x509write_crt_set_serial(&cert_ctx, &serial_mpi);
        if (ret != 0) goto cert_cleanup;
    }

    ret = mbedtls_x509write_crt_set_validity(&cert_ctx,
            "20240101000000", "20991231235959");
    if (ret != 0) goto cert_cleanup;

    ret = mbedtls_x509write_crt_set_basic_constraints(&cert_ctx, 0, -1);
    if (ret != 0) goto cert_cleanup;

    ret = mbedtls_x509write_crt_set_subject_key_identifier(&cert_ctx);
    if (ret != 0) goto cert_cleanup;

    ret = mbedtls_x509write_crt_set_authority_key_identifier(&cert_ctx);
    if (ret != 0) goto cert_cleanup;

    ret = mbedtls_x509write_crt_set_key_usage(&cert_ctx,
            MBEDTLS_X509_KU_DIGITAL_SIGNATURE);
    if (ret != 0) goto cert_cleanup;

    /* Extended Key Usage: Client Authentication (1.3.6.1.5.5.7.3.2)
     * DER: SEQUENCE { OID 1.3.6.1.5.5.7.3.2 }                              */
    {
        static const uint8_t eku_der[] = {
            0x30, 0x0A,
              0x06, 0x08,
                0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02,
        };
        ret = mbedtls_x509write_crt_set_extension(&cert_ctx,
                MBEDTLS_OID_EXTENDED_KEY_USAGE,
                MBEDTLS_OID_SIZE(MBEDTLS_OID_EXTENDED_KEY_USAGE),
                0,
                eku_der, sizeof(eku_der));
        if (ret != 0) goto cert_cleanup;
    }

    /* Write DER — mbedTLS writes at the END of the provided buffer          */
    {
        static uint8_t tmp[4096];
        int written = mbedtls_x509write_crt_der(&cert_ctx, tmp, sizeof(tmp),
                                                  mbedtls_ctr_drbg_random,
                                                  &_ctr_drbg);
        if (written <= 0) { ret = (int)written; goto cert_cleanup; }

        _cert_9a_len = (uint16_t)written;
        /* Copy from end-of-buffer to front of _cert_9a_der */
        memcpy(_cert_9a_der, tmp + sizeof(tmp) - written, (size_t)written);
    }

    /* Persist to flash */
    _flash_save(privkey, pubkey_x, pubkey_y, _cert_9a_der, _cert_9a_len);
    ret = 0;

cert_cleanup:
    mbedtls_x509write_crt_free(&cert_ctx);
    mbedtls_mpi_free(&serial_mpi);
    return ret;
}

/* ══════════════════════════════════════════════════════════════════════════════
 * Public API
 * ══════════════════════════════════════════════════════════════════════════════ */

int crypto_backend_init(void)
{
    int ret;

    mbedtls_entropy_init(&_entropy);
    mbedtls_ctr_drbg_init(&_ctr_drbg);
    mbedtls_pk_init(&_pk_9a);

    /* Personalisation string = board UID for uniqueness across devices */
    pico_unique_board_id_t uid;
    pico_get_unique_board_id(&uid);
    ret = mbedtls_ctr_drbg_seed(&_ctr_drbg, mbedtls_entropy_func, &_entropy,
                                  uid.id, PICO_UNIQUE_BOARD_ID_SIZE_BYTES);
    if (ret != 0) return ret;

    if (_flash_is_initialized()) {
        ret = _flash_load();
    } else {
        ret = _generate_and_persist();
    }
    if (ret != 0) return ret;

    _initialized = true;
    return 0;
}

size_t crypto_get_cert_der(uint8_t key_ref, uint8_t *buf, size_t buf_len)
{
    if (!_initialized || key_ref != KEY_REF_9A) return 0;
    if (_cert_9a_len == 0 || _cert_9a_len > buf_len) return 0;
    memcpy(buf, _cert_9a_der, _cert_9a_len);
    return _cert_9a_len;
}

size_t crypto_get_pubkey(uint8_t key_ref, uint8_t *buf, size_t buf_len)
{
    if (!_initialized || key_ref != KEY_REF_9A) return 0;
    if (buf_len < 65) return 0;

    size_t olen = 0;
    int ret = mbedtls_ecp_write_public_key(mbedtls_pk_ec(_pk_9a),
                                            MBEDTLS_ECP_PF_UNCOMPRESSED,
                                            &olen, buf, buf_len);
    if (ret != 0 || olen != 65) return 0;
    return 65;
}

size_t crypto_sign(uint8_t key_ref, uint8_t alg,
                    const uint8_t *hash, size_t hash_len,
                    uint8_t *sig_out, size_t sig_out_len)
{
    if (!_initialized) return 0;
    if (key_ref != KEY_REF_9A || alg != ALG_ECDSA_P256) return 0;
    if (hash_len != 32) return 0;
    if (sig_out_len < 72) return 0;

    size_t sig_len = 0;
    /* mbedTLS 3.x: pk_sign takes (sig, sig_size, *sig_len, ...) */
    int ret = mbedtls_pk_sign(&_pk_9a,
                               MBEDTLS_MD_SHA256,
                               hash, hash_len,
                               sig_out, sig_out_len, &sig_len,
                               mbedtls_ctr_drbg_random, &_ctr_drbg);
    if (ret != 0) return 0;
    return sig_len;
}
