/**
 * piv.c — PIV applet (NIST SP 800-73-4)
 *
 * Supported APDUs:
 *   00 A4 04 00  SELECT (PIV AID)
 *   00 CB 3F FF  GET DATA (CCC, CHUID, certificate 9A)
 *   00 20 00 80  VERIFY (application PIN)
 *   00 87 11 9A  GENERAL AUTHENTICATE (ECDSA-P256, key 9A)
 *   00 C0 00 00  GET RESPONSE (ISO 7816 chaining for large responses)
 *
 * State across calls:
 *   • PIN verified flag (reset on IccPowerOff via piv_init())
 *   • GET RESPONSE buffer for large data objects
 */

#include "piv.h"
#include "apdu.h"
#include "crypto_backend.h"
#include "device_state.h"
#include "config.h"

#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/* ══════════════════════════════════════════════════════════════════════════════
 * Static card data objects
 * ══════════════════════════════════════════════════════════════════════════════ */

/*
 * Card Capability Container (CCC) — NIST SP 800-73-4 Appendix A
 * Minimum CCC that satisfies macOS CCID driver.
 *
 * Structure (BER-TLV, wrapped in tag 53):
 *   53 [len]
 *     F0 15  Card Identifier (21 bytes):
 *              A0 00 00 01 16  GSC-IS RID
 *              FF              Manufacturer ID placeholder
 *              02              Card type: javaCard
 *              [13 bytes]      Card ID serial number (zeros for test)
 *     F1 01  Capability Container version number: 0x21 (PIV-II)
 *     F2 01  Capability Grammar version number:   0x21
 *     F3 00  Application Card URL (empty)
 *     F4 01  PKCS#15 flag: 0x00 (not present)
 *     F5 01  Registered Data Model number: 0x10
 *     F6 00  Access Control Rule Table (empty)
 *     F7 00  Card APDUs (empty)
 *     FA 00  Redirection Tag (empty)
 *     FB 00  Capability Tuples (empty)
 *     FC 00  Status Tuples (empty)
 *     FD 00  Next CCC (empty)
 *     FE 00  Error Detection Code
 */
static const uint8_t _ccc_data[] = {
    0x53, 0x33,
      0xF0, 0x15,
        0xA0, 0x00, 0x00, 0x01, 0x16,  /* GSC-IS RID                         */
        0xFF,                            /* manufacturer ID (0xFF = test)      */
        0x02,                            /* card type: JavaCard                */
        0x00, 0x00, 0x00, 0x00, 0x00,  /* card ID serial (14 bytes zeros)     */
        0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
      0xF1, 0x01, 0x21,                 /* CCC version: PIV-II                */
      0xF2, 0x01, 0x21,                 /* Grammar version: PIV-II            */
      0xF3, 0x00,                       /* App Card URL: empty                */
      0xF4, 0x01, 0x00,                 /* PKCS#15: not present               */
      0xF5, 0x01, 0x10,                 /* Registered Data Model              */
      0xF6, 0x00,                       /* ACR table: empty                   */
      0xF7, 0x00,                       /* Card APDUs: empty                  */
      0xFA, 0x00,                       /* Redirection: empty                 */
      0xFB, 0x00,                       /* Capability Tuples: empty           */
      0xFC, 0x00,                       /* Status Tuples: empty               */
      0xFD, 0x00,                       /* Next CCC: empty                    */
      0xFE, 0x00,                       /* Error Detection Code               */
};

/*
 * CHUID (Card Holder Unique Identifier) — NIST SP 800-73-4 Appendix A
 * Wrapped in tag 53.
 *
 *   FASC-N (tag 30, 25 bytes): all zeros (test card, no real FASC-N)
 *   GUID   (tag 34, 16 bytes): fixed test UUID
 *   Expiration Date (tag 35, 8 bytes): "20991231"
 *   Asymmetric Signature (tag 3E, 0 bytes): empty (unsigned, self-signed test)
 *   Error Detection Code (tag FE, 0 bytes)
 *
 * NOTE: macOS requires the GUID to pair a card to a user account.
 * This GUID must remain stable across power cycles (it is hardcoded here).
 */
static const uint8_t _chuid_data[] = {
    0x53, 0x3B,
      /* FASC-N: 25 bytes of zeros */
      0x30, 0x19,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,
      /* GUID: 16 bytes — change this to a real UUID v4 for your card */
      0x34, 0x10,
        0x57,0x41,0x52,0x44,0x33,0x4E,0x00,0x01,
        0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,0x00,0x01,
      /* Expiration Date: "20991231" */
      0x35, 0x08,
        0x32,0x30,0x39,0x39,0x31,0x32,0x33,0x31,
      /* Asymmetric Signature: empty */
      0x3E, 0x00,
      /* Error Detection Code */
      0xFE, 0x00,
};

/* ══════════════════════════════════════════════════════════════════════════════
 * PIV application state
 * ══════════════════════════════════════════════════════════════════════════════ */

static struct {
    bool selected;          /* PIV AID has been successfully selected          */
    bool pin_verified;      /* PIN verified since last reset                   */

    /* GET RESPONSE buffer: holds leftover data when SW1=61 chaining is used   */
    uint8_t  chain_buf[4096];
    size_t   chain_len;     /* total bytes in chain_buf                        */
    size_t   chain_offset;  /* bytes already sent                              */
} _piv;

/* ══════════════════════════════════════════════════════════════════════════════
 * BER-TLV helpers
 * ══════════════════════════════════════════════════════════════════════════════ */

/* Write BER-TLV length encoding (1 or 3 bytes) into *out; return bytes used. */
static size_t _ber_len_write(uint8_t *out, size_t len)
{
    if (len < 0x80) {
        out[0] = (uint8_t)len;
        return 1;
    } else if (len <= 0xFF) {
        out[0] = 0x81;
        out[1] = (uint8_t)len;
        return 2;
    } else {
        out[0] = 0x82;
        out[1] = (uint8_t)(len >> 8);
        out[2] = (uint8_t)(len & 0xFF);
        return 3;
    }
}

/* ══════════════════════════════════════════════════════════════════════════════
 * APDU handlers
 * ══════════════════════════════════════════════════════════════════════════════ */

/* ── SELECT ─────────────────────────────────────────────────────────────────── */
static size_t _handle_select(const apdu_cmd_t *cmd,
                              uint8_t *out, size_t out_cap)
{
    apdu_resp_t r;
    apdu_resp_init(&r, out, out_cap);

    /* P1=04 means select by AID */
    if (cmd->p1 != 0x04) {
        return apdu_resp_finalize(&r, SW_INCORRECT_P1P2);
    }
    if (!cmd->has_lc || cmd->lc < PIV_AID_LEN) {
        return apdu_resp_finalize(&r, SW_WRONG_DATA);
    }
    if (memcmp(cmd->data, PIV_AID, PIV_AID_LEN) != 0) {
        return apdu_resp_finalize(&r, SW_FILE_NOT_FOUND);
    }

    _piv.selected = true;

    /*
     * Return minimal FCI (File Control Information):
     *   61 [len]
     *     4F [aidlen] [AID]     Application identifier
     *     79 07                 Coexistent tag allocation authority
     *       4F 05 A0000003480000  (PIV NIST OID)
     *
     * Many hosts are fine with a bare 9000, but macOS CCID driver
     * checks for a well-formed FCI. We return a minimal one.
     */
    static const uint8_t fci[] = {
        0x61, 0x11,
          0x4F, 0x0B,  /* AID length = 11 */
            0xA0,0x00,0x00,0x03,0x08,0x00,0x00,0x10,0x00,0x01,0x00,
          0x79, 0x02,
            0x4F, 0x00,
    };
    apdu_resp_append(&r, fci, sizeof(fci));
    return apdu_resp_finalize(&r, SW_OK);
}

/* ── VERIFY (PIN) ───────────────────────────────────────────────────────────── */
static size_t _handle_verify(const apdu_cmd_t *cmd,
                              uint8_t *out, size_t out_cap)
{
    apdu_resp_t r;
    apdu_resp_init(&r, out, out_cap);

    if (cmd->p1 != 0x00) {
        return apdu_resp_finalize(&r, SW_INCORRECT_P1P2);
    }
    /* P2 = 0x80 (application PIN) */
    if (cmd->p2 != PIV_PIN_REF_APP) {
        return apdu_resp_finalize(&r, SW_REFERENCED_DATA_NOT_FOUND);
    }

    /* P1=00, no data: return retry count (we don't track attempts) */
    if (!cmd->has_lc || cmd->lc == 0) {
        /* 63 Cx: Cx = retry count remaining (we say 3) */
        return apdu_resp_finalize(&r, 0x63C3u);
    }

    if (cmd->lc != 8) {
        /* PIV PIN must be padded to 8 bytes */
        return apdu_resp_finalize(&r, SW_WRONG_LENGTH);
    }

    /* Build expected PIN buffer: PIN bytes + 0xFF padding */
    uint8_t expected[8];
    memset(expected, PIV_PIN_PAD_BYTE, sizeof(expected));
    const char *pin = PIV_DEFAULT_PIN;
    size_t pin_len  = strlen(pin);
    memcpy(expected, pin, pin_len);

    if (memcmp(cmd->data, expected, 8) != 0) {
        _piv.pin_verified = false;
        return apdu_resp_finalize(&r, SW_SECURITY_NOT_SATISFIED);
    }

    _piv.pin_verified = true;
    return apdu_resp_finalize(&r, SW_OK);
}

/* ── GET DATA ────────────────────────────────────────────────────────────────── */
static size_t _handle_get_data(const apdu_cmd_t *cmd,
                                uint8_t *out, size_t out_cap)
{
    apdu_resp_t r;
    apdu_resp_init(&r, out, out_cap);

    /* P1=3F P2=FF means "get data by tag" */
    if (cmd->p1 != 0x3F || cmd->p2 != 0xFF) {
        return apdu_resp_finalize(&r, SW_INCORRECT_P1P2);
    }
    /* Data must be: 5C [len] [tag bytes] */
    if (!cmd->has_lc || cmd->lc < 3 || cmd->data[0] != 0x5C) {
        return apdu_resp_finalize(&r, SW_WRONG_DATA);
    }
    uint8_t tag_len  = cmd->data[1];
    if (tag_len != 3 && tag_len != 1) {
        return apdu_resp_finalize(&r, SW_WRONG_DATA);
    }
    const uint8_t *tag = cmd->data + 2;

    const uint8_t *obj     = NULL;
    size_t         obj_len = 0;

    if (tag_len == 3) {
        if (memcmp(tag, PIV_TAG_CCC, 3) == 0) {
            obj     = _ccc_data;
            obj_len = sizeof(_ccc_data);
        } else if (memcmp(tag, PIV_TAG_CHUID, 3) == 0) {
            obj     = _chuid_data;
            obj_len = sizeof(_chuid_data);
        } else if (memcmp(tag, PIV_TAG_CERT_9A, 3) == 0) {
            /* Build the certificate data object on the fly:
             *   53 [len]
             *     70 [cert_len] [cert DER bytes]
             *     71 01 00      (uncompressed)
             *     FE 00         (error detection code)
             */
            static uint8_t cert_obj[4096];
            uint8_t cert_der[3994];
            size_t cert_len = crypto_get_cert_der(KEY_REF_9A,
                                                   cert_der, sizeof(cert_der));
            if (cert_len == 0) {
                return apdu_resp_finalize(&r, SW_REFERENCED_DATA_NOT_FOUND);
            }
            size_t pos = 0;
            /* tag 53 */
            cert_obj[pos++] = 0x53;
            /* inner length: 2 + cert_len (tag 70 + len) + 3 (71 01 00) + 2 (FE 00) */
            size_t inner_len = 2 + cert_len + 3 + 2;
            /* multi-byte len for inner */
            if (cert_len >= 0x80) inner_len++; /* 81 prefix */
            if (cert_len > 0xFF)  inner_len++; /* 82 prefix instead */
            pos += _ber_len_write(cert_obj + pos, inner_len);
            /* tag 70 */
            cert_obj[pos++] = 0x70;
            pos += _ber_len_write(cert_obj + pos, cert_len);
            memcpy(cert_obj + pos, cert_der, cert_len);
            pos += cert_len;
            /* tag 71 */
            cert_obj[pos++] = 0x71;
            cert_obj[pos++] = 0x01;
            cert_obj[pos++] = 0x00;   /* uncompressed */
            /* tag FE */
            cert_obj[pos++] = 0xFE;
            cert_obj[pos++] = 0x00;

            obj     = cert_obj;
            obj_len = pos;
        } else {
            return apdu_resp_finalize(&r, SW_REFERENCED_DATA_NOT_FOUND);
        }
    } else { /* tag_len == 1 */
        if (tag[0] == 0x7E) {
            /* Discovery Object — minimal stub */
            static const uint8_t disc[] = {
                0x7E, 0x12,
                  0x4F, 0x0B,
                    0xA0,0x00,0x00,0x03,0x08,0x00,0x00,0x10,0x00,0x01,0x00,
                  0x5F, 0x2F, 0x02,
                    0x40, 0x00,   /* PIN usage policy: application PIN only   */
            };
            obj     = disc;
            obj_len = sizeof(disc);
        } else {
            return apdu_resp_finalize(&r, SW_REFERENCED_DATA_NOT_FOUND);
        }
    }

    /* Determine how much to return in this response */
    uint16_t le = cmd->has_le ? cmd->le : 256;

    if (obj_len <= le) {
        apdu_resp_append(&r, obj, obj_len);
        return apdu_resp_finalize(&r, SW_OK);
    }

    /* Response exceeds Le: start ISO 7816 chaining */
    /* Copy remainder into chain buffer              */
    memcpy(_piv.chain_buf, obj, obj_len);
    _piv.chain_len    = obj_len;
    _piv.chain_offset = le;

    apdu_resp_append(&r, obj, le);

    size_t remaining = obj_len - le;
    return apdu_resp_finalize(&r, SW_MORE_DATA(remaining > 0xFF ? 0xFF : remaining));
}

/* ── GET RESPONSE ────────────────────────────────────────────────────────────── */
static size_t _handle_get_response(const apdu_cmd_t *cmd,
                                    uint8_t *out, size_t out_cap)
{
    apdu_resp_t r;
    apdu_resp_init(&r, out, out_cap);

    if (_piv.chain_offset >= _piv.chain_len) {
        return apdu_resp_finalize(&r, SW_CONDITIONS_NOT_SATISFIED);
    }

    uint16_t le = cmd->has_le ? cmd->le : 256;
    size_t   available = _piv.chain_len - _piv.chain_offset;
    size_t   send_now  = (available <= le) ? available : le;

    apdu_resp_append(&r, _piv.chain_buf + _piv.chain_offset, send_now);
    _piv.chain_offset += send_now;

    if (_piv.chain_offset >= _piv.chain_len) {
        return apdu_resp_finalize(&r, SW_OK);
    }
    size_t remaining = _piv.chain_len - _piv.chain_offset;
    return apdu_resp_finalize(&r, SW_MORE_DATA(remaining > 0xFF ? 0xFF : remaining));
}

/* ── GENERAL AUTHENTICATE ────────────────────────────────────────────────────── */
/*
 * Command data (BER-TLV):
 *   7C [len]
 *     82 00          RESPONSE: empty tag signals "sign this challenge"
 *     81 [hash_len]  CHALLENGE: the hash to sign (32 bytes for SHA-256)
 *
 * Response:
 *   7C [len]
 *     82 [sig_len]   RESPONSE: DER-encoded ECDSA signature
 *   + 9000
 */
static size_t _handle_general_authenticate(const apdu_cmd_t *cmd,
                                            uint8_t *out, size_t out_cap)
{
    apdu_resp_t r;
    apdu_resp_init(&r, out, out_cap);

    uint8_t alg     = cmd->p1;   /* 0x11 = ECDSA-P256                         */
    uint8_t key_ref = cmd->p2;   /* 0x9A = PIV Authentication                 */

    if (alg != ALG_ECDSA_P256) {
        return apdu_resp_finalize(&r, SW_INCORRECT_P1P2);
    }
    if (key_ref != KEY_REF_9A) {
        return apdu_resp_finalize(&r, SW_REFERENCED_DATA_NOT_FOUND);
    }
    if (!_piv.pin_verified) {
        return apdu_resp_finalize(&r, SW_SECURITY_NOT_SATISFIED);
    }
    if (!cmd->has_lc || cmd->lc < 4) {
        return apdu_resp_finalize(&r, SW_WRONG_LENGTH);
    }

    /* Parse Dynamic Authentication Template: 7C [len] 82 00 81 [hlen] [hash] */
    const uint8_t *p   = cmd->data;
    size_t         rem = cmd->lc;

    if (p[0] != PIV_DAT_TAG) {
        return apdu_resp_finalize(&r, SW_WRONG_DATA);
    }
    p++; rem--;
    /* Skip length byte(s) */
    if (rem == 0) return apdu_resp_finalize(&r, SW_WRONG_DATA);
    size_t dat_len;
    if (p[0] < 0x80) {
        dat_len = p[0]; p++; rem--;
    } else if (p[0] == 0x81 && rem >= 2) {
        dat_len = p[1]; p += 2; rem -= 2;
    } else {
        return apdu_resp_finalize(&r, SW_WRONG_DATA);
    }
    (void)dat_len;

    /* Expect tag 82 (RESPONSE, empty) */
    if (rem < 2 || p[0] != PIV_DAT_RESPONSE || p[1] != 0x00) {
        return apdu_resp_finalize(&r, SW_WRONG_DATA);
    }
    p += 2; rem -= 2;

    /* Expect tag 81 (CHALLENGE) */
    if (rem < 2 || p[0] != PIV_DAT_CHALLENGE) {
        return apdu_resp_finalize(&r, SW_WRONG_DATA);
    }
    p++; rem--;
    size_t hash_len = p[0];
    p++; rem--;
    if (rem < hash_len || hash_len == 0 || hash_len > 64) {
        return apdu_resp_finalize(&r, SW_WRONG_DATA);
    }
    const uint8_t *hash = p;

    /* ── User presence check ─────────────────────────────────────────────────── */
    /* Request authorization; block until button pressed or timeout.
     * In this prototype we poll dev_state synchronously for up to 30 s.
     * In a real implementation the CCID layer would return SW_CONDITIONS_NOT_SATISFIED
     * immediately and the host would retry — but macOS does not retry cleanly.
     * Instead we signal here and actually perform the sign only when authorized.
     */
    if (!dev_state_is_authorized()) {
        dev_state_request_auth();
        /* Return 0x6985 CONDITIONS_NOT_SATISFIED so the host knows to prompt */
        return apdu_resp_finalize(&r, SW_CONDITIONS_NOT_SATISFIED);
    }

    /* Consume the one-shot authorization */
    if (!dev_state_consume_auth()) {
        return apdu_resp_finalize(&r, SW_CONDITIONS_NOT_SATISFIED);
    }

    dev_state_begin_processing();

    /* ── Sign ───────────────────────────────────────────────────────────────── */
    uint8_t sig_der[72];
    size_t  sig_len = crypto_sign(key_ref, alg, hash, hash_len,
                                   sig_der, sizeof(sig_der));
    if (sig_len == 0) {
        dev_state_op_complete();
        return apdu_resp_finalize(&r, SW_UNKNOWN);
    }

    dev_state_op_complete();

    /* ── Build response: 7C [inner_len] 82 [sig_len] [sig_bytes] ──────────── */
    /* inner_len = 1 (tag 82) + 1 (length byte) + sig_len = 2 + sig_len       */
    apdu_resp_push(&r, PIV_DAT_TAG);               /* 0x7C                    */
    apdu_resp_push(&r, (uint8_t)(2 + sig_len));    /* 7C content length       */
    apdu_resp_push(&r, PIV_DAT_RESPONSE);          /* 0x82                    */
    apdu_resp_push(&r, (uint8_t)sig_len);          /* signature byte count    */
    apdu_resp_append(&r, sig_der, sig_len);

    return apdu_resp_finalize(&r, SW_OK);
}

/* ══════════════════════════════════════════════════════════════════════════════
 * Public API
 * ══════════════════════════════════════════════════════════════════════════════ */

void piv_init(void)
{
    memset(&_piv, 0, sizeof(_piv));
}

size_t piv_process_apdu(const uint8_t *apdu_in, size_t in_len,
                          uint8_t *apdu_out, size_t out_cap)
{
    apdu_cmd_t cmd;

    if (!apdu_parse(apdu_in, in_len, &cmd)) {
        /* Malformed APDU */
        apdu_out[0] = (uint8_t)(SW_UNKNOWN >> 8);
        apdu_out[1] = (uint8_t)(SW_UNKNOWN & 0xFF);
        return 2;
    }

    /* CLA must be 0x00 for all PIV commands we support */
    if (cmd.cla != 0x00) {
        apdu_out[0] = (uint8_t)(SW_CLA_NOT_SUPPORTED >> 8);
        apdu_out[1] = (uint8_t)(SW_CLA_NOT_SUPPORTED & 0xFF);
        return 2;
    }

    /* Route by INS */
    switch (cmd.ins) {
    case 0xA4:  /* SELECT */
        return _handle_select(&cmd, apdu_out, out_cap);

    case 0x20:  /* VERIFY */
        if (!_piv.selected) break;
        return _handle_verify(&cmd, apdu_out, out_cap);

    case 0xCB:  /* GET DATA */
        if (!_piv.selected) break;
        return _handle_get_data(&cmd, apdu_out, out_cap);

    case 0xC0:  /* GET RESPONSE */
        if (!_piv.selected) break;
        return _handle_get_response(&cmd, apdu_out, out_cap);

    case 0x87:  /* GENERAL AUTHENTICATE */
        if (!_piv.selected) break;
        return _handle_general_authenticate(&cmd, apdu_out, out_cap);

    default:
        break;
    }

    /* Not selected or INS not supported */
    {
        uint16_t sw_end = _piv.selected ? SW_INS_NOT_SUPPORTED
                                        : SW_CONDITIONS_NOT_SATISFIED;
        apdu_out[0] = (uint8_t)(sw_end >> 8);
        apdu_out[1] = (uint8_t)(sw_end & 0xFF);
    }
    return 2;
}
