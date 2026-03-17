/**
 * apdu.h — ISO 7816-4 APDU types and helpers
 */

#ifndef WARD3N_APDU_H
#define WARD3N_APDU_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/* ── Status words ───────────────────────────────────────────────────────────── */
#define SW_OK                   0x9000u
#define SW_MORE_DATA(n)         (0x6100u | ((n) & 0xFFu))  /* 61 xx */
#define SW_WRONG_LENGTH         0x6700u
#define SW_SECURITY_NOT_SATISFIED 0x6982u
#define SW_AUTH_BLOCKED         0x6983u
#define SW_DATA_INVALID         0x6984u
#define SW_CONDITIONS_NOT_SATISFIED 0x6985u
#define SW_INCORRECT_P1P2       0x6A86u
#define SW_REFERENCED_DATA_NOT_FOUND 0x6A88u
#define SW_WRONG_P1P2           0x6B00u
#define SW_INS_NOT_SUPPORTED    0x6D00u
#define SW_CLA_NOT_SUPPORTED    0x6E00u
#define SW_UNKNOWN              0x6F00u
#define SW_FILE_NOT_FOUND       0x6A82u
#define SW_RECORD_NOT_FOUND     0x6A83u
#define SW_WRONG_DATA           0x6A80u

/* ── APDU command ───────────────────────────────────────────────────────────── */
typedef struct {
    uint8_t         cla;
    uint8_t         ins;
    uint8_t         p1;
    uint8_t         p2;
    uint16_t        lc;          /* 0 if absent                                */
    const uint8_t  *data;        /* points into original buffer                */
    uint16_t        le;          /* 0 = absent, 256 = Le byte was 0x00         */
    bool            has_lc;
    bool            has_le;
} apdu_cmd_t;

/* ── APDU response builder ──────────────────────────────────────────────────── */
typedef struct {
    uint8_t  *buf;       /* caller-supplied output buffer                      */
    size_t    capacity;  /* total buffer size                                  */
    size_t    len;       /* bytes written so far (excluding SW)                */
    uint16_t  sw;        /* status word (written last by apdu_resp_finalize)   */
} apdu_resp_t;

/* ── Parse ──────────────────────────────────────────────────────────────────── */

/**
 * Parse raw bytes into apdu_cmd_t.
 * raw_len must be >= 4 (CLA INS P1 P2).
 * Returns true on success.
 */
bool apdu_parse(const uint8_t *raw, size_t raw_len, apdu_cmd_t *out);

/* ── Response helpers ───────────────────────────────────────────────────────── */

void apdu_resp_init(apdu_resp_t *r, uint8_t *buf, size_t capacity);

/**
 * Append data bytes to response body.
 * Returns false if buf would overflow.
 */
bool apdu_resp_append(apdu_resp_t *r, const uint8_t *data, size_t len);

/**
 * Append a single byte.
 */
bool apdu_resp_push(apdu_resp_t *r, uint8_t byte);

/**
 * Write SW1 SW2 at the end of the buffer and return total length.
 * r->buf[r->len] = SW1, r->buf[r->len+1] = SW2.
 * Returns total byte count (body + 2 SW bytes).
 */
size_t apdu_resp_finalize(apdu_resp_t *r, uint16_t sw);

#endif /* WARD3N_APDU_H */
