/**
 * apdu.c — ISO 7816-4 APDU parser and response builder
 */

#include "apdu.h"
#include <string.h>

/* ── Parse a raw APDU byte stream ───────────────────────────────────────────── */
bool apdu_parse(const uint8_t *raw, size_t raw_len, apdu_cmd_t *out)
{
    if (!raw || !out || raw_len < 4) return false;

    memset(out, 0, sizeof(*out));
    out->cla  = raw[0];
    out->ins  = raw[1];
    out->p1   = raw[2];
    out->p2   = raw[3];

    if (raw_len == 4) {
        /* Case 1: no body, no Le */
        return true;
    }

    /* ISO 7816-4 short APDU only (extended APDUs not needed for PIV subset) */
    size_t idx = 4;
    uint8_t first_byte = raw[idx];

    if (raw_len == 5) {
        /* Case 2S: Le only (no Lc) */
        out->has_le = true;
        out->le     = (first_byte == 0) ? 256 : first_byte;
        return true;
    }

    /* Lc present (Case 3S or 4S) */
    out->has_lc = true;
    out->lc     = first_byte;
    idx++;

    if (idx + out->lc > raw_len) return false;  /* truncated */
    out->data = raw + idx;
    idx += out->lc;

    if (idx < raw_len) {
        /* Le follows Lc+Data */
        out->has_le = true;
        out->le     = (raw[idx] == 0) ? 256 : raw[idx];
        idx++;
    }

    return true;
}

/* ── Response builder ───────────────────────────────────────────────────────── */

void apdu_resp_init(apdu_resp_t *r, uint8_t *buf, size_t capacity)
{
    r->buf      = buf;
    r->capacity = capacity;
    r->len      = 0;
    r->sw       = SW_OK;
}

bool apdu_resp_append(apdu_resp_t *r, const uint8_t *data, size_t len)
{
    if (!len) return true;
    if (r->len + len + 2 > r->capacity) return false;  /* +2 reserve for SW */
    memcpy(r->buf + r->len, data, len);
    r->len += len;
    return true;
}

bool apdu_resp_push(apdu_resp_t *r, uint8_t byte)
{
    return apdu_resp_append(r, &byte, 1);
}

size_t apdu_resp_finalize(apdu_resp_t *r, uint16_t sw)
{
    r->sw = sw;
    r->buf[r->len]     = (uint8_t)(sw >> 8);
    r->buf[r->len + 1] = (uint8_t)(sw & 0xFF);
    return r->len + 2;
}
