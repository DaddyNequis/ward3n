/**
 * ccid.c — CCID custom class driver for TinyUSB
 *
 * Implements a minimal CCID transport over three endpoints:
 *   EP1 OUT (Bulk) — receives PC_to_RDR messages
 *   EP1 IN  (Bulk) — sends  RDR_to_PC messages
 *   EP2 IN  (Intr) — sends  slot-change notifications (stub)
 *
 * CCID message handling is intentionally kept in this file.
 * APDU routing is delegated to piv_process_apdu().
 */

#include "tusb.h"
#include "device/usbd_pvt.h"   /* usbd_edpt_open / xfer / claim / release     */

#include "ccid.h"
#include "config.h"
#include "piv.h"

#include <string.h>

/* ── Static slot state ──────────────────────────────────────────────────────── */
static bool _icc_powered = false;   /* true after IccPowerOn, false after Off  */

/* ATR returned on IccPowerOn.
 * 3B 10 01 11 — direct convention, minimal T=1 ATR:
 *   TS   = 3B        direct convention
 *   T0   = 10        Y1=0001 → TD1 present, K=0 (no historical bytes)
 *   TD1  = 01        Y2=0000 (no further interface bytes), T=0001 → T=1
 *   TCK  = 11        XOR of T0..TD1 = 0x10^0x01 = 0x11
 * Explicitly advertising T=1 matches dwProtocols and tells macOS PCSC
 * to negotiate T=1 as the active protocol, which is required when
 * dwFeatures=0x00040000 (APDU-level: reader handles protocol internally). */
static const uint8_t _atr[] = { 0x3B, 0x10, 0x01, 0x11 };

/* ── Endpoint addresses and transfer buffers ─────────────────────────────────── */
static uint8_t _ep_out;
static uint8_t _ep_in;
static uint8_t _ep_intr;

/* Aligned per TinyUSB requirements */
static CFG_TUSB_MEM_ALIGN uint8_t _rx_buf[CCID_BUF_SIZE];
static CFG_TUSB_MEM_ALIGN uint8_t _tx_buf[CCID_BUF_SIZE];

/* ── Pending response (set by xfer_cb, consumed by ccid_task) ───────────────── */
static volatile bool   _response_pending = false;
static          size_t _response_len = 0;

/* ── RDR_to_PC_SlotStatus helper ────────────────────────────────────────────── */
static size_t _make_slot_status(uint8_t *out, uint8_t seq,
                                uint8_t cmd_status, uint8_t error,
                                uint8_t clock_status)
{
    ccid_header_t *h = (ccid_header_t *)out;
    h->bMessageType = CCID_RDR_to_PC_SlotStatus;
    h->dwLength     = 0;
    h->bSlot        = 0;
    h->bSeq         = seq;
    h->bSpecific_0  = (uint8_t)(cmd_status | (_icc_powered ? CCID_ICC_ACTIVE
                                                            : CCID_ICC_INACTIVE));
    h->bSpecific_1  = error;
    h->bSpecific_2  = clock_status;   /* 0 = clock running */
    return CCID_HEADER_LEN;
}

/* ── RDR_to_PC_DataBlock helper ─────────────────────────────────────────────── */
static size_t _make_data_block(uint8_t *out, uint8_t seq,
                               uint8_t cmd_status, uint8_t error,
                               const uint8_t *data, size_t data_len)
{
    ccid_header_t *h = (ccid_header_t *)out;
    h->bMessageType = CCID_RDR_to_PC_DataBlock;
    h->dwLength     = (uint32_t)data_len;
    h->bSlot        = 0;
    h->bSeq         = seq;
    h->bSpecific_0  = (uint8_t)(cmd_status | (_icc_powered ? CCID_ICC_ACTIVE
                                                            : CCID_ICC_INACTIVE));
    h->bSpecific_1  = error;
    h->bSpecific_2  = 0;   /* bChainParameter: no chaining at CCID level      */
    if (data && data_len) {
        memcpy(out + CCID_HEADER_LEN, data, data_len);
    }
    return CCID_HEADER_LEN + data_len;
}

/* ── Message dispatcher ─────────────────────────────────────────────────────── */
static void _process_message(const uint8_t *msg, size_t msg_len)
{
    if (msg_len < CCID_HEADER_LEN) return;

    const ccid_header_t *req = (const ccid_header_t *)msg;
    uint8_t seq = req->bSeq;
    size_t  resp_len = 0;

    switch (req->bMessageType) {

    /* ── IccPowerOn ──────────────────────────────────────────────────────────── */
    case CCID_PC_to_RDR_IccPowerOn:
        _icc_powered = true;
        piv_init();   /* reset PIV applet state on power cycle                 */
        resp_len = _make_data_block(_tx_buf, seq, CCID_CMD_OK, 0,
                                    _atr, sizeof(_atr));
        break;

    /* ── IccPowerOff ─────────────────────────────────────────────────────────── */
    case CCID_PC_to_RDR_IccPowerOff:
        _icc_powered = false;
        resp_len = _make_slot_status(_tx_buf, seq, CCID_CMD_OK, 0, 0);
        break;

    /* ── GetSlotStatus ───────────────────────────────────────────────────────── */
    case CCID_PC_to_RDR_GetSlotStatus:
        resp_len = _make_slot_status(_tx_buf, seq, CCID_CMD_OK, 0, 0);
        break;

    /* ── XfrBlock: route APDU to PIV applet ─────────────────────────────────── */
    case CCID_PC_to_RDR_XfrBlock: {
        if (!_icc_powered) {
            resp_len = _make_data_block(_tx_buf, seq, CCID_CMD_FAILED, 0x01,
                                        NULL, 0);
            break;
        }
        uint32_t apdu_len = req->dwLength;
        if (apdu_len == 0 || CCID_HEADER_LEN + apdu_len > msg_len) {
            resp_len = _make_data_block(_tx_buf, seq, CCID_CMD_FAILED, 0x01,
                                        NULL, 0);
            break;
        }
        const uint8_t *apdu_in = msg + CCID_HEADER_LEN;

        /* APDU response goes into _tx_buf after the CCID header              */
        uint8_t *apdu_out = _tx_buf + CCID_HEADER_LEN;
        size_t   out_cap  = sizeof(_tx_buf) - CCID_HEADER_LEN;
        size_t   apdu_resp_len = piv_process_apdu(apdu_in, apdu_len,
                                                  apdu_out, out_cap);

        /* Now build the CCID DataBlock header in-place                       */
        ccid_header_t *h = (ccid_header_t *)_tx_buf;
        h->bMessageType = CCID_RDR_to_PC_DataBlock;
        h->dwLength     = (uint32_t)apdu_resp_len;
        h->bSlot        = 0;
        h->bSeq         = seq;
        h->bSpecific_0  = CCID_CMD_OK | CCID_ICC_ACTIVE;
        h->bSpecific_1  = 0;
        h->bSpecific_2  = 0;
        resp_len = CCID_HEADER_LEN + apdu_resp_len;
        break;
    }

    /* ── Abort (acknowledge, take no action) ─────────────────────────────────── */
    case CCID_PC_to_RDR_Abort:
        resp_len = _make_slot_status(_tx_buf, seq, CCID_CMD_OK, 0, 0);
        break;

    /* ── SetParameters (0x61) ────────────────────────────────────────────────── */
    case 0x61: {
        /* macOS usbsmartcardreaderd sends this unconditionally to negotiate T=1
         * parameters even for APDU-level readers.  We are APDU-level so the
         * parameters are irrelevant, but we must echo them back in the correct
         * RDR_to_PC_Parameters (0x82) format or macOS aborts the connect.     */
        uint32_t plen = req->dwLength;
        if (plen > sizeof(_tx_buf) - CCID_HEADER_LEN)
            plen = 0;
        ccid_header_t *h = (ccid_header_t *)_tx_buf;
        h->bMessageType = CCID_RDR_to_PC_Parameters;
        h->dwLength     = plen;
        h->bSlot        = 0;
        h->bSeq         = seq;
        h->bSpecific_0  = (uint8_t)(CCID_CMD_OK | CCID_ICC_ACTIVE);
        h->bSpecific_1  = 0;
        h->bSpecific_2  = req->bSpecific_2;   /* bProtocolNum (0x01 = T=1)    */
        if (plen > 0 && CCID_HEADER_LEN + plen <= msg_len)
            memcpy(_tx_buf + CCID_HEADER_LEN, msg + CCID_HEADER_LEN, plen);
        resp_len = CCID_HEADER_LEN + plen;
        break;
    }

    /* ── SetDataRateAndClockFrequency (0x73) ─────────────────────────────────── */
    case 0x73: {
        /* macOS also sends this unconditionally.  Echo back whatever it
         * requested in RDR_to_PC_DataRateAndClockFrequency (0x84).            */
        ccid_header_t *h = (ccid_header_t *)_tx_buf;
        h->bMessageType = 0x84;
        h->dwLength     = 8;
        h->bSlot        = 0;
        h->bSeq         = seq;
        h->bSpecific_0  = (uint8_t)(CCID_CMD_OK | CCID_ICC_ACTIVE);
        h->bSpecific_1  = 0;
        h->bSpecific_2  = 0;   /* bRFU */
        if (req->dwLength >= 8 && CCID_HEADER_LEN + 8 <= msg_len) {
            /* Echo the requested clock/rate back so macOS sees its own values */
            memcpy(_tx_buf + CCID_HEADER_LEN, msg + CCID_HEADER_LEN, 8);
        } else {
            /* Fallback to descriptor defaults */
            uint32_t clk  = 0x00000DFCU; /* 3580 kHz */
            uint32_t rate = 0x000025CDU; /* 9677 bps */
            memcpy(_tx_buf + CCID_HEADER_LEN,     &clk,  4);
            memcpy(_tx_buf + CCID_HEADER_LEN + 4, &rate, 4);
        }
        resp_len = CCID_HEADER_LEN + 8;
        break;
    }

    default:
        /* Unknown command — respond with CMD_FAILED */
        resp_len = _make_slot_status(_tx_buf, seq, CCID_CMD_FAILED, 0, 0);
        break;
    }

    if (resp_len > 0) {
        _response_len = resp_len;
        _response_pending = true;
    }
}

/* ══════════════════════════════════════════════════════════════════════════════
 * TinyUSB custom class driver callbacks
 * ══════════════════════════════════════════════════════════════════════════════ */

static void _ccid_init(void)
{
    _icc_powered     = false;
    _response_pending = false;
    _response_len    = 0;
    memset(_rx_buf, 0, sizeof(_rx_buf));
    memset(_tx_buf, 0, sizeof(_tx_buf));
}

static void _ccid_reset(uint8_t rhport)
{
    (void)rhport;
    _icc_powered     = false;
    _response_pending = false;
}

static uint16_t _ccid_open(uint8_t rhport, tusb_desc_interface_t const *itf_desc,
                            uint16_t max_len)
{
    /* Verify this is a CCID interface */
    TU_VERIFY(TUSB_CLASS_SMART_CARD == itf_desc->bInterfaceClass, 0);

    uint16_t drv_len = sizeof(tusb_desc_interface_t);
    uint8_t const *p_desc = tu_desc_next(itf_desc);

    /* Skip any class-specific (functional) descriptors (type 0x21 for CCID) */
    while (tu_desc_type(p_desc) == 0x21u && drv_len < max_len) {
        drv_len += tu_desc_len(p_desc);
        p_desc   = tu_desc_next(p_desc);
    }

    /* Open endpoints */
    _ep_out  = 0;
    _ep_in   = 0;
    _ep_intr = 0;

    for (int i = 0; i < 3 && drv_len < max_len; i++) {
        if (tu_desc_type(p_desc) != TUSB_DESC_ENDPOINT) break;
        tusb_desc_endpoint_t const *ep = (tusb_desc_endpoint_t const *)p_desc;
        TU_ASSERT(usbd_edpt_open(rhport, ep), 0);

        if (ep->bmAttributes.xfer == TUSB_XFER_BULK) {
            if (tu_edpt_dir(ep->bEndpointAddress) == TUSB_DIR_OUT) {
                _ep_out = ep->bEndpointAddress;
            } else {
                _ep_in = ep->bEndpointAddress;
            }
        } else if (ep->bmAttributes.xfer == TUSB_XFER_INTERRUPT) {
            _ep_intr = ep->bEndpointAddress;
        }
        drv_len += tu_desc_len(p_desc);
        p_desc   = tu_desc_next(p_desc);
    }

    TU_ASSERT(_ep_out && _ep_in, 0);

    /* Arm OUT endpoint to receive first CCID message */
    usbd_edpt_xfer(rhport, _ep_out, _rx_buf, sizeof(_rx_buf));

    return drv_len;
}

static bool _ccid_control_xfer_cb(uint8_t rhport, uint8_t stage,
                                   tusb_control_request_t const *request)
{
    /* Only act on SETUP stage; TinyUSB re-invokes for DATA/ACK automatically */
    if (stage != CONTROL_STAGE_SETUP) return true;

    if (request->bmRequestType_bit.type == TUSB_REQ_TYPE_CLASS) {
        switch (request->bRequest) {
        case 0x62: /* GET_CLOCK_FREQUENCIES — bNumClockSupported=0 → empty  */
        case 0x63: /* GET_DATA_RATES       — bNumDataRatesSupported=0 → empty */
            /* Return ZLP; macOS falls back to dwDefaultClock/dwDataRate values
             * from the CCID functional descriptor.                            */
            return tud_control_xfer(rhport, request, NULL, 0);

        case 0x61: /* ABORT — acknowledge; bulk-level abort handled separately */
            return tud_control_xfer(rhport, request, NULL, 0);

        default:
            break;
        }
    }
    return false; /* STALL unrecognised requests */
}

static bool _ccid_xfer_cb(uint8_t rhport, uint8_t ep_addr,
                           xfer_result_t result, uint32_t xferred_bytes)
{
    (void)result;

    if (ep_addr == _ep_out) {
        /* Received a PC_to_RDR message */
        if (xferred_bytes >= CCID_HEADER_LEN) {
            _process_message(_rx_buf, xferred_bytes);
        }
        /* Re-arm OUT endpoint immediately */
        usbd_edpt_xfer(rhport, _ep_out, _rx_buf, sizeof(_rx_buf));
    }
    /* Bulk IN / Interrupt IN completions: nothing to do (one-shot sends) */
    return true;
}

/* deinit stub — required by TinyUSB 2024+ class driver API */
static bool _ccid_deinit(void) { return true; }

/* ── Class driver vtable ─────────────────────────────────────────────────────── */
static usbd_class_driver_t const _ccid_driver = {
#if CFG_TUSB_DEBUG >= 2
    .name            = "CCID",
#endif
    .init            = _ccid_init,
    .deinit          = _ccid_deinit,   /* added in TinyUSB Pico SDK 2.x        */
    .reset           = _ccid_reset,
    .open            = _ccid_open,
    .control_xfer_cb = _ccid_control_xfer_cb,
    .xfer_cb         = _ccid_xfer_cb,
    .sof             = NULL,
};

const usbd_class_driver_t *ccid_driver(void)
{
    return &_ccid_driver;
}

/* ── ccid_task: called from main loop to push pending responses ─────────────── */
void ccid_task(void)
{
    if (!_response_pending) return;

    /* Claim the IN endpoint; if it's busy (previous transfer not done), retry
     * next tick — this is safe because the main loop spins fast.             */
    uint8_t rhport = 0;
    if (!usbd_edpt_claim(rhport, _ep_in)) return;

    _response_pending = false;
    usbd_edpt_xfer(rhport, _ep_in, _tx_buf, (uint16_t)_response_len);
}
