/**
 * ccid.h — CCID custom class driver for TinyUSB
 *
 * Implements the USB Smart Card Device Class (CCID) specification v1.1.
 * Registered with TinyUSB via usbd_app_driver_get_cb().
 *
 * Supported messages:
 *   PC_to_RDR_IccPowerOn     (0x62) → RDR_to_PC_DataBlock (ATR)
 *   PC_to_RDR_IccPowerOff    (0x63) → RDR_to_PC_SlotStatus
 *   PC_to_RDR_GetSlotStatus  (0x65) → RDR_to_PC_SlotStatus
 *   PC_to_RDR_XfrBlock       (0x6F) → RDR_to_PC_DataBlock (APDU response)
 */

#ifndef WARD3N_CCID_H
#define WARD3N_CCID_H

#include "tusb.h"
/* usbd_class_driver_t is in the TinyUSB private device header.
 * Including it here is the correct pattern for custom class drivers. */
#include "device/usbd_pvt.h"

#include <stdint.h>
#include <stddef.h>

/* ── CCID message types ─────────────────────────────────────────────────────── */
#define CCID_PC_to_RDR_IccPowerOn      0x62u
#define CCID_PC_to_RDR_IccPowerOff     0x63u
#define CCID_PC_to_RDR_GetSlotStatus   0x65u
#define CCID_PC_to_RDR_XfrBlock        0x6Fu
#define CCID_PC_to_RDR_Abort           0x72u

#define CCID_RDR_to_PC_DataBlock       0x80u
#define CCID_RDR_to_PC_SlotStatus      0x81u
#define CCID_RDR_to_PC_Parameters      0x82u

/* ── CCID header size ───────────────────────────────────────────────────────── */
#define CCID_HEADER_LEN 10u

/* ── CCID status / error bytes ──────────────────────────────────────────────── */
/* bStatus bits [1:0]: ICC status */
#define CCID_ICC_ACTIVE     0x00u
#define CCID_ICC_INACTIVE   0x01u
#define CCID_ICC_ABSENT     0x02u
/* bStatus bits [7:6]: CMD status */
#define CCID_CMD_OK         0x00u
#define CCID_CMD_FAILED     0x40u
#define CCID_CMD_TIME_EXT   0x80u

/* ── CCID message header ────────────────────────────────────────────────────── */
typedef struct __attribute__((packed)) {
    uint8_t  bMessageType;
    uint32_t dwLength;    /* body length, little-endian                       */
    uint8_t  bSlot;
    uint8_t  bSeq;
    uint8_t  bSpecific_0; /* interpretation depends on message type           */
    uint8_t  bSpecific_1;
    uint8_t  bSpecific_2;
} ccid_header_t;

/* ── Public API ─────────────────────────────────────────────────────────────── */

/**
 * Return pointer to the TinyUSB custom class driver descriptor.
 * Called by usbd_app_driver_get_cb() in usb_descriptors.c.
 */
const usbd_class_driver_t *ccid_driver(void);

/**
 * Non-blocking check called from main loop after tud_task().
 * Processes any pending CCID response queued by the class driver ISR.
 */
void ccid_task(void);

#endif /* WARD3N_CCID_H */
