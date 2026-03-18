/**
 * config.h — hardware pin assignments, flash layout, and compile-time constants
 */

#ifndef WARD3N_CONFIG_H
#define WARD3N_CONFIG_H

#include "pico/stdlib.h"
#include "hardware/flash.h"

/* ── Hardware pins (RP2040 Zero) ────────────────────────────────────────────── */
#define NEOPIXEL_PIN        16u   /* Onboard WS2812 on RP2040 Zero            */
#define BUTTON_PIN           9u   /* User presence button (active-low + pull-up)*/
#define BUTTON_DEBOUNCE_MS  30u   /* Debounce window                           */

/* ── State machine timing ───────────────────────────────────────────────────── */
#define AUTH_WINDOW_MS      10000u /* Authorized window after button press (ms) */
#define WAIT_BUTTON_TIMEOUT_MS 30000u /* Give up waiting for button after 30 s  */

/* ── Flash layout (2 MB RP2040 Zero) ───────────────────────────────────────── */
/*   XIP base + total flash - one sector reserved for key storage               */
#define FLASH_SIZE_BYTES        (2 * 1024 * 1024)
#define KEY_STORAGE_OFFSET      (FLASH_SIZE_BYTES - FLASH_SECTOR_SIZE)
#define KEY_STORAGE_XIP_ADDR    (XIP_BASE + KEY_STORAGE_OFFSET)
#define KEY_STORAGE_MAGIC       0xA3B1C057u  /* arbitrary magic to detect init  */

/* Flash sector = 4096 bytes, layout:
 *   [0  .. 3 ] magic (uint32_t)
 *   [4  ..35 ] private key d (32 bytes, big-endian)
 *   [36 ..67 ] public key X  (32 bytes, big-endian)
 *   [68 ..99 ] public key Y  (32 bytes, big-endian)
 *   [100..101] cert_len (uint16_t LE)
 *   [102..4095] cert DER bytes (up to 3994 bytes)
 */
#define KS_OFFSET_MAGIC     0
#define KS_OFFSET_PRIVKEY   4
#define KS_OFFSET_PUBKEY_X  36
#define KS_OFFSET_PUBKEY_Y  68
#define KS_OFFSET_CERT_LEN  100
#define KS_OFFSET_CERT_DER  102
#define KS_MAX_CERT_LEN     (FLASH_SECTOR_SIZE - KS_OFFSET_CERT_DER)

/* ── PIV constants ──────────────────────────────────────────────────────────── */
#define PIV_PIN_LEN_MIN     6u
#define PIV_PIN_LEN_MAX     8u
#define PIV_PIN_PAD_BYTE    0xFFu
/* Fixed PIN for development — CHANGE THIS or implement real PIN management */
#define PIV_DEFAULT_PIN     "123456"

/* ── USB / CCID ─────────────────────────────────────────────────────────────── */
#define CCID_EP_BULK_OUT    0x01u
#define CCID_EP_BULK_IN     0x81u
#define CCID_EP_INTR_IN     0x82u
#define CCID_EP_BULK_SIZE   64u
#define CCID_EP_INTR_SIZE   8u
#define CCID_BUF_SIZE       512u  /* must hold max short APDU + CCID header     */

/* USB IDs — use VID/PID pair reserved for development prototyping.
 * Pending validation: replace with a legitimate VID/PID pair before production.*/
#define USB_VID             0x1209u  /* pid.codes open-source VID                */
#define USB_PID             0x0001u  /* pid.codes unassigned — change before prod */

#endif /* WARD3N_CONFIG_H */
