/**
 * tusb_config.h — TinyUSB configuration for ward3n CCID device
 *
 * We implement CCID as a custom class driver via usbd_app_driver_get_cb().
 * No standard TinyUSB class (CDC, HID, vendor…) is needed.
 */

#ifndef _TUSB_CONFIG_H_
#define _TUSB_CONFIG_H_

#ifdef __cplusplus
extern "C" {
#endif

/* ── Controller / port ─────────────────────────────────────────────────────── */
#ifndef CFG_TUSB_MCU
#  define CFG_TUSB_MCU OPT_MCU_RP2040
#endif

#define CFG_TUSB_RHPORT0_MODE OPT_MODE_DEVICE
#define CFG_TUSB_OS            OPT_OS_NONE   /* bare-metal, polled in main loop */

/* ── Debug (set 0 for release) ─────────────────────────────────────────────── */
#define CFG_TUSB_DEBUG 0

/* ── Memory ─────────────────────────────────────────────────────────────────── */
#define CFG_TUSB_MEM_SECTION
#define CFG_TUSB_MEM_ALIGN      __attribute__((aligned(4)))

/* ── Device ─────────────────────────────────────────────────────────────────── */
#define CFG_TUD_ENDPOINT0_SIZE 64

/* All standard classes disabled — CCID is custom */
#define CFG_TUD_CDC      0
#define CFG_TUD_MSC      0
#define CFG_TUD_HID      0
#define CFG_TUD_MIDI     0
#define CFG_TUD_VENDOR   0
#define CFG_TUD_AUDIO    0
#define CFG_TUD_VIDEO    0
#define CFG_TUD_DFU_RUNTIME 0

#ifdef __cplusplus
}
#endif

#endif /* _TUSB_CONFIG_H_ */
