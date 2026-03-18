/**
 * usb_descriptors.c — USB device / configuration descriptors and TinyUSB callbacks
 *
 * Implements a USB CCID device (bDeviceClass = 0, interface class = 0x0B).
 * The CCID class driver is registered via usbd_app_driver_get_cb().
 *
 * Descriptor layout:
 *   Device descriptor (18 bytes)
 *   Configuration descriptor:
 *     Config header (9)
 *     Interface (9)
 *     CCID functional descriptor (54 = 0x36)
 *     Endpoint Bulk OUT (7)
 *     Endpoint Bulk IN  (7)
 *     Endpoint Interrupt IN (7)
 */

#include "tusb.h"
#include "config.h"
#include "ccid.h"

/* ── String descriptor indices ──────────────────────────────────────────────── */
enum {
    STR_IDX_LANGUAGE  = 0,
    STR_IDX_MFGR      = 1,
    STR_IDX_PRODUCT   = 2,
    STR_IDX_SERIAL    = 3,
};

/* ── Device descriptor ──────────────────────────────────────────────────────── */
static const tusb_desc_device_t desc_device = {
    .bLength            = sizeof(tusb_desc_device_t),
    .bDescriptorType    = TUSB_DESC_DEVICE,
    .bcdUSB             = 0x0200,           /* USB 2.0                          */
    .bDeviceClass       = 0x00,             /* class defined at interface level */
    .bDeviceSubClass    = 0x00,
    .bDeviceProtocol    = 0x00,
    .bMaxPacketSize0    = CFG_TUD_ENDPOINT0_SIZE,
    .idVendor           = USB_VID,
    .idProduct          = USB_PID,
    .bcdDevice          = 0x0100,
    .iManufacturer      = STR_IDX_MFGR,
    .iProduct           = STR_IDX_PRODUCT,
    .iSerialNumber      = STR_IDX_SERIAL,
    .bNumConfigurations = 1,
};

/* ── Configuration descriptor ───────────────────────────────────────────────── */
/*
 * Total = 9 (config) + 9 (iface) + 54 (CCID functional) + 7+7+7 (endpoints)
 *       = 93 bytes
 */
#define CCID_FUNC_DESC_LEN  54u
#define CONFIG_TOTAL_LEN    (9u + 9u + CCID_FUNC_DESC_LEN + 7u + 7u + 7u)

/* CCID functional descriptor (CCID spec v1.1, section 5.1) */
#define CCID_DESCRIPTOR_TYPE 0x21u

/* dwFeatures = 0x00040000:
 *   Short and Extended APDU level exchange (bit 18).
 *   macOS usbsmartcardreaderd sends complete APDUs in XfrBlock abData
 *   without T=0/T=1 TPDU framing — which is exactly what this firmware
 *   implements.  Using TPDU-level (0x00020000) causes macOS to attempt
 *   protocol negotiation against the ATR, which fails with ATR 3B 00.
 */
static const uint8_t desc_configuration[CONFIG_TOTAL_LEN] = {
    /* ── Config descriptor (9) ─────────────────────────────────────────────── */
    9,
    TUSB_DESC_CONFIGURATION,
    U16_TO_U8S_LE(CONFIG_TOTAL_LEN),
    1,        /* bNumInterfaces */
    1,        /* bConfigurationValue */
    0,        /* iConfiguration */
    TUSB_DESC_CONFIG_ATT_REMOTE_WAKEUP | 0x80u, /* bmAttributes */
    50,       /* bMaxPower (100 mA) */

    /* ── Interface descriptor (9) ──────────────────────────────────────────── */
    9,
    TUSB_DESC_INTERFACE,
    0,        /* bInterfaceNumber */
    0,        /* bAlternateSetting */
    3,        /* bNumEndpoints */
    0x0Bu,    /* bInterfaceClass: CCID / Smart Card */
    0x00,     /* bInterfaceSubClass */
    0x00,     /* bInterfaceProtocol */
    0,        /* iInterface */

    /* ── CCID class (functional) descriptor (54) ────────────────────────────── */
    CCID_FUNC_DESC_LEN,                         /* bLength                      */
    CCID_DESCRIPTOR_TYPE,                        /* bDescriptorType              */
    U16_TO_U8S_LE(0x0110),                       /* bcdCCID 1.10                 */
    0x00,                                        /* bMaxSlotIndex (0 = 1 slot)   */
    0x07,                                        /* bVoltageSupport: 5V/3V/1.8V  */
    U32_TO_U8S_LE(0x00000003),                   /* dwProtocols: T=0 + T=1       */
    U32_TO_U8S_LE(0x00000DFC),                   /* dwDefaultClock: 3580 kHz     */
    U32_TO_U8S_LE(0x00000DFC),                   /* dwMaximumClock               */
    0x00,                                        /* bNumClockSupported (0=default)*/
    U32_TO_U8S_LE(0x000025CD),                   /* dwDataRate: 9677 bps         */
    U32_TO_U8S_LE(0x000025CD),                   /* dwMaxDataRate                */
    0x00,                                        /* bNumDataRatesSupported       */
    U32_TO_U8S_LE(0x000000FE),                   /* dwMaxIFSD: 254               */
    U32_TO_U8S_LE(0x00000000),                   /* dwSynchProtocols             */
    U32_TO_U8S_LE(0x00000000),                   /* dwMechanical                 */
    U32_TO_U8S_LE(0x00040000),                   /* dwFeatures (see above)       */
    U32_TO_U8S_LE(0x0000010F),                   /* dwMaxCCIDMessageLength: 271  */
    0xFF,                                        /* bClassGetResponse            */
    0xFF,                                        /* bClassEnvelope               */
    U16_TO_U8S_LE(0x0000),                       /* wLcdLayout: no LCD           */
    0x00,                                        /* bPINSupport: none            */
    0x01,                                        /* bMaxCCIDBusySlots: 1         */

    /* ── Endpoint: Bulk OUT (host → device) (7) ─────────────────────────────── */
    7,
    TUSB_DESC_ENDPOINT,
    CCID_EP_BULK_OUT,           /* 0x01 */
    TUSB_XFER_BULK,
    U16_TO_U8S_LE(CCID_EP_BULK_SIZE),
    0,

    /* ── Endpoint: Bulk IN (device → host) (7) ──────────────────────────────── */
    7,
    TUSB_DESC_ENDPOINT,
    CCID_EP_BULK_IN,            /* 0x81 */
    TUSB_XFER_BULK,
    U16_TO_U8S_LE(CCID_EP_BULK_SIZE),
    0,

    /* ── Endpoint: Interrupt IN (device → host) (7) ─────────────────────────── */
    7,
    TUSB_DESC_ENDPOINT,
    CCID_EP_INTR_IN,            /* 0x82 */
    TUSB_XFER_INTERRUPT,
    U16_TO_U8S_LE(CCID_EP_INTR_SIZE),
    16,  /* bInterval: 16 ms */
};

/* ── String descriptors ─────────────────────────────────────────────────────── */
static const char *const string_table[] = {
    "\x09\x04",     /* 0: language = English (0x0409)     */
    "ward3n",       /* 1: manufacturer                    */
    "PIV Security Key",  /* 2: product                    */
    "00000001",     /* 3: serial — replaced at runtime    */
};

/* ── TinyUSB callbacks ──────────────────────────────────────────────────────── */

const uint8_t *tud_descriptor_device_cb(void)
{
    return (const uint8_t *)&desc_device;
}

const uint8_t *tud_descriptor_configuration_cb(uint8_t index)
{
    (void)index;
    return desc_configuration;
}

/* Static buffer for string descriptors (UTF-16LE) */
static uint16_t _desc_str[64];

const uint16_t *tud_descriptor_string_cb(uint8_t index, uint16_t langid)
{
    (void)langid;
    uint8_t chr_count;

    if (index == 0) {
        /* Language descriptor */
        _desc_str[1] = 0x0409;
        chr_count = 1;
    } else if (index < (uint8_t)TU_ARRAY_SIZE(string_table)) {
        const char *str = string_table[index];
        chr_count = (uint8_t)strlen(str);
        if (chr_count > 63) chr_count = 63;
        for (uint8_t i = 0; i < chr_count; i++) {
            _desc_str[1 + i] = str[i];
        }
    } else {
        return NULL;
    }

    _desc_str[0] = (uint16_t)((TUSB_DESC_STRING << 8) | (2 * chr_count + 2));
    return _desc_str;
}

/* ── Custom class driver registration ──────────────────────────────────────── */

usbd_class_driver_t const *usbd_app_driver_get_cb(uint8_t *driver_count)
{
    *driver_count = 1;
    return ccid_driver();
}
