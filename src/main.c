/**
 * main.c — ward3n firmware entry point
 *
 * Boot sequence:
 *   1. Init hardware (clocks, stdio for debug)
 *   2. Init crypto backend (load/generate key pair + cert)
 *   3. Init PIV applet
 *   4. Init button + NeoPixel
 *   5. Init TinyUSB
 *   6. Main loop: tud_task() + ccid_task() + button_poll() + neopixel_tick()
 */

#include "pico/stdlib.h"
#include "pico/unique_id.h"
#include "tusb.h"

#include "config.h"
#include "device_state.h"
#include "crypto_backend.h"
#include "piv.h"
#include "ccid.h"
#include "button.h"
#include "neopixel.h"

int main(void)
{
    /* ── System clock: default 125 MHz, USB PLL already set by pico_stdlib ──── */
    stdio_init_all();

    /* ── Device state machine ─────────────────────────────────────────────────── */
    dev_state_init();

    /* ── NeoPixel: red during init ───────────────────────────────────────────── */
    neopixel_init();
    neopixel_set(40, 0, 0);

    /* ── Crypto backend ──────────────────────────────────────────────────────── */
    /* This may take several seconds on first boot (key generation + cert write) */
    int err = crypto_backend_init();
    if (err != 0) {
        /* Fatal: flash red and hang */
        neopixel_set(255, 0, 0);
        while (1) tight_loop_contents();
    }

    /* ── PIV applet init ─────────────────────────────────────────────────────── */
    piv_init();

    /* ── Button ──────────────────────────────────────────────────────────────── */
    button_init();

    /* ── USB (TinyUSB) ───────────────────────────────────────────────────────── */
    tusb_init();

    /* ── Main loop ───────────────────────────────────────────────────────────── */
    while (1) {
        /* USB stack — must be called frequently */
        tud_task();

        /* CCID response sender (dequeues pending RDR_to_PC messages) */
        ccid_task();

        /* Button polling / debounce */
        button_was_pressed();   /* side-effect: calls dev_state_button_pressed */

        /* State machine timeout handling */
        dev_state_tick();

        /* NeoPixel animation */
        neopixel_tick();
    }
}

/* ── TinyUSB mount / suspend callbacks ──────────────────────────────────────── */

void tud_mount_cb(void)
{
    /* USB host connected — enter idle state */
    /* NeoPixel will show idle blue on next neopixel_tick() */
}

void tud_umount_cb(void)
{
    /* USB disconnected */
    neopixel_off();
    dev_state_init();
}

void tud_suspend_cb(bool remote_wakeup_en)
{
    (void)remote_wakeup_en;
    neopixel_off();
}

void tud_resume_cb(void)
{
    /* Resumed from suspend */
}
