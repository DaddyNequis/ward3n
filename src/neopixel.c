/**
 * neopixel.c — WS2812 NeoPixel driver + state-driven animation
 *
 * PIO state machine drives GPIO 16 (RP2040 Zero onboard LED).
 * neopixel_tick() is called from the main loop and updates the animation
 * based on the current device state.
 */

#include "neopixel.h"
#include "device_state.h"
#include "config.h"

/* PIO-generated header (from ws2812.pio) */
#include "ws2812.pio.h"

#include "hardware/pio.h"
#include "hardware/clocks.h"
#include "pico/time.h"

#include <stdint.h>

/* ── PIO state ──────────────────────────────────────────────────────────────── */
static PIO   _pio = pio0;
static uint  _sm  = 0;

/* ── Send one RGB pixel to the PIO FIFO ─────────────────────────────────────── */
/* WS2812 expects 24-bit GRB, MSB-first.                                         */
static void _send_pixel(uint8_t r, uint8_t g, uint8_t b)
{
    uint32_t word = ((uint32_t)g << 24) | ((uint32_t)r << 16) | ((uint32_t)b << 8);
    pio_sm_put_blocking(_pio, _sm, word);
}

/* ── Public API ─────────────────────────────────────────────────────────────── */

void neopixel_init(void)
{
    uint offset = pio_add_program(_pio, &ws2812_program);
    ws2812_program_init(_pio, _sm, offset, NEOPIXEL_PIN, 800000.0f);
}

void neopixel_set(uint8_t r, uint8_t g, uint8_t b)
{
    _send_pixel(r, g, b);
}

/* ── Animation state ─────────────────────────────────────────────────────────── */
static absolute_time_t _next_tick;
static bool            _blink_on = false;

void neopixel_tick(void)
{
    if (!time_reached(_next_tick)) return;

    dev_state_t state = dev_state_get();

    switch (state) {
    case DEV_STATE_IDLE:
        /* Dim blue — static (breathing could be added here) */
        neopixel_set(0, 0, 20);
        _next_tick = make_timeout_time_ms(500);
        break;

    case DEV_STATE_WAITING_BUTTON:
        /* Yellow fast blink: 200 ms period */
        _blink_on = !_blink_on;
        if (_blink_on) {
            neopixel_set(80, 60, 0);   /* warm yellow */
        } else {
            neopixel_off();
        }
        _next_tick = make_timeout_time_ms(200);
        break;

    case DEV_STATE_AUTHORIZED:
        /* Green solid */
        neopixel_set(0, 60, 0);
        _next_tick = make_timeout_time_ms(250);
        break;

    case DEV_STATE_PROCESSING:
        /* Green fast blink: 100 ms period */
        _blink_on = !_blink_on;
        neopixel_set(_blink_on ? 0 : 0,
                     _blink_on ? 80 : 0,
                     0);
        _next_tick = make_timeout_time_ms(100);
        break;
    }
}
