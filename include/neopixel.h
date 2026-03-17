/**
 * neopixel.h — WS2812 NeoPixel driver (PIO-based, RP2040 Zero onboard LED)
 *
 * Colors encode device state:
 *   IDLE              → dim blue  (pulsing in main loop)
 *   WAITING_BUTTON    → yellow fast blink (200 ms)
 *   AUTHORIZED        → green solid
 *   PROCESSING        → green fast blink (100 ms)
 *   Error flash       → red 500 ms then back
 */

#ifndef WARD3N_NEOPIXEL_H
#define WARD3N_NEOPIXEL_H

#include <stdint.h>

/**
 * Initialise PIO state machine for WS2812 on NEOPIXEL_PIN.
 * Call once at boot.
 */
void neopixel_init(void);

/**
 * Set the NeoPixel to an RGB colour immediately.
 * r, g, b are 0–255.
 */
void neopixel_set(uint8_t r, uint8_t g, uint8_t b);

/** Convenience: turn off. */
static inline void neopixel_off(void) { neopixel_set(0, 0, 0); }

/**
 * Call from main loop to update the NeoPixel animation for the current
 * device state. Reads dev_state_get() internally.
 */
void neopixel_tick(void);

#endif /* WARD3N_NEOPIXEL_H */
