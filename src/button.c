/**
 * button.c — user-presence button, GPIO 23, active-low with pull-up
 *
 * Uses a GPIO edge interrupt to detect falling edges, then confirms
 * the press after BUTTON_DEBOUNCE_MS by checking the GPIO level again.
 * button_was_pressed() returns true exactly once per confirmed press.
 */

#include "button.h"
#include "config.h"
#include "device_state.h"

#include "pico/stdlib.h"
#include "hardware/gpio.h"
#include "pico/time.h"

#include <stdbool.h>
#include <stdint.h>

static volatile bool _edge_seen    = false;
static volatile bool _press_confirmed = false;
static          absolute_time_t _edge_time;

static void _gpio_irq(uint gpio, uint32_t events)
{
    (void)events;
    if (gpio == BUTTON_PIN && !_edge_seen) {
        _edge_seen = true;
        _edge_time = get_absolute_time();
    }
}

void button_init(void)
{
    gpio_init(BUTTON_PIN);
    gpio_set_dir(BUTTON_PIN, GPIO_IN);
    gpio_pull_up(BUTTON_PIN);

    /* Detect falling edge (button connects pin to GND) */
    gpio_set_irq_enabled_with_callback(BUTTON_PIN,
                                        GPIO_IRQ_EDGE_FALL,
                                        true,
                                        _gpio_irq);
}

bool button_was_pressed(void)
{
    if (!_edge_seen) return false;

    /* Check if debounce window has elapsed */
    int64_t elapsed_ms = absolute_time_diff_us(_edge_time, get_absolute_time()) / 1000;
    if (elapsed_ms < BUTTON_DEBOUNCE_MS) return false;

    _edge_seen = false;

    /* Confirm: pin must still be low (button still held or just released) */
    if (gpio_get(BUTTON_PIN) == 0) {
        _press_confirmed = true;
        /* Notify state machine */
        dev_state_button_pressed();
        return true;
    }

    return false;
}
