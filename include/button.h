/**
 * button.h — user-presence button (GPIO, active-low, debounced)
 */

#ifndef WARD3N_BUTTON_H
#define WARD3N_BUTTON_H

#include <stdbool.h>

/**
 * Configure the button GPIO and install the edge-detect interrupt.
 * Call once at boot.
 */
void button_init(void);

/**
 * Call from main loop. Returns true exactly once per confirmed press
 * (edge + debounce). Resets after returning true.
 */
bool button_was_pressed(void);

#endif /* WARD3N_BUTTON_H */
