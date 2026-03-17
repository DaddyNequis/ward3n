/**
 * device_state.h — device state machine
 *
 * Transitions:
 *   IDLE ──(crypto op arrives, pin ok)──► WAITING_BUTTON
 *   WAITING_BUTTON ──(button pressed)──► AUTHORIZED
 *   AUTHORIZED ──(crypto op executed)──► PROCESSING ──► IDLE
 *   AUTHORIZED ──(10 s timeout)────────► IDLE
 *   WAITING_BUTTON ──(30 s timeout)────► IDLE
 */

#ifndef WARD3N_DEVICE_STATE_H
#define WARD3N_DEVICE_STATE_H

#include <stdint.h>
#include <stdbool.h>

typedef enum {
    DEV_STATE_IDLE            = 0,
    DEV_STATE_WAITING_BUTTON  = 1,
    DEV_STATE_AUTHORIZED      = 2,
    DEV_STATE_PROCESSING      = 3,
} dev_state_t;

/* Initialise timers and state. Call once at boot. */
void dev_state_init(void);

/* Call from main loop to handle timeouts. */
void dev_state_tick(void);

/* Current state accessor. */
dev_state_t dev_state_get(void);

/* Called by PIV layer when a privileged operation is about to run. */
void dev_state_request_auth(void);

/* Called by button ISR / polling on confirmed press. */
void dev_state_button_pressed(void);

/* Called by PIV layer when it starts executing the crypto op. */
void dev_state_begin_processing(void);

/* Called by PIV layer when the crypto op is complete.
 * Consumes the one-shot authorization and returns to IDLE. */
void dev_state_op_complete(void);

/* Returns true if the device is authorized to perform a crypto operation.
 * Calling this consumes the one-shot flag. */
bool dev_state_consume_auth(void);

/* Returns true if the 10-second window is still open. */
bool dev_state_is_authorized(void);

#endif /* WARD3N_DEVICE_STATE_H */
