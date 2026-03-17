/**
 * device_state.c — device state machine implementation
 */

#include "device_state.h"
#include "config.h"
#include "pico/time.h"

#include <stdint.h>

static volatile dev_state_t _state          = DEV_STATE_IDLE;
static          absolute_time_t _deadline;
static volatile bool _auth_consumed         = false;

void dev_state_init(void)
{
    _state         = DEV_STATE_IDLE;
    _auth_consumed = false;
}

void dev_state_tick(void)
{
    switch (_state) {
    case DEV_STATE_WAITING_BUTTON:
        if (absolute_time_diff_us(get_absolute_time(), _deadline) <= 0) {
            /* Timed out waiting for button */
            _state = DEV_STATE_IDLE;
        }
        break;

    case DEV_STATE_AUTHORIZED:
        if (absolute_time_diff_us(get_absolute_time(), _deadline) <= 0) {
            /* Auth window expired */
            _auth_consumed = true;   /* discard pending authorization */
            _state = DEV_STATE_IDLE;
        }
        break;

    default:
        break;
    }
}

dev_state_t dev_state_get(void)
{
    return _state;
}

void dev_state_request_auth(void)
{
    if (_state == DEV_STATE_IDLE) {
        _state    = DEV_STATE_WAITING_BUTTON;
        _deadline = make_timeout_time_ms(WAIT_BUTTON_TIMEOUT_MS);
    }
}

void dev_state_button_pressed(void)
{
    if (_state == DEV_STATE_WAITING_BUTTON) {
        _auth_consumed = false;
        _state         = DEV_STATE_AUTHORIZED;
        _deadline      = make_timeout_time_ms(AUTH_WINDOW_MS);
    }
}

void dev_state_begin_processing(void)
{
    if (_state == DEV_STATE_AUTHORIZED) {
        _state = DEV_STATE_PROCESSING;
    }
}

void dev_state_op_complete(void)
{
    _state = DEV_STATE_IDLE;
}

bool dev_state_consume_auth(void)
{
    if (_state == DEV_STATE_AUTHORIZED && !_auth_consumed) {
        _auth_consumed = true;
        return true;
    }
    return false;
}

bool dev_state_is_authorized(void)
{
    return (_state == DEV_STATE_AUTHORIZED && !_auth_consumed);
}
