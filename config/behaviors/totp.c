// For module approach on split keyboards:
// config/modules/totp/src/totp_behavior.c - Split keyboard version

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zmk/behavior.h>
#include <zmk/event_manager.h>
#include <zmk/events/keycode_state_changed.h>
#include <zmk/split/bluetooth/central.h>

LOG_MODULE_DECLARE(zmk, CONFIG_ZMK_LOG_LEVEL);

// TOTP data structure
struct totp_entry {
    char name[16];
    uint8_t secret[10];
    uint32_t period;
};

static struct totp_entry totp_accounts[3] = {
    {"GitHub", {0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x11, 0x22}, 30},
    {"Google", {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33}, 30}, 
    {"AWS", {0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x21, 0xDE, 0xAD, 0xBE, 0xEF}, 30}
};

// Simple TOTP hash (replace with proper implementation)
static uint32_t simple_totp_hash(uint8_t *secret, uint32_t time_step) {
    uint32_t hash = time_step;
    for (int i = 0; i < 10; i++) {
        hash = ((hash << 5) + hash) + secret[i];
        hash ^= (hash >> 13);
        hash *= 0x5bd1e995;
        hash ^= (hash >> 15);
    }
    return (hash % 1000000); // 6-digit code
}

static void generate_totp_codes(void) {
    // Only generate on central side (USB-connected)
    #if IS_ENABLED(CONFIG_ZMK_SPLIT_ROLE_CENTRAL) || !IS_ENABLED(CONFIG_ZMK_SPLIT)
    
    LOG_INF("=== TOTP CODES ===");
    LOG_INF("Generated on: %s", IS_ENABLED(CONFIG_ZMK_SPLIT) ? "CENTRAL" : "SINGLE");
    
    uint64_t uptime_ms = k_uptime_get();
    uint32_t time_step = (uptime_ms / 1000) / 30; // 30-second periods
    
    LOG_INF("Uptime: %llu ms, Time step: %u", uptime_ms, time_step);
    
    for (int i = 0; i < 3; i++) {
        uint32_t code = simple_totp_hash(totp_accounts[i].secret, time_step);
        LOG_INF("%s: %06u", totp_accounts[i].name, code);
    }
    
    LOG_INF("==================");
    
    #else
    LOG_INF("TOTP: Triggered on peripheral side - no codes generated");
    #endif
}

// Key event listener
static int totp_keycode_listener(const zmk_event_t *eh) {
    struct zmk_keycode_state_changed *ev = as_zmk_keycode_state_changed(eh);
    if (ev == NULL) {
        return ZMK_EV_EVENT_BUBBLE;
    }

    // Detect our macro sequence F13+F14+F15
    static int sequence_state = 0;
    
    if (ev->state) { // Key pressed
        switch (ev->keycode) {
            case HID_USAGE_KEY_KEYBOARD_F13:
                if (sequence_state == 0) {
                    sequence_state = 1;
                    LOG_INF("TOTP: Sequence step 1");
                } else {
                    sequence_state = 0;
                }
                break;
                
            case HID_USAGE_KEY_KEYBOARD_F14:
                if (sequence_state == 1) {
                    sequence_state = 2;
                    LOG_INF("TOTP: Sequence step 2");
                } else {
                    sequence_state = 0;
                }
                break;
                
            case HID_USAGE_KEY_KEYBOARD_F15:
                if (sequence_state == 2) {
                    LOG_INF("TOTP: Sequence complete - generating codes");
                    generate_totp_codes();
                    sequence_state = 0;
                } else {
                    sequence_state = 0;
                }
                break;
                
            default:
                sequence_state = 0;
                break;
        }
    }

    return ZMK_EV_EVENT_BUBBLE;
}

ZMK_LISTENER(totp_listener, totp_keycode_listener);
ZMK_SUBSCRIPTION(totp_listener, zmk_keycode_state_changed);
