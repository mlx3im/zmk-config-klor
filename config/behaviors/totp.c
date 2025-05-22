#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zmk/behavior.h>
#include <zmk/keymap.h>
#include <drivers/behavior.h>
#include <zephyr/sys/byteorder.h>
#include <mbedtls/md.h>

LOG_MODULE_DECLARE(zmk, CONFIG_ZMK_LOG_LEVEL);

// TOTP configuration structure
struct totp_config {
    char label[32];
    uint8_t secret[32];
    uint8_t secret_len;
    uint32_t period;
    uint8_t digits;
};

// Three TOTP entries - replace with your actual secrets (base32 decoded)
static struct totp_config totp_entries[3] = {
    {
        .label = "Account1",
        .secret = {0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x21, 0xDE, 0xAD, 0xBE, 0xEF}, // Example secret
        .secret_len = 10,
        .period = 30,
        .digits = 6
    },
    {
        .label = "Account2", 
        .secret = {0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x11, 0x22}, // Example secret
        .secret_len = 10,
        .period = 30,
        .digits = 6
    },
    {
        .label = "Account3",
        .secret = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33}, // Example secret
        .secret_len = 10,
        .period = 30,
        .digits = 6
    }
};

// HMAC-SHA1 implementation for TOTP
static void hmac_sha1(const uint8_t *key, size_t key_len, 
                      const uint8_t *data, size_t data_len, 
                      uint8_t *output) {
    mbedtls_md_context_t ctx;
    const mbedtls_md_info_t *info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA1);
    
    mbedtls_md_init(&ctx);
    mbedtls_md_setup(&ctx, info, 1);
    mbedtls_md_hmac_starts(&ctx, key, key_len);
    mbedtls_md_hmac_update(&ctx, data, data_len);
    mbedtls_md_hmac_finish(&ctx, output);
    mbedtls_md_free(&ctx);
}

// Generate TOTP code
static uint32_t generate_totp(struct totp_config *config) {
    // Get current time (Unix timestamp)
    uint64_t time_step = k_uptime_get() / 1000 / config->period; // Simplified - use RTC in real implementation
    
    // Convert to big-endian 8-byte array
    uint8_t time_bytes[8];
    sys_put_be64(time_step, time_bytes);
    
    // Calculate HMAC-SHA1
    uint8_t hmac[20];
    hmac_sha1(config->secret, config->secret_len, time_bytes, 8, hmac);
    
    // Dynamic truncation
    uint8_t offset = hmac[19] & 0x0F;
    uint32_t code = ((hmac[offset] & 0x7F) << 24) |
                    ((hmac[offset + 1] & 0xFF) << 16) |
                    ((hmac[offset + 2] & 0xFF) << 8) |
                    (hmac[offset + 3] & 0xFF);
    
    // Reduce to desired number of digits
    uint32_t divisor = 1;
    for (int i = 0; i < config->digits; i++) {
        divisor *= 10;
    }
    
    return code % divisor;
}

// Print all TOTP codes to USB log
static void print_all_totp_codes(void) {
    LOG_INF("=== TOTP Codes ===");
    
    for (int i = 0; i < 3; i++) {
        uint32_t code = generate_totp(&totp_entries[i]);
        LOG_INF("%s: %0*u", totp_entries[i].label, totp_entries[i].digits, code);
    }
    
    LOG_INF("==================");
}

// Custom behavior implementation
struct behavior_totp_config {};
struct behavior_totp_data {};

static int behavior_totp_init(const struct device *dev) {
    return 0;
}

static int on_totp_binding_pressed(struct zmk_behavior_binding *binding,
                                   struct zmk_behavior_binding_event event) {
    print_all_totp_codes();
    return ZMK_BEHAVIOR_OPAQUE;
}

static int on_totp_binding_released(struct zmk_behavior_binding *binding,
                                    struct zmk_behavior_binding_event event) {
    return ZMK_BEHAVIOR_OPAQUE;
}

static const struct behavior_driver_api behavior_totp_driver_api = {
    .binding_pressed = on_totp_binding_pressed,
    .binding_released = on_totp_binding_released,
};

static const struct behavior_totp_config behavior_totp_config = {};
static struct behavior_totp_data behavior_totp_data;

DEVICE_DT_INST_DEFINE(0, behavior_totp_init, NULL,
                      &behavior_totp_data, &behavior_totp_config,
                      APPLICATION, CONFIG_KERNEL_INIT_PRIORITY_DEFAULT,
                      &behavior_totp_driver_api);

