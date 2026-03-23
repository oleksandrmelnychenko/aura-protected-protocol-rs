#pragma once
#include "epp_export.h"

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#define EPP_API_VERSION_MAJOR 1
#define EPP_API_VERSION_MINOR 0
#define EPP_API_VERSION_PATCH 1

#define EPP_DEFAULT_ONE_TIME_KEY_COUNT 100
#define EPP_LIBRARY_VERSION "1.0.1"

typedef enum {
    EPP_SUCCESS = 0,
    EPP_ERROR_GENERIC = 1,
    EPP_ERROR_INVALID_INPUT = 2,
    EPP_ERROR_KEY_GENERATION = 3,
    EPP_ERROR_DERIVE_KEY = 4,
    EPP_ERROR_HANDSHAKE = 5,
    EPP_ERROR_ENCRYPTION = 6,
    EPP_ERROR_DECRYPTION = 7,
    EPP_ERROR_DECODE = 8,
    EPP_ERROR_ENCODE = 9,
    EPP_ERROR_BUFFER_TOO_SMALL = 10,
    EPP_ERROR_OBJECT_DISPOSED = 11,
    EPP_ERROR_PREPARE_LOCAL = 12,
    EPP_ERROR_OUT_OF_MEMORY = 13,
    EPP_ERROR_CRYPTO_FAILURE = 14,
    EPP_ERROR_NULL_POINTER = 15,
    EPP_ERROR_INVALID_STATE = 16,
    EPP_ERROR_REPLAY_ATTACK = 17,
    EPP_ERROR_SESSION_EXPIRED = 18,
    EPP_ERROR_PQ_MISSING = 19,
    EPP_ERROR_GROUP_PROTOCOL = 20,
    EPP_ERROR_GROUP_MEMBERSHIP = 21,
    EPP_ERROR_TREE_INTEGRITY = 22,
    EPP_ERROR_WELCOME = 23,
    EPP_ERROR_MESSAGE_EXPIRED = 24,
    EPP_ERROR_FRANKING = 25
} EppErrorCode;

typedef struct EppError {
    EppErrorCode code;
    char* message;
} EppError;

/* Owned byte buffer returned from Rust. Must be released with epp_buffer_release(). */
typedef struct EppBuffer {
    uint8_t* data;
    size_t length;
} EppBuffer;

typedef enum {
    EPP_ENVELOPE_REQUEST = 0,
    EPP_ENVELOPE_RESPONSE = 1,
    EPP_ENVELOPE_NOTIFICATION = 2,
    EPP_ENVELOPE_HEARTBEAT = 3,
    EPP_ENVELOPE_ERROR_RESPONSE = 4
} EppEnvelopeType;

/* Library lifecycle */
EPP_API const char* epp_version(void);
EPP_API EppErrorCode epp_init(void);
EPP_API void epp_shutdown(void);

/* Error utilities */
EPP_API void epp_error_free(EppError* error);
EPP_API const char* epp_error_string(EppErrorCode code);

/* Buffer utilities */
EPP_API void epp_buffer_release(EppBuffer* buffer);
EPP_API EppBuffer* epp_buffer_alloc(size_t capacity);
EPP_API void epp_buffer_free(EppBuffer* buffer);

/* Secure memory wipe */
EPP_API EppErrorCode epp_secure_wipe(uint8_t* data, size_t length);

#ifdef __cplusplus
}
#endif
