#pragma once
#include "aura_export.h"

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#define AURA_API_VERSION_MAJOR 3
#define AURA_API_VERSION_MINOR 0
#define AURA_API_VERSION_PATCH 0

#define AURA_DEFAULT_ONE_TIME_KEY_COUNT 100
#define AURA_LIBRARY_VERSION "3.0.0"

typedef enum {
    AURA_SUCCESS = 0,
    AURA_ERROR_GENERIC = 1,
    AURA_ERROR_INVALID_INPUT = 2,
    AURA_ERROR_KEY_GENERATION = 3,
    AURA_ERROR_DERIVE_KEY = 4,
    AURA_ERROR_HANDSHAKE = 5,
    AURA_ERROR_ENCRYPTION = 6,
    AURA_ERROR_DECRYPTION = 7,
    AURA_ERROR_DECODE = 8,
    AURA_ERROR_ENCODE = 9,
    AURA_ERROR_BUFFER_TOO_SMALL = 10,
    AURA_ERROR_OBJECT_DISPOSED = 11,
    AURA_ERROR_PREPARE_LOCAL = 12,
    AURA_ERROR_OUT_OF_MEMORY = 13,
    AURA_ERROR_CRYPTO_FAILURE = 14,
    AURA_ERROR_NULL_POINTER = 15,
    AURA_ERROR_INVALID_STATE = 16,
    AURA_ERROR_REPLAY_ATTACK = 17,
    AURA_ERROR_SESSION_EXPIRED = 18,
    AURA_ERROR_PQ_MISSING = 19,
    AURA_ERROR_GROUP_PROTOCOL = 20,
    AURA_ERROR_GROUP_MEMBERSHIP = 21,
    AURA_ERROR_TREE_INTEGRITY = 22,
    AURA_ERROR_WELCOME = 23,
    AURA_ERROR_MESSAGE_EXPIRED = 24,
    AURA_ERROR_FRANKING = 25,
    AURA_ERROR_VOIP_CALL = 26,
    AURA_ERROR_VOIP_MEDIA = 27,
    AURA_ERROR_VOIP_REKEY = 28,
    AURA_ERROR_BUSY = 29
} AuraErrorCode;

typedef struct AuraError {
    AuraErrorCode code;
    char* message;
} AuraError;

/* Owned byte buffer returned from Rust. Must be released with aura_buffer_release(). */
typedef struct AuraBuffer {
    uint8_t* data;
    size_t length;
} AuraBuffer;

typedef enum {
    AURA_ENVELOPE_REQUEST = 0,
    AURA_ENVELOPE_RESPONSE = 1,
    AURA_ENVELOPE_NOTIFICATION = 2,
    AURA_ENVELOPE_HEARTBEAT = 3,
    AURA_ENVELOPE_ERROR_RESPONSE = 4
} AuraEnvelopeType;

/* Library lifecycle */
AURA_API const char* aura_version(void);
AURA_API AuraErrorCode aura_init(void);
AURA_API void aura_shutdown(void);

/*
 * Wire protocol versions this build speaks.
 *
 * Distinct from aura_version(), which reports the library's semver string.
 * Peers and stored blobs are accepted only on an exact match, so a host can
 * pre-flight compatibility instead of discovering a mismatch as a decrypt
 * failure.
 */
AURA_API uint32_t aura_protocol_version(void);
AURA_API uint32_t aura_group_protocol_version(void);

/* Error utilities */
AURA_API void aura_error_free(AuraError* error);
AURA_API const char* aura_error_string(AuraErrorCode code);

/* Buffer utilities */
AURA_API void aura_buffer_release(AuraBuffer* buffer);
AURA_API AuraBuffer* aura_buffer_alloc(size_t capacity);
AURA_API void aura_buffer_free(AuraBuffer* buffer);

/* Secure memory wipe */
AURA_API AuraErrorCode aura_secure_wipe(uint8_t* data, size_t length);

#ifdef __cplusplus
}
#endif
