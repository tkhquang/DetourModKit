#ifndef DETOURMODKIT_EXAMPLES_STAGED_RELOAD_PROTOCOL_H
#define DETOURMODKIT_EXAMPLES_STAGED_RELOAD_PROTOCOL_H

#include "DetourModKit/abi/wheel_host.h"

#include <stdint.h>

/** @brief ABI revision for the staged-reload example request. */
#define DMK_STAGED_RELOAD_ABI_VERSION 2u

/** @brief A live Init result or a retired Shutdown result with no retained resources. */
#define DMK_STAGED_RELOAD_OK 1u

/** @brief A retired Shutdown result that requires the loader to retain its module reference. */
#define DMK_STAGED_RELOAD_RETAINED 2u

/**
 * @struct StagedReloadInitRequest
 * @brief Fixed-width request passed from the resident loader to one logic generation.
 */
typedef struct StagedReloadInitRequest
{
    /** @brief The request size known to the loader. */
    uint32_t struct_size;
    /** @brief The request ABI revision. */
    uint32_t abi_version;
    /** @brief The loader-assigned generation id. */
    uint64_t generation_id;
    /** @brief The identity expected in wheel_host. */
    uint64_t expected_host_identity;
    /** @brief The process-lifetime resident host table. */
    const WheelHostTable *wheel_host;
} StagedReloadInitRequest;

#endif /* DETOURMODKIT_EXAMPLES_STAGED_RELOAD_PROTOCOL_H */
