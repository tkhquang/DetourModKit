#ifndef DETOURMODKIT_EXAMPLES_STAGED_RELOAD_PROTOCOL_H
#define DETOURMODKIT_EXAMPLES_STAGED_RELOAD_PROTOCOL_H

#include "DetourModKit/abi/wheel_host.h"

#include <stdint.h>

/** @brief ABI revision for the staged-reload example request. */
#define DMK_STAGED_RELOAD_ABI_VERSION 1u

/** @brief Success value for staged logic exports. */
#define DMK_STAGED_RELOAD_OK 1u

/**
 * @struct DmkStagedReloadInitRequest
 * @brief Fixed-width request passed from the resident loader to one logic generation.
 */
typedef struct DmkStagedReloadInitRequest
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
    const DmkWheelHostTable *wheel_host;
} DmkStagedReloadInitRequest;

#endif /* DETOURMODKIT_EXAMPLES_STAGED_RELOAD_PROTOCOL_H */
