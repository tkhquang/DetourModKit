/* This build-tree consumer compiles the versioned staged-reload ABI header as C and verifies each value. */
#include <DetourModKit/abi/staged_reload.h>

typedef char StagedReloadAbiVersionCheck[DMK_STAGED_RELOAD_ABI_VERSION == 3u ? 1 : -1];
typedef char StagedReloadRefusedCheck[DMK_STAGED_RELOAD_REFUSED == 0u ? 1 : -1];
typedef char StagedReloadOkCheck[DMK_STAGED_RELOAD_OK == 1u ? 1 : -1];
typedef char StagedReloadRetainedCheck[DMK_STAGED_RELOAD_RETAINED == 2u ? 1 : -1];
typedef char StagedReloadBusyCheck[DMK_STAGED_RELOAD_BUSY == 3u ? 1 : -1];
typedef char StagedReloadRestartRequiredCheck[DMK_STAGED_RELOAD_RESTART_REQUIRED == 4u ? 1 : -1];

int dmk_staged_reload_c_probe(unsigned int abi_version, unsigned int result)
{
    if (abi_version != DMK_STAGED_RELOAD_ABI_VERSION)
    {
        return 0;
    }
    switch (result)
    {
    case DMK_STAGED_RELOAD_OK:
        return 1;
    case DMK_STAGED_RELOAD_REFUSED:
    case DMK_STAGED_RELOAD_RETAINED:
    case DMK_STAGED_RELOAD_BUSY:
    case DMK_STAGED_RELOAD_RESTART_REQUIRED:
    default:
        return 0;
    }
}
