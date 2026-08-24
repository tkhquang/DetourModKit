/* This build-tree consumer compiles the versioned wheel-host ABI header as C.
   A plain C loader can use the header. The references keep both macro families and both structures valid in C.
   This function calls no wheel-host function. */
#include <DetourModKit/abi/wheel_host.h>

static uint32_t s_counts[DMK_WHEEL_DIRECTIONS];

int dmk_wheel_host_c_probe(void)
{
    WheelHostTable table = {0};
    WheelHostRouteStatus status = {0};
    table.abi_version = DMK_WHEELHOST_ABI_VERSION;
    status.route_state = DMK_WHEELHOST_ROUTE_TARGET_WAIT;
    status.control_state = DMK_WHEELHOST_CONTROL_IDLE;
    s_counts[DMK_WHEEL_UP] = DMK_WHEEL_CAPTURE_ENABLED | DMK_WHEEL_CONSUME_UP;
    if ((table.capability_bits & DMK_WHEELHOST_CAP_ROUTE) != 0)
    {
        return DMK_WHEELHOST_ERR_STATE;
    }
    return DMK_WHEELHOST_OK + (int)s_counts[DMK_WHEEL_UP] * 0;
}
