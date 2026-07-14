#include <windows.h>

namespace
{
    constexpr DWORD PROBE_WAIT_MS{600000};
} // namespace

int main()
{
    // The verifier's two-second budget must expire before this fallback wait.
    Sleep(PROBE_WAIT_MS);
    return 0;
}
