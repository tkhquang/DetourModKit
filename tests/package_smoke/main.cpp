#include <DetourModKit.hpp>

int main()
{
    static_assert(DMK_VERSION_AT_LEAST(0, 0, 0));

    // Document the canonical null spelling as a compile-time contract. Address deliberately has no implicit
    // integer constructor, so a bare `0` is ambiguous between the uintptr_t and nullptr_t constructors and must
    // not be used; `Address{}` (or `Address{nullptr}`) is the null address. Keeping this here means the smoke also
    // guards that ergonomics decision against regression from a consumer's toolchain.
    static_assert(DetourModKit::Address{}.raw() == 0, "Address{} must be the null address.");

    if (DetourModKit::hook::is_target_hooked(DetourModKit::Address{}))
    {
        return 1;
    }

    // Exercise the v4 lifecycle surface end to end: start a Session for the current process (no gate, no
    // single-instance guard), then let it destruct to run the ordered teardown. This links the whole Session +
    // subsystem-teardown path.
    if (auto session = DetourModKit::Session::start(DetourModKit::ModInfo{}); !session.has_value())
    {
        return 2;
    }
    // ~Session ran the ordered teardown when `session` left the if-statement scope.
    return 0;
}
