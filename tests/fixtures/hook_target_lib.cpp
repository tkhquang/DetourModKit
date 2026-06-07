#include <windows.h>

extern "C"
{
    __declspec(dllexport) __declspec(noinline) int compute_damage(int base, int modifier)
    {
        volatile int magic = 0xDEAD;
        volatile int result = base + modifier + (magic - magic);
        return result;
    }

    __declspec(dllexport) __declspec(noinline) int compute_armor(int defense, int level)
    {
        volatile int magic = 0xBEEF;
        volatile int result = defense * level + (magic - magic);
        return result;
    }

    __declspec(dllexport) __declspec(noinline) int compute_speed(int agility, int bonus)
    {
        volatile int magic = 0xCAFE;
        volatile int result = agility - bonus + (magic - magic);
        return result;
    }

    __declspec(dllexport) __declspec(noinline) int compute_critical(int power, int luck)
    {
        volatile int magic = 0xF00D;
        volatile int result = power + luck * 2 + (magic - magic);
        return result;
    }

    // A fixed, unique byte signature that lands in the DLL's read-only data
    // section. Module-scoped scanner tests resolve it to verify that a single
    // module-range scan reaches .rdata (no separate Readable kind needed) and
    // that the resolved address falls inside the DLL image. The bytes are
    // arbitrary and chosen not to collide with real code or string content.
    // `extern` forces external linkage: a namespace-scope `const` defaults to
    // internal linkage in C++, which dllexport cannot apply to.
    __declspec(dllexport) extern const unsigned char dmk_scan_marker[16] = {
        0xA7, 0x3C, 0xF1, 0x88, 0x5E, 0x22, 0xD9, 0x04,
        0x6B, 0xB0, 0x1F, 0x97, 0x4A, 0xE3, 0x7D, 0x50};
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    (void)hModule;
    (void)ul_reason_for_call;
    (void)lpReserved;
    return TRUE;
}
