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
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    (void)hModule;
    (void)ul_reason_for_call;
    (void)lpReserved;
    return TRUE;
}
