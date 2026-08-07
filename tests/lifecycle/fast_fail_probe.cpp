// Fast-failing control probe for CTestTimeoutControlNegative. With no argument it exits nonzero immediately, so the
// verifier must reject the result as a non-timeout failure. The release soak's explicit wer-crash mode instead raises
// a native fail-fast exception to prove Windows Error Reporting can capture the lifecycle processes before the soak.

#include <windows.h>

#include <string_view>

int main(int argc, char *argv[])
{
    if (argc == 2 && std::string_view{argv[1]} == "wer-crash")
    {
        ::RaiseFailFastException(nullptr, nullptr, 0);
        return 2;
    }

    return argc == 1 ? 1 : 2;
}
