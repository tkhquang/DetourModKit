// Fast-failing control probe for CTestTimeoutControlNegative. With no argument it exits nonzero immediately, so the
// verifier must reject the result as a non-timeout failure. The release soak's explicit wer-crash mode instead dies
// by a native access violation: the termination class the lifecycle processes crash with, and the class WER
// LocalDumps collection documents capturing. A fail-fast raise does not reach that collection path on hosted
// runners.

#include <string_view>

int main(int argc, char *argv[])
{
    if (argc == 2 && std::string_view{argv[1]} == "wer-crash")
    {
        // The pointer itself is volatile, so neither compiler can prove the store faults and lower it to a trap
        // instruction; the exit status must be STATUS_ACCESS_VIOLATION, not STATUS_ILLEGAL_INSTRUCTION.
        volatile int *volatile target = nullptr;
        *target = 0x2A;
        return 2;
    }

    return argc == 1 ? 1 : 2;
}
