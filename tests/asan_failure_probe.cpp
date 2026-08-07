#include <cstddef>
#include <memory>

int main()
{
    const auto allocation = std::make_unique<std::byte[]>(8);
    volatile std::byte *const bytes = allocation.get();

    // Index eight is the deliberate fault: a capable instrumented run reports a heap-buffer-overflow and exits red.
    bytes[8] = std::byte{0x41};
    return 0;
}
