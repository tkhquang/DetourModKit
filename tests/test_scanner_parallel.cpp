#include <gtest/gtest.h>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>
#include <string>
#include <vector>

#include "DetourModKit/memory.hpp"
#include "DetourModKit/scanner.hpp"

#include <windows.h>

using namespace DetourModKit;

// The parallel batch scanner (scanner_parallel.cpp) is a fork-join wrapper over the serial scanners: each item is one
// independent serial scan distributed across worker threads. These tests cover input-order preservation, the per-item
// fail-closed behaviour (null / empty / zero-occurrence / no-match), ScannerKind selection, module-range confinement,
// the worker-count knob, and a many-pattern equivalence sweep that exercises the concurrent path. A separate suite from
// test_scanner.cpp keeps the threading concerns isolated, mirroring the deliberate test_memory_chain.cpp split.

namespace
{
    /**
     * @brief Builds a 16-byte signature derived from a seed.
     * @details An LCG fill spreads the bytes so each seed yields a distinct sequence that is astronomically unlikely to
     *          collide elsewhere in process memory, the same property the hand-written signatures in test_scanner.cpp
     *          rely on.
     */
    std::array<std::byte, 16> make_unique_sig(std::uint32_t seed) noexcept
    {
        std::array<std::byte, 16> sig{};
        std::uint32_t state = 0x9E3779B1u ^ (seed * 0x85EBCA77u + 0xC2B2AE3Du);
        for (auto &b : sig)
        {
            state = state * 1664525u + 1013904223u;
            b = std::byte{static_cast<std::uint8_t>((state >> 24) & 0xFFu)};
        }
        return sig;
    }

    /// Renders a byte span as a space-separated uppercase-hex AOB string for parse_aob.
    std::string sig_to_aob(std::span<const std::byte> sig)
    {
        static constexpr char digits[] = "0123456789ABCDEF";
        std::string out;
        out.reserve(sig.size() * 3);
        for (const std::byte b : sig)
        {
            const auto value = std::to_integer<unsigned>(b);
            out.push_back(digits[(value >> 4) & 0xFu]);
            out.push_back(digits[value & 0xFu]);
            out.push_back(' ');
        }
        return out;
    }

    /// RAII committed page; frees on scope exit so a test never leaks a reserved range.
    struct CommittedPage
    {
        void *base = nullptr;
        std::size_t size = 0;

        CommittedPage(std::size_t bytes, DWORD protect)
            : base(VirtualAlloc(nullptr, bytes, MEM_COMMIT | MEM_RESERVE, protect)), size(bytes)
        {
        }
        ~CommittedPage() noexcept
        {
            if (base != nullptr)
            {
                VirtualFree(base, 0, MEM_RELEASE);
            }
        }
        CommittedPage(const CommittedPage &) = delete;
        CommittedPage &operator=(const CommittedPage &) = delete;
        CommittedPage(CommittedPage &&) = delete;
        CommittedPage &operator=(CommittedPage &&) = delete;

        [[nodiscard]] std::byte *bytes() const noexcept { return reinterpret_cast<std::byte *>(base); }
    };
} // namespace

TEST(ScannerBatchTest, EmptyBatchReturnsEmpty)
{
    const std::vector<Scanner::BatchScanItem> items;
    const auto results = Scanner::scan_regions_batch(items);
    EXPECT_TRUE(results.empty());
}

TEST(ScannerBatchTest, ResolvesEachItemInExecutableMemory)
{
    CommittedPage page(4096, PAGE_EXECUTE_READWRITE);
    ASSERT_NE(page.base, nullptr);
    std::memset(page.bytes(), 0xCC, page.size);

    constexpr std::size_t PATTERN_COUNT = 3;
    std::vector<Scanner::CompiledPattern> patterns;
    patterns.reserve(PATTERN_COUNT);
    std::array<const std::byte *, PATTERN_COUNT> planted{};

    for (std::size_t i = 0; i < PATTERN_COUNT; ++i)
    {
        const auto sig = make_unique_sig(static_cast<std::uint32_t>(i + 1));
        std::byte *target = page.bytes() + 200 + i * 512;
        std::memcpy(target, sig.data(), sig.size());
        planted[i] = target;
        auto compiled = Scanner::parse_aob(sig_to_aob(sig));
        ASSERT_TRUE(compiled.has_value());
        patterns.push_back(std::move(*compiled));
    }

    std::vector<Scanner::BatchScanItem> items;
    items.reserve(PATTERN_COUNT);
    for (const auto &pattern : patterns)
    {
        items.push_back(Scanner::BatchScanItem{&pattern, 1});
    }

    const auto results = Scanner::scan_regions_batch(items, Scanner::ScannerKind::Executable);
    ASSERT_EQ(results.size(), PATTERN_COUNT);
    for (std::size_t i = 0; i < PATTERN_COUNT; ++i)
    {
        EXPECT_EQ(results[i], planted[i]);
        // Each batch result must agree with the serial scanner for the same pattern.
        EXPECT_EQ(results[i], Scanner::scan_executable_regions(patterns[i], 1));
    }
}

TEST(ScannerBatchTest, PreservesInputOrderRegardlessOfAddressOrder)
{
    CommittedPage page(4096, PAGE_EXECUTE_READWRITE);
    ASSERT_NE(page.base, nullptr);
    std::memset(page.bytes(), 0xCC, page.size);

    // Item 0's match sits at a HIGH address, item 1's at a LOW address, so result order tracks input order, not the
    // address order a single sweep would surface.
    const auto sig_high = make_unique_sig(101);
    const auto sig_low = make_unique_sig(202);
    std::byte *high_target = page.bytes() + 2048;
    std::byte *low_target = page.bytes() + 64;
    std::memcpy(high_target, sig_high.data(), sig_high.size());
    std::memcpy(low_target, sig_low.data(), sig_low.size());

    auto pattern_high = Scanner::parse_aob(sig_to_aob(sig_high));
    auto pattern_low = Scanner::parse_aob(sig_to_aob(sig_low));
    ASSERT_TRUE(pattern_high.has_value());
    ASSERT_TRUE(pattern_low.has_value());

    const std::vector<Scanner::BatchScanItem> items{Scanner::BatchScanItem{&*pattern_high, 1},
                                                    Scanner::BatchScanItem{&*pattern_low, 1}};
    const auto results = Scanner::scan_regions_batch(items);
    ASSERT_EQ(results.size(), 2u);
    EXPECT_EQ(results[0], high_target);
    EXPECT_EQ(results[1], low_target);
}

TEST(ScannerBatchTest, NullPatternItemFailsClosedWithoutAffectingNeighbours)
{
    CommittedPage page(4096, PAGE_EXECUTE_READWRITE);
    ASSERT_NE(page.base, nullptr);
    std::memset(page.bytes(), 0xCC, page.size);

    const auto sig = make_unique_sig(303);
    std::byte *target = page.bytes() + 128;
    std::memcpy(target, sig.data(), sig.size());
    auto pattern = Scanner::parse_aob(sig_to_aob(sig));
    ASSERT_TRUE(pattern.has_value());

    const std::vector<Scanner::BatchScanItem> items{Scanner::BatchScanItem{nullptr, 1},
                                                    Scanner::BatchScanItem{&*pattern, 1}};
    const auto results = Scanner::scan_regions_batch(items);
    ASSERT_EQ(results.size(), 2u);
    EXPECT_EQ(results[0], nullptr); // null pattern fails closed
    EXPECT_EQ(results[1], target);  // neighbour still resolves
}

TEST(ScannerBatchTest, EmptyPatternItemFailsClosedWithoutAffectingNeighbours)
{
    CommittedPage page(4096, PAGE_EXECUTE_READWRITE);
    ASSERT_NE(page.base, nullptr);
    std::memset(page.bytes(), 0xCC, page.size);

    const auto sig = make_unique_sig(707);
    std::byte *target = page.bytes() + 128;
    std::memcpy(target, sig.data(), sig.size());
    auto valid = Scanner::parse_aob(sig_to_aob(sig));
    ASSERT_TRUE(valid.has_value());

    // A non-null but empty (size() == 0) pattern is a distinct path from the null-pointer item: the batch driver
    // passes it to the serial scanner, whose pattern.empty() guard fails it closed. The neighbour must be unaffected.
    const Scanner::CompiledPattern empty_pattern{};
    ASSERT_TRUE(empty_pattern.empty());

    const std::vector<Scanner::BatchScanItem> items{Scanner::BatchScanItem{&empty_pattern, 1},
                                                    Scanner::BatchScanItem{&*valid, 1}};
    const auto results = Scanner::scan_regions_batch(items);
    ASSERT_EQ(results.size(), 2u);
    EXPECT_EQ(results[0], nullptr); // empty pattern fails closed
    EXPECT_EQ(results[1], target);  // neighbour still resolves
}

TEST(ScannerBatchTest, ZeroOccurrenceAndMissingPatternFailClosed)
{
    CommittedPage page(4096, PAGE_EXECUTE_READWRITE);
    ASSERT_NE(page.base, nullptr);
    std::memset(page.bytes(), 0xCC, page.size);

    const auto sig = make_unique_sig(404);
    std::memcpy(page.bytes() + 256, sig.data(), sig.size());
    auto present = Scanner::parse_aob(sig_to_aob(sig));
    // A signature that is planted nowhere in the process.
    auto absent = Scanner::parse_aob("FE ED FA CE DE AD BE EF CA FE BA BE 01 02 03 04");
    ASSERT_TRUE(present.has_value());
    ASSERT_TRUE(absent.has_value());

    const std::vector<Scanner::BatchScanItem> items{Scanner::BatchScanItem{&*present, 0}, // occurrence 0
                                                    Scanner::BatchScanItem{&*absent, 1}}; // never present
    const auto results = Scanner::scan_regions_batch(items);
    ASSERT_EQ(results.size(), 2u);
    EXPECT_EQ(results[0], nullptr);
    EXPECT_EQ(results[1], nullptr);
}

TEST(ScannerBatchTest, HonoursPerItemOccurrence)
{
    CommittedPage page(4096, PAGE_EXECUTE_READWRITE);
    ASSERT_NE(page.base, nullptr);
    std::memset(page.bytes(), 0x00, page.size);

    const auto sig = make_unique_sig(505);
    std::byte *first = page.bytes() + 100;
    std::byte *second = page.bytes() + 900;
    std::memcpy(first, sig.data(), sig.size());
    std::memcpy(second, sig.data(), sig.size());
    auto pattern = Scanner::parse_aob(sig_to_aob(sig));
    ASSERT_TRUE(pattern.has_value());

    const std::vector<Scanner::BatchScanItem> items{Scanner::BatchScanItem{&*pattern, 1},
                                                    Scanner::BatchScanItem{&*pattern, 2}};
    const auto results = Scanner::scan_regions_batch(items);
    ASSERT_EQ(results.size(), 2u);
    EXPECT_EQ(results[0], first);
    EXPECT_EQ(results[1], second);
}

TEST(ScannerBatchTest, ReadableKindSeesDataOnlyPatternExecutableKindDoesNot)
{
    CommittedPage page(4096, PAGE_READWRITE);
    ASSERT_NE(page.base, nullptr);
    std::memset(page.bytes(), 0x00, page.size);

    const auto sig = make_unique_sig(606);
    std::memcpy(page.bytes() + 64, sig.data(), sig.size());
    auto pattern = Scanner::parse_aob(sig_to_aob(sig));
    ASSERT_TRUE(pattern.has_value());

    const std::vector<Scanner::BatchScanItem> items{Scanner::BatchScanItem{&*pattern, 1}};

    // A data-only (non-executable) page is invisible to the executable sweep.
    const auto exec_results = Scanner::scan_regions_batch(items, Scanner::ScannerKind::Executable);
    ASSERT_EQ(exec_results.size(), 1u);
    EXPECT_EQ(exec_results[0], nullptr);

    // The readable sweep reaches it (it may find the planted page or another readable copy of the sequence, so only
    // non-null is asserted, not the exact address).
    const auto read_results = Scanner::scan_regions_batch(items, Scanner::ScannerKind::Readable);
    ASSERT_EQ(read_results.size(), 1u);
    EXPECT_NE(read_results[0], nullptr);
}

TEST(ScannerBatchTest, WorkerCountKnobYieldsIdenticalResults)
{
    CommittedPage page(64 * 1024, PAGE_EXECUTE_READWRITE);
    ASSERT_NE(page.base, nullptr);
    std::memset(page.bytes(), 0xCC, page.size);

    constexpr std::size_t PATTERN_COUNT = 16;
    std::vector<Scanner::CompiledPattern> patterns;
    patterns.reserve(PATTERN_COUNT);
    std::array<const std::byte *, PATTERN_COUNT> planted{};
    for (std::size_t i = 0; i < PATTERN_COUNT; ++i)
    {
        const auto sig = make_unique_sig(static_cast<std::uint32_t>(1000 + i));
        std::byte *target = page.bytes() + 256 + i * 1024;
        std::memcpy(target, sig.data(), sig.size());
        planted[i] = target;
        auto compiled = Scanner::parse_aob(sig_to_aob(sig));
        ASSERT_TRUE(compiled.has_value());
        patterns.push_back(std::move(*compiled));
    }

    std::vector<Scanner::BatchScanItem> items;
    items.reserve(PATTERN_COUNT);
    for (const auto &pattern : patterns)
    {
        items.push_back(Scanner::BatchScanItem{&pattern, 1});
    }

    // The result is independent of how many workers the batch uses: serial (1), a fixed pool (4), and a count far
    // exceeding the item count (clamped) must all agree, item for item, with the planted addresses.
    for (const std::size_t workers : {std::size_t{1}, std::size_t{4}, std::size_t{1024}, std::size_t{0}})
    {
        const auto results = Scanner::scan_regions_batch(items, Scanner::ScannerKind::Executable, workers);
        ASSERT_EQ(results.size(), PATTERN_COUNT) << "workers=" << workers;
        for (std::size_t i = 0; i < PATTERN_COUNT; ++i)
        {
            EXPECT_EQ(results[i], planted[i]) << "workers=" << workers << " item=" << i;
        }
    }
}

TEST(ScannerBatchTest, ModuleBatchConfinesToRangeAndResolvesEachItem)
{
    CommittedPage page(64 * 1024, PAGE_EXECUTE_READWRITE);
    ASSERT_NE(page.base, nullptr);
    std::memset(page.bytes(), 0xCC, page.size);

    constexpr std::size_t PATTERN_COUNT = 8;
    std::vector<Scanner::CompiledPattern> patterns;
    patterns.reserve(PATTERN_COUNT);
    std::array<const std::byte *, PATTERN_COUNT> planted{};
    for (std::size_t i = 0; i < PATTERN_COUNT; ++i)
    {
        const auto sig = make_unique_sig(static_cast<std::uint32_t>(2000 + i));
        std::byte *target = page.bytes() + 128 + i * 2048;
        std::memcpy(target, sig.data(), sig.size());
        planted[i] = target;
        auto compiled = Scanner::parse_aob(sig_to_aob(sig));
        ASSERT_TRUE(compiled.has_value());
        patterns.push_back(std::move(*compiled));
    }

    std::vector<Scanner::BatchScanItem> items;
    items.reserve(PATTERN_COUNT);
    for (const auto &pattern : patterns)
    {
        items.push_back(Scanner::BatchScanItem{&pattern, 1});
    }

    const auto base = reinterpret_cast<std::uintptr_t>(page.base);
    const Memory::ModuleRange range{base, base + page.size};

    // Range-scoped: the only copy of each sig inside [base, base + size) is the planted one, so the match is exact.
    const auto results = Scanner::scan_module_batch(items, range, Scanner::ScannerKind::Readable);
    ASSERT_EQ(results.size(), PATTERN_COUNT);
    for (std::size_t i = 0; i < PATTERN_COUNT; ++i)
    {
        EXPECT_EQ(results[i], planted[i]) << "item=" << i;
    }
}

TEST(ScannerBatchTest, ModuleBatchInvalidRangeFailsClosed)
{
    auto pattern = Scanner::parse_aob(sig_to_aob(make_unique_sig(3000)));
    ASSERT_TRUE(pattern.has_value());

    const std::vector<Scanner::BatchScanItem> items{Scanner::BatchScanItem{&*pattern, 1},
                                                    Scanner::BatchScanItem{&*pattern, 1}};
    const Memory::ModuleRange invalid{}; // base == end == 0 => valid() is false
    const auto results = Scanner::scan_module_batch(items, invalid);
    ASSERT_EQ(results.size(), 2u);
    EXPECT_EQ(results[0], nullptr);
    EXPECT_EQ(results[1], nullptr);
}

TEST(ScannerBatchTest, CascadeBatchEmptyReturnsEmpty)
{
    const std::vector<Scanner::CascadeRequest> requests;
    const auto results = Scanner::resolve_cascade_batch(requests);
    EXPECT_EQ(results.size(), 0u);
}

TEST(ScannerBatchTest, CascadeBatchMatchesSerialResolvers)
{
    CommittedPage code_page(64 * 1024, PAGE_EXECUTE_READWRITE);
    ASSERT_NE(code_page.base, nullptr);
    std::memset(code_page.bytes(), 0xCC, code_page.size);

    const auto sig_a = make_unique_sig(4000);
    const auto sig_b = make_unique_sig(4001);
    std::byte *target_a = code_page.bytes() + 512;
    std::byte *target_b = code_page.bytes() + 4096;
    std::memcpy(target_a, sig_a.data(), sig_a.size());
    std::memcpy(target_b, sig_b.data(), sig_b.size());

    const std::string aob_a = sig_to_aob(sig_a);
    const std::string aob_b = sig_to_aob(sig_b);

    Scanner::AddrCandidate cands_a[] = {
        {"module-a", aob_a, Scanner::ResolveMode::Direct, 0, 0},
    };
    Scanner::AddrCandidate cands_b[] = {
        {"module-b", aob_b, Scanner::ResolveMode::Direct, 0, 0},
    };

    const auto base = reinterpret_cast<std::uintptr_t>(code_page.base);
    const Memory::ModuleRange range{base, base + code_page.size};

    Scanner::CascadeRequest module_request{};
    module_request.candidates = cands_a;
    module_request.label = "module-a";
    module_request.range = range;

    Scanner::CascadeRequest fallback_request{};
    fallback_request.candidates = cands_b;
    fallback_request.label = "module-b-fallback";
    fallback_request.range = range;
    fallback_request.prologue_fallback = true;

    Scanner::CascadeRequest whole_process_request{};
    whole_process_request.candidates = cands_b;
    whole_process_request.label = "whole-process-b";

    Scanner::CascadeRequest empty_request{};
    empty_request.label = "empty";

    Scanner::CascadeRequest invalid_range_request{};
    invalid_range_request.candidates = cands_a;
    invalid_range_request.label = "invalid-range";
    invalid_range_request.range = Memory::ModuleRange{};

    const std::vector<Scanner::CascadeRequest> requests{module_request, fallback_request, whole_process_request,
                                                        empty_request, invalid_range_request};

    const auto results = Scanner::resolve_cascade_batch(requests, 4);
    ASSERT_EQ(results.size(), requests.size());

    const auto serial_module = Scanner::resolve_cascade_in_module(cands_a, "module-a", range);
    const auto serial_fallback =
        Scanner::resolve_cascade_in_module_with_prologue_fallback(cands_b, "module-b-fallback", range);
    const auto serial_whole = Scanner::resolve_cascade(cands_b, "whole-process-b");

    ASSERT_TRUE(results[0].has_value());
    ASSERT_TRUE(serial_module.has_value());
    EXPECT_EQ(results[0]->address, serial_module->address);
    EXPECT_EQ(results[0]->winning_name, serial_module->winning_name);
    EXPECT_EQ(results[0]->address, reinterpret_cast<std::uintptr_t>(target_a));

    ASSERT_TRUE(results[1].has_value());
    ASSERT_TRUE(serial_fallback.has_value());
    EXPECT_EQ(results[1]->address, serial_fallback->address);
    EXPECT_EQ(results[1]->winning_name, serial_fallback->winning_name);
    EXPECT_EQ(results[1]->address, reinterpret_cast<std::uintptr_t>(target_b));

    ASSERT_TRUE(results[2].has_value());
    ASSERT_TRUE(serial_whole.has_value());
    EXPECT_EQ(results[2]->address, serial_whole->address);
    EXPECT_EQ(results[2]->winning_name, serial_whole->winning_name);
    EXPECT_EQ(results[2]->address, reinterpret_cast<std::uintptr_t>(target_b));

    ASSERT_FALSE(results[3].has_value());
    EXPECT_EQ(results[3].error(), Scanner::ResolveError::EmptyCandidates);

    ASSERT_FALSE(results[4].has_value());
    EXPECT_EQ(results[4].error(), Scanner::ResolveError::InvalidRange);
}

TEST(ScannerBatchTest, CascadeBatchWorkerCountYieldsIdenticalResults)
{
    CommittedPage code_page(64 * 1024, PAGE_EXECUTE_READWRITE);
    ASSERT_NE(code_page.base, nullptr);
    std::memset(code_page.bytes(), 0xCC, code_page.size);

    constexpr std::size_t REQUEST_COUNT = 16;
    const auto base = reinterpret_cast<std::uintptr_t>(code_page.base);
    const Memory::ModuleRange range{base, base + code_page.size};

    // Caller-owned storage the requests alias; it must outlive resolve_cascade_batch, so it lives in the test frame and
    // is sized up front (never reallocated) so the spans and string_views stay valid.
    std::vector<std::string> labels(REQUEST_COUNT);
    std::vector<std::string> aobs(REQUEST_COUNT);
    std::vector<Scanner::AddrCandidate> candidates(REQUEST_COUNT);
    std::vector<Scanner::CascadeRequest> requests(REQUEST_COUNT);
    std::array<std::uintptr_t, REQUEST_COUNT> planted{};

    for (std::size_t i = 0; i < REQUEST_COUNT; ++i)
    {
        const auto sig = make_unique_sig(static_cast<std::uint32_t>(6000 + i));
        std::byte *target = code_page.bytes() + 512 + i * 1024;
        std::memcpy(target, sig.data(), sig.size());
        planted[i] = reinterpret_cast<std::uintptr_t>(target);
        labels[i] = "cascade_" + std::to_string(i);
        aobs[i] = sig_to_aob(sig);
        candidates[i] = Scanner::AddrCandidate{labels[i], aobs[i], Scanner::ResolveMode::Direct, 0, 0};
        requests[i].candidates = std::span<const Scanner::AddrCandidate>(&candidates[i], 1);
        requests[i].label = labels[i];
        requests[i].range = range;
    }

    // The concurrent cascade resolver must agree with the planted addresses item for item, and that agreement must be
    // independent of the worker count: serial (1), a fixed pool (4), an over-count clamp (1024), and auto (0). This
    // sweep drives many requests through the shared fork-join driver to exercise the work-stealing concurrent path.
    for (const std::size_t workers : {std::size_t{1}, std::size_t{4}, std::size_t{1024}, std::size_t{0}})
    {
        const auto results = Scanner::resolve_cascade_batch(requests, workers);
        ASSERT_EQ(results.size(), REQUEST_COUNT) << "workers=" << workers;
        for (std::size_t i = 0; i < REQUEST_COUNT; ++i)
        {
            ASSERT_TRUE(results[i].has_value()) << "workers=" << workers << " item=" << i;
            EXPECT_EQ(results[i]->address, planted[i]) << "workers=" << workers << " item=" << i;
            EXPECT_EQ(results[i]->winning_name, labels[i]) << "workers=" << workers << " item=" << i;
        }
    }
}

// A CascadeRequest carrying a name/string resilience tier resolves identically through the fork-join batch path and the
// serial resolver, confirming resolve_cascade_batch uses the same mode dispatch as the serial path. StringXref is the
// representative tier: find_string_xref is the non-noexcept backend, so this also exercises that the throwing dispatch
// runs safely on a worker thread. The fixture is an RWX page holding one literal and one RIP-relative lea reference to
// it.
TEST(ScannerBatchTest, CascadeBatchResolvesStringXrefTierLikeSerial)
{
    // Zero-fill: a 0x00 byte both terminates the planted literal and never starts a RIP-relative load.
    CommittedPage image(4096, PAGE_EXECUTE_READWRITE);
    ASSERT_NE(image.base, nullptr);
    std::memset(image.bytes(), 0x00, image.size);

    constexpr std::size_t STR_OFF = 0x100;
    constexpr std::size_t LEA_OFF = 0x040;
    const char literal[] = "BatchStringXrefAnchorLiteral";
    std::memcpy(image.bytes() + STR_OFF, literal, sizeof(literal)); // sizeof includes the NUL terminator

    // lea rax, [rip+str]: 48 8D 05 <disp32>, the canonical narrow-scan string-load shape.
    auto *insn = reinterpret_cast<std::uint8_t *>(image.bytes() + LEA_OFF);
    insn[0] = 0x48;
    insn[1] = 0x8D;
    insn[2] = 0x05;
    const auto base = reinterpret_cast<std::uintptr_t>(image.base);
    const auto next = static_cast<std::int64_t>(base + LEA_OFF + 7);
    const auto disp = static_cast<std::int32_t>(static_cast<std::int64_t>(base + STR_OFF) - next);
    std::memcpy(insn + 3, &disp, sizeof(disp));

    const Memory::ModuleRange range{base, base + image.size};

    Scanner::AddrCandidate cands[] = {
        {"string-tier", "BatchStringXrefAnchorLiteral", Scanner::ResolveMode::StringXref},
    };

    Scanner::CascadeRequest request{};
    request.candidates = cands;
    request.label = "string-tier";
    request.range = range;

    const std::vector<Scanner::CascadeRequest> requests{request};
    const auto results = Scanner::resolve_cascade_batch(requests, 2);
    ASSERT_EQ(results.size(), 1u);

    const auto serial = Scanner::resolve_cascade_in_module(cands, "string-tier", range);
    ASSERT_TRUE(serial.has_value());
    ASSERT_TRUE(results[0].has_value());
    EXPECT_EQ(results[0]->address, serial->address);
    EXPECT_EQ(results[0]->winning_name, serial->winning_name);
    EXPECT_EQ(results[0]->address, base + LEA_OFF);
}
