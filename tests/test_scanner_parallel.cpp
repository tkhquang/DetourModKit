#include <gtest/gtest.h>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#include "DetourModKit/scan.hpp"

// White-box include of the generic fork-join driver and the test binary's allocation-failure injector: the noexcept
// degradation tests below drive the shared batch primitive under injected OOM to prove the never-terminate contract.
// fork_join.hpp lives in src/, which is on the test target's private include path.
#include "fork_join.hpp"
#include "test_alloc_probe.hpp"

#include <windows.h>

using namespace DetourModKit;

// These tests cover public batch-resolver dispatch, typed failures, and the string-xref tier on worker threads.

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

    /// Renders a byte span as a space-separated uppercase-hex AOB string for parse_aob / Pattern::compile.
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

    /// Compiles a known-good AOB literal into a public scan::Pattern (the batch candidate signatures).
    [[nodiscard]] scan::Pattern aob(std::string_view dsl)
    {
        return scan::Pattern::compile(dsl).value();
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

TEST(ScannerBatchTest, ResolveBatchEmptyReturnsEmpty)
{
    const std::vector<scan::ScanRequest> requests;
    const auto batch = scan::resolve_batch(requests);
    // No requests is a successful whole-batch outcome carrying an empty per-request vector, NOT a whole-batch failure.
    ASSERT_TRUE(batch.has_value());
    EXPECT_EQ(batch->size(), 0u);
}

TEST(ScannerBatchTest, ResolveBatchMatchesSerialResolve)
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

    const scan::Candidate cands_a[] = {scan::Candidate::direct("module-a", aob(sig_to_aob(sig_a)))};
    const scan::Candidate cands_b[] = {scan::Candidate::direct("module-b", aob(sig_to_aob(sig_b)))};

    const auto base = reinterpret_cast<std::uintptr_t>(code_page.base);
    const Region range{Address{base}, code_page.size};

    const scan::ScanRequest module_request{.ladder = cands_a, .label = "module-a", .scope = range};
    const scan::ScanRequest fallback_request{.ladder = cands_b,
                                             .label = "module-b-fallback",
                                             .scope = range,
                                             .fallback_policy = scan::FallbackPolicy::WarnOnly};
    // Whole-process scope on the default readable page class is refused for want of provable authority, so this entry
    // exercises the batch path's propagation of a per-request typed refusal alongside successful siblings.
    const scan::ScanRequest whole_process_request{
        .ladder = cands_b, .label = "whole-process-b", .scope = Region::whole_process()};
    const scan::ScanRequest empty_request{.ladder = {}, .label = "empty"};
    const scan::ScanRequest invalid_range_request{.ladder = cands_a, .label = "invalid-range", .scope = Region{}};

    const std::vector<scan::ScanRequest> requests{module_request, fallback_request, whole_process_request,
                                                  empty_request, invalid_range_request};

    const auto batch = scan::resolve_batch(requests, 4);
    ASSERT_TRUE(batch.has_value());
    const auto &results = *batch;
    ASSERT_EQ(results.size(), requests.size());

    const auto serial_module = scan::resolve(module_request);
    const auto serial_fallback = scan::resolve(fallback_request);
    const auto serial_whole = scan::resolve(whole_process_request);

    ASSERT_TRUE(results[0].has_value());
    ASSERT_TRUE(serial_module.has_value());
    EXPECT_EQ(results[0]->address, serial_module->address);
    EXPECT_EQ(results[0]->winning_name, serial_module->winning_name);
    EXPECT_EQ(results[0]->address.raw(), reinterpret_cast<std::uintptr_t>(target_a));

    ASSERT_TRUE(results[1].has_value());
    ASSERT_TRUE(serial_fallback.has_value());
    EXPECT_EQ(results[1]->address, serial_fallback->address);
    EXPECT_EQ(results[1]->winning_name, serial_fallback->winning_name);
    EXPECT_EQ(results[1]->address.raw(), reinterpret_cast<std::uintptr_t>(target_b));

    // An unconfined readable scope cannot prove a match is not the query finding its own retained bytes, so it is
    // refused before any candidate is graded. The batch worker must reach exactly the serial verdict: a typed refusal,
    // not an empty miss and not a silent success.
    ASSERT_FALSE(results[2].has_value());
    ASSERT_FALSE(serial_whole.has_value());
    EXPECT_EQ(results[2].error().code, ErrorCode::NotAuthoritative);
    EXPECT_EQ(serial_whole.error().code, ErrorCode::NotAuthoritative);

    ASSERT_FALSE(results[3].has_value());
    EXPECT_EQ(results[3].error().code, ErrorCode::EmptyCandidates);

    ASSERT_FALSE(results[4].has_value());
    EXPECT_EQ(results[4].error().code, ErrorCode::InvalidRange);
}

TEST(ScannerBatchTest, ResolveBatchWorkerCountYieldsIdenticalResults)
{
    CommittedPage code_page(64 * 1024, PAGE_EXECUTE_READWRITE);
    ASSERT_NE(code_page.base, nullptr);
    std::memset(code_page.bytes(), 0xCC, code_page.size);

    constexpr std::size_t REQUEST_COUNT = 16;
    const auto base = reinterpret_cast<std::uintptr_t>(code_page.base);
    const Region range{Address{base}, code_page.size};

    // Caller-owned storage the requests alias; it must outlive resolve_batch, so it lives in the test frame and is
    // sized up front (never reallocated) so the spans and string_views stay valid. Candidate is not default
    // constructible (factories only), so the ladder vector is reserve + push_back rather than pre-sized.
    std::vector<std::string> labels(REQUEST_COUNT);
    std::vector<scan::Candidate> candidates;
    candidates.reserve(REQUEST_COUNT);
    std::vector<scan::ScanRequest> requests(REQUEST_COUNT);
    std::array<std::uintptr_t, REQUEST_COUNT> planted{};

    for (std::size_t i = 0; i < REQUEST_COUNT; ++i)
    {
        const auto sig = make_unique_sig(static_cast<std::uint32_t>(6000 + i));
        std::byte *target = code_page.bytes() + 512 + i * 1024;
        std::memcpy(target, sig.data(), sig.size());
        planted[i] = reinterpret_cast<std::uintptr_t>(target);
        labels[i] = "cascade_" + std::to_string(i);
        candidates.push_back(scan::Candidate::direct(labels[i], aob(sig_to_aob(sig))));
        requests[i].ladder = std::span<const scan::Candidate>(&candidates[i], 1);
        requests[i].label = labels[i];
        requests[i].scope = range;
    }

    // The concurrent resolver must agree with the planted addresses item for item, and that agreement must be
    // independent of the worker count: serial (1), a fixed pool (4), an over-count clamp (1024), and auto (0). This
    // sweep drives many requests through the shared fork-join driver to exercise the work-stealing concurrent path.
    for (const std::size_t workers : {std::size_t{1}, std::size_t{4}, std::size_t{1024}, std::size_t{0}})
    {
        const auto batch = scan::resolve_batch(requests, workers);
        ASSERT_TRUE(batch.has_value()) << "workers=" << workers;
        const auto &results = *batch;
        ASSERT_EQ(results.size(), REQUEST_COUNT) << "workers=" << workers;
        for (std::size_t i = 0; i < REQUEST_COUNT; ++i)
        {
            ASSERT_TRUE(results[i].has_value()) << "workers=" << workers << " item=" << i;
            EXPECT_EQ(results[i]->address.raw(), planted[i]) << "workers=" << workers << " item=" << i;
            EXPECT_EQ(results[i]->winning_name, labels[i]) << "workers=" << workers << " item=" << i;
        }
    }
}

// A string-xref Candidate resolves identically through the fork-join batch path and the serial resolver, confirming
// resolve_batch uses the same variant dispatch as the serial path. StringXref is the representative tier:
// find_string_xref is the non-noexcept backend, so the request is replicated into a batch larger than one worker to
// exercise that throwing dispatch running on a spawned worker thread (not just the calling thread). Every copy aliases
// the same immutable RWX fixture -- one literal plus one RIP-relative lea reference -- so each concurrent resolve must
// agree with the serial result; disagreement would signal a data race in the shared read-only scan path.
TEST(ScannerBatchTest, ResolveBatchResolvesStringXrefTierLikeSerial)
{
    // No memory::init_cache() by design: find_string_xref installs its fault guard lazily (MinGW) or uses SEH (MSVC),
    // so it needs no cache warm-up. Zero-fill: a 0x00 byte both terminates the planted literal and never starts a
    // RIP-relative load.
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

    const Region range{Address{base}, image.size};

    const scan::Candidate cands[] = {scan::Candidate::string_xref("string-tier", "BatchStringXrefAnchorLiteral")};
    const scan::ScanRequest request{.ladder = cands, .label = "string-tier", .scope = range};

    // Replicate the request so the batch has more items than a single worker: worker_count = min(4, 4) = 4 takes the
    // fork-join driver's multi-worker path (three jthreads plus the calling thread), so find_string_xref dispatches
    // off the calling thread. The copies alias one immutable candidate and scope, so agreement is the race check.
    constexpr std::size_t REQUEST_COUNT = 4;
    const std::vector<scan::ScanRequest> requests(REQUEST_COUNT, request);
    const auto batch = scan::resolve_batch(requests, REQUEST_COUNT);
    ASSERT_TRUE(batch.has_value());
    const auto &results = *batch;
    ASSERT_EQ(results.size(), REQUEST_COUNT);

    const auto serial = scan::resolve(request);
    ASSERT_TRUE(serial.has_value());
    for (std::size_t i = 0; i < results.size(); ++i)
    {
        ASSERT_TRUE(results[i].has_value()) << "item=" << i;
        EXPECT_EQ(results[i]->address, serial->address) << "item=" << i;
        EXPECT_EQ(results[i]->winning_name, serial->winning_name) << "item=" << i;
        EXPECT_EQ(results[i]->address.raw(), base + LEA_OFF) << "item=" << i;
    }
}

// noexcept-batch degradation under injected out-of-memory.
//
// resolve_batch is noexcept: injected into a running host, it must degrade rather than terminate under true OOM. The
// contract has two arms, both driven here through the thread-local allocation-failure injector on a SERIAL batch
// (max_workers == 1) so every allocation lands on the test thread deterministically:
//   1. If the N-entry result container itself cannot be allocated, the whole batch fails: resolve_batch catches the
//      bad_alloc at the noexcept boundary and returns the OUTER Result as Error{OutOfMemory}. The signal is explicit
//      (an unwrap the caller cannot skip), not a silently-undersized vector, so it mirrors hook::install_all.
//   2. If the container is built but a per-request resolve throws bad_alloc, the outer Result succeeds and only that
//      slot degrades to Error{OutOfMemory}; the inner vector still has one result per request.
// The fork-join driver's own two-tier catch (a non-bad_alloc throw keeps the fail-closed seed) is proven directly by
// the last test, which needs no injection.

// The batch entry point must be noexcept for the never-terminate contract to hold at all; pin it at compile time so a
// future signature change that drops noexcept fails the build rather than silently regressing the guarantee.
static_assert(noexcept(scan::resolve_batch(std::span<const scan::ScanRequest>{}, std::size_t{1})),
              "scan::resolve_batch must be noexcept: it is the never-terminate batch boundary.");

TEST(ScannerBatchTest, ResolveBatchContainerAllocFailureReturnsOuterErrorWholeBatchSignal)
{
    DMK_REQUIRE_PROXY_FREE_STL();
    CommittedPage code_page(64 * 1024, PAGE_EXECUTE_READWRITE);
    ASSERT_NE(code_page.base, nullptr);
    std::memset(code_page.bytes(), 0xCC, code_page.size);

    const auto sig = make_unique_sig(7100);
    std::memcpy(code_page.bytes() + 512, sig.data(), sig.size());
    const Region range{Address{reinterpret_cast<std::uintptr_t>(code_page.base)}, code_page.size};
    const scan::Candidate cands[] = {scan::Candidate::direct("oom-container", aob(sig_to_aob(sig)))};
    const scan::ScanRequest request{.ladder = cands, .label = "oom-container", .scope = range};
    const std::vector<scan::ScanRequest> requests{request, request, request};
    const std::span<const scan::ScanRequest> view{requests};

    Result<std::vector<Result<scan::Hit>>> results;
    {
        // Budget 0: the very first allocation (the result container inside run_fork_join) fails, so resolve_batch
        // swallows the bad_alloc at its noexcept boundary and reports the whole-batch failure on the OUTER Result.
        // Building Error{OutOfMemory} allocates nothing (its `where` is a const char*), so this path stays no-throw
        // even with every allocation failing.
        dmk_test::AllocFailScope fail(0);
        results = scan::resolve_batch(view, 1);
    }

    // Whole-batch out-of-memory signal: the outer Result holds no per-request vector at all, so a caller must unwrap
    // it before indexing and cannot silently proceed on a truncated batch.
    ASSERT_FALSE(results.has_value());
    EXPECT_EQ(results.error().code, ErrorCode::OutOfMemory);
}

TEST(ScannerBatchTest, ResolveBatchPerRequestAllocFailureDegradesToOutOfMemory)
{
    DMK_REQUIRE_PROXY_FREE_STL();
    CommittedPage code_page(64 * 1024, PAGE_EXECUTE_READWRITE);
    ASSERT_NE(code_page.base, nullptr);
    std::memset(code_page.bytes(), 0xCC, code_page.size);

    constexpr std::size_t REQUEST_COUNT = 4;
    const Region range{Address{reinterpret_cast<std::uintptr_t>(code_page.base)}, code_page.size};

    // Caller-owned storage the spans alias; sized up front so it never reallocates and the request views stay valid.
    std::vector<std::string> labels(REQUEST_COUNT);
    std::vector<scan::Candidate> candidates;
    candidates.reserve(REQUEST_COUNT);
    std::vector<scan::ScanRequest> requests(REQUEST_COUNT);
    for (std::size_t i = 0; i < REQUEST_COUNT; ++i)
    {
        const auto sig = make_unique_sig(static_cast<std::uint32_t>(7200 + i));
        std::memcpy(code_page.bytes() + 512 + i * 1024, sig.data(), sig.size());
        labels[i] = "oom_item_" + std::to_string(i);
        candidates.push_back(scan::Candidate::direct(labels[i], aob(sig_to_aob(sig))));
        requests[i].ladder = std::span<const scan::Candidate>(&candidates[i], 1);
        requests[i].label = labels[i];
        requests[i].scope = range;
    }
    const std::span<const scan::ScanRequest> view{requests};

    Result<std::vector<Result<scan::Hit>>> results;
    {
        // Budget 1: the result container (one allocation) is built and fail-closed-seeded, then every per-request
        // resolve throws bad_alloc on its first internal allocation. Each throw is caught inside resolve_batch's
        // per-request wrapper and mapped to Error{OutOfMemory}, so the outer Result succeeds and the inner vector
        // still holds one result per request.
        dmk_test::AllocFailScope fail(1);
        results = scan::resolve_batch(view, 1);
    }

    // The container survived, so the outer Result succeeds and this is per-request degradation, not the whole-batch
    // signal.
    ASSERT_TRUE(results.has_value());
    const auto &batch = *results;
    ASSERT_EQ(batch.size(), requests.size());
    for (std::size_t i = 0; i < batch.size(); ++i)
    {
        ASSERT_FALSE(batch[i].has_value()) << "item=" << i;
        EXPECT_EQ(batch[i].error().code, ErrorCode::OutOfMemory) << "item=" << i;
    }
}

TEST(ForkJoinTest, PerItemThrowKeepsFailClosedSeedAndIsolatesNeighbours)
{
    // The generic driver's inner degradation arm: a resolve_one that throws (anything, here a non-bad_alloc) fails
    // only its own item closed -- that slot keeps the fail_one seed -- while every neighbour resolves normally. This
    // is the path that maps "any other per-request throw" to the seeded value, complementing the bad_alloc arm above.
    const std::array<int, 5> items{0, 1, 2, 3, 4};
    const auto results = detail::run_fork_join<int, int>(
        std::span<const int>(items), 1,
        [](const int &value) -> int
        {
            if (value == 2)
            {
                throw std::runtime_error("injected per-item failure");
            }
            return value * 10;
        },
        [](const int &) noexcept -> int { return -1; });

    ASSERT_EQ(results.size(), items.size());
    EXPECT_EQ(results[0], 0);
    EXPECT_EQ(results[1], 10);
    EXPECT_EQ(results[2], -1); // threw: kept the fail-closed seed
    EXPECT_EQ(results[3], 30);
    EXPECT_EQ(results[4], 40);
}
