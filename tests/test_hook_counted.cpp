#include <gtest/gtest.h>
#include <windows.h>

#include <array>
#include <atomic>
#include <chrono>
#include <csetjmp>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <type_traits>
#include <utility>

#if defined(_MSC_VER)
#include <intrin.h>
#endif
#include <xmmintrin.h>

#include "DetourModKit/hook.hpp"

#include "fixtures/hook_fixture.hpp"
#include "fixtures/log_capture.hpp"
#include "fixtures/proof_section.hpp"
#include "fixtures/scratch_page.hpp"

using namespace DetourModKit;
using namespace DetourModKit::hook;
using namespace dmk_test::hook_fixture;

#if defined(DMK_ENABLE_TEST_SEAMS)
namespace DetourModKit::detail
{
    // Mirrors src/internal/hook_backend.hpp, which this binary cannot include because it names the backend headers.
    struct CountedThunkProbe
    {
        void *entry{nullptr};
        void *range_end{nullptr};
        void *enter_count{nullptr};
        void *after_exit_count{nullptr};
        std::size_t helper_calls{0};
        std::size_t counted_calls{0};
        std::size_t pushes{0};
        std::size_t pops{0};
    };

    [[nodiscard]] CountedThunkProbe counted_thunk_for_test(const hook::Hook &hook) noexcept;
} // namespace DetourModKit::detail
#endif

namespace
{
    using Forward8Fn = std::int64_t (*)(
        std::int64_t,
        std::int64_t,
        std::int64_t,
        std::int64_t,
        std::int64_t,
        std::int64_t,
        std::int64_t,
        std::int64_t
    );

    /// The bound of a retirement that a parked call or a stuck count keeps Busy.
    constexpr std::chrono::milliseconds BUSY_DEADLINE{100};
    /// The bound of a retirement that has to succeed.
    constexpr std::chrono::milliseconds RETIRE_DEADLINE{2000};

    constexpr std::int64_t FORWARD_DELTA = 1000000;
    constexpr int FRAME_DELTA = 0x100;
    constexpr int UNWIND_DELTA = 0x200;
    constexpr int SPLIT_DELTA = 0x300;
    constexpr int PROLOGUE_DELTA = 0x400;
    constexpr int RELAY_DELTA = 0x500;
    constexpr int RELAY_ARGUMENT = 41;

    DMK_PROOF_TARGET std::int64_t weighted_eight(
        std::int64_t a,
        std::int64_t b,
        std::int64_t c,
        std::int64_t d,
        std::int64_t e,
        std::int64_t f,
        std::int64_t g,
        std::int64_t h
    )
    {
        volatile std::int64_t sum = a + 2 * b + 3 * c + 4 * d + 5 * e + 6 * f + 7 * g + 8 * h;
        return sum;
    }

    DMK_PROOF_SEEDED_TARGET(frame_return_target, 307)
    DMK_PROOF_SEEDED_TARGET(frame_slot_target, 311)
    DMK_PROOF_SEEDED_TARGET(unwind_target, 313)
    DMK_PROOF_SEEDED_TARGET(split_target, 317)
    DMK_PROOF_SEEDED_TARGET(prologue_target, 331)
    DMK_PROOF_SEEDED_TARGET(body_target, 337)
    DMK_PROOF_SEEDED_TARGET(tail_target, 347)
    DMK_PROOF_SEEDED_TARGET(relay_target, 349)

    DMK_PROOF_TARGET int thunk_range_target(int value, int *out)
    {
        volatile int doubled = value * 2;
        *out = doubled;
        return doubled + 1;
    }

    template <class Fn> [[nodiscard]] InlineRequest request_for(const char *name, Fn *target)
    {
        return InlineRequest{
            .name = name,
            .target = Address{reinterpret_cast<std::uintptr_t>(target)},
        };
    }

    /// The trampoline of each eight-argument hook. Each Case value belongs to one target.
    template <int Case> std::atomic<Forward8Fn> s_eight_original{nullptr};

    template <int Case>
    DMK_TEST_NOINLINE std::int64_t forward_eight_detour(
        std::int64_t a,
        std::int64_t b,
        std::int64_t c,
        std::int64_t d,
        std::int64_t e,
        std::int64_t f,
        std::int64_t g,
        std::int64_t h
    ) noexcept
    {
        return s_eight_original<Case>.load(std::memory_order_acquire)(a, b, c, d, e, f, g, h) + FORWARD_DELTA;
    }

    /// Hooks @p target with a counted detour, compares two calls with the trampoline, and retires the hook.
    template <int Case> void expect_eight_arguments_forwarded(Forward8Fn target, const char *name)
    {
        const std::int64_t pristine = dmk_test::call_unfolded(target, 1, 2, 3, 4, 5, 6, 7, 8);
        ASSERT_NE(dmk_test::call_unfolded(target, 2, 1, 3, 4, 5, 6, 7, 8), pristine)
            << "the target cannot tell a swapped argument";
        Result<Hook> installed = inline_at<&forward_eight_detour<Case>>(request_for(name, target));
        ASSERT_TRUE(installed.has_value()) << installed.error().message();
        HookStack stack;
        Hook &hook = stack.push(std::move(*installed));
        s_eight_original<Case>.store(hook.original<Forward8Fn>(), std::memory_order_release);
        ASSERT_TRUE(hook.enable().has_value());

        EXPECT_EQ(dmk_test::call_unfolded(target, 1, 2, 3, 4, 5, 6, 7, 8), pristine + FORWARD_DELTA);
        EXPECT_EQ(
            dmk_test::call_unfolded(target, -8, 7, -6, 5, -4, 3, -2, 1),
            dmk_test::call_unfolded(hook.original<Forward8Fn>(), -8, 7, -6, 5, -4, 3, -2, 1) + FORWARD_DELTA
        );

        const HookRetirement retired = stack.retire(RETIRE_DEADLINE);
        EXPECT_EQ(retired.outcome, RetirementOutcome::Retired);
        EXPECT_EQ(retired.restored, 1u);
        EXPECT_EQ(retired.vacated, 0u);
        EXPECT_EQ(retired.pinned, 0u);
        EXPECT_TRUE(stack.empty());
        EXPECT_EQ(dmk_test::call_unfolded(target, 1, 2, 3, 4, 5, 6, 7, 8), pristine);
    }

    /**
     * @brief Reports whether @p address lies inside the function that starts at @p function.
     * @details The unwind record that covers @p address names the function. A return address lies past the start.
     */
    [[nodiscard]] bool returns_into(const void *address, const void *function) noexcept
    {
        DWORD64 image_base = 0;
        const auto at = reinterpret_cast<DWORD64>(address);
        const PRUNTIME_FUNCTION record = RtlLookupFunctionEntry(at, &image_base, nullptr);
        if (record == nullptr)
        {
            return false;
        }
        const DWORD64 begin = image_base + record->BeginAddress;
        return begin == reinterpret_cast<DWORD64>(function) && at > begin && at < image_base + record->EndAddress;
    }

    std::atomic<EchoFn> s_frame_return_original{nullptr};
    std::atomic<void *> s_frame_return_address{nullptr};

    DMK_TEST_NOINLINE int frame_return_detour(CallerFrame frame, int value) noexcept
    {
        s_frame_return_address.store(frame.return_address(), std::memory_order_release);
        return dmk_test::call_unfolded(s_frame_return_original.load(std::memory_order_acquire), value) + FRAME_DELTA;
    }

    /// The game caller of frame_return_target. The volatile result forbids a tail jump, so the call returns here.
    DMK_TEST_NOINLINE int call_frame_return_target(int value)
    {
        const EchoFn volatile target = &frame_return_target;
        volatile int result = target(value);
        return result;
    }

    /// What frame_slot_detour reads from inside the hooked call.
    struct FrameSlotObservation
    {
        void **slot{nullptr};
        void *return_address{nullptr};
        std::uintptr_t detour_local{0};
        ULONG_PTR stack_low{0};
        ULONG_PTR stack_high{0};
    };

    std::atomic<EchoFn> s_frame_slot_original{nullptr};
    FrameSlotObservation s_frame_slot;
    std::atomic<std::uintptr_t> s_frame_slot_caller_local{0};

    DMK_TEST_NOINLINE int frame_slot_detour(CallerFrame frame, int value) noexcept
    {
        volatile int local = value;
        s_frame_slot.slot = frame.return_address_slot;
        s_frame_slot.return_address = frame.return_address();
        s_frame_slot.detour_local = reinterpret_cast<std::uintptr_t>(&local);
        GetCurrentThreadStackLimits(&s_frame_slot.stack_low, &s_frame_slot.stack_high);
        return dmk_test::call_unfolded(s_frame_slot_original.load(std::memory_order_acquire), local) + FRAME_DELTA;
    }

    /// The game caller of frame_slot_target. It publishes the address of a local in its own frame first.
    DMK_TEST_NOINLINE int call_frame_slot_target(int value)
    {
        volatile int marker = value;
        s_frame_slot_caller_local.store(reinterpret_cast<std::uintptr_t>(&marker), std::memory_order_release);
        const EchoFn volatile target = &frame_slot_target;
        volatile int result = target(marker);
        return result;
    }

    using PointerFn = int (*)(int, int *);

    std::atomic<PointerFn> s_thunk_range_original{nullptr};
    std::atomic<void *> s_thunk_range_return{nullptr};

    DMK_TEST_NOINLINE int thunk_range_detour(int value, int *out) noexcept
    {
#if defined(_MSC_VER)
        s_thunk_range_return.store(_ReturnAddress(), std::memory_order_release);
#else
        s_thunk_range_return.store(__builtin_return_address(0), std::memory_order_release);
#endif
        return dmk_test::call_unfolded(s_thunk_range_original.load(std::memory_order_acquire), value, out) + 1;
    }

    std::atomic<bool> s_unwind_escape{false};
    std::jmp_buf s_unwind_landing;

    // A longjmp runs only the unwind phase, and neither personality routine terminates a noexcept frame in that phase.
    DMK_TEST_NOINLINE int unwind_detour(int value) noexcept
    {
        if (s_unwind_escape.exchange(false, std::memory_order_acq_rel))
        {
            longjmp(s_unwind_landing, 1);
        }
        return value + UNWIND_DELTA;
    }

#if defined(_MSC_VER)
#pragma warning(push)
// No frame between the setjmp and its longjmp owns an object with a destructor.
#pragma warning(disable : 4611)
#endif

    /// Calls unwind_target and reports whether its detour left through the unwind of a longjmp.
    DMK_TEST_NOINLINE bool unwind_out_of_detour(int value)
    {
        if (setjmp(s_unwind_landing) != 0)
        {
            return true;
        }
        (void)dmk_test::call_unfolded(&unwind_target, value);
        return false;
    }

#if defined(_MSC_VER)
#pragma warning(pop)
#endif

    DMK_TEST_NOINLINE int split_detour(int value) noexcept
    {
        return value + SPLIT_DELTA;
    }

    DMK_TEST_NOINLINE int prologue_detour(int value) noexcept
    {
        return value + PROLOGUE_DELTA;
    }

    std::atomic<int> s_relay_detour_calls{0};
    std::atomic<EchoFn> s_relay_original{nullptr};

    DMK_TEST_NOINLINE int relay_detour(int value) noexcept
    {
        s_relay_detour_calls.fetch_add(1, std::memory_order_relaxed);
        return dmk_test::call_unfolded(s_relay_original.load(std::memory_order_acquire), value) + RELAY_DELTA;
    }

    /// Waits up to @ref PARK_BOUND for @p flag and reports whether it turned true.
    [[nodiscard]] bool wait_for(const std::atomic<bool> &flag) noexcept
    {
        const ULONGLONG deadline = GetTickCount64() + static_cast<ULONGLONG>(PARK_BOUND.count()) * 1000;
        while (!flag.load(std::memory_order_acquire) && GetTickCount64() < deadline)
        {
            Sleep(1);
        }
        return flag.load(std::memory_order_acquire);
    }

    /// Calls @p fn through a volatile pointer like dmk_test::call_unfolded, and passes references through unchanged.
    template <class Ret, class... Params, class... Args> Ret call_forwarding(Ret (*fn)(Params...), Args &&...args)
    {
        Ret (*const volatile indirect)(Params...) = fn;
        return indirect(std::forward<Args>(args)...);
    }

    /// Installs a counted hook of @p Detour on @p target, publishes its trampoline to @p original, and arms it.
    template <auto Detour, class Fn>
    void arm_counted(HookStack &stack, const char *name, Fn *target, std::atomic<Fn *> &original)
    {
        Result<Hook> installed = inline_at<Detour>(request_for(name, target));
        ASSERT_TRUE(installed.has_value()) << installed.error().message();
        Hook &hook = stack.push(std::move(*installed));
        original.store(hook.original<Fn *>(), std::memory_order_release);
        ASSERT_TRUE(hook.enable().has_value());
    }

    /// Retires @p stack and expects each of its @p hooks to restore its target.
    void expect_restored(HookStack &stack, std::uint32_t hooks)
    {
        const HookRetirement retired = stack.retire(RETIRE_DEADLINE);
        EXPECT_EQ(retired.outcome, RetirementOutcome::Retired);
        EXPECT_EQ(retired.restored, hooks);
        EXPECT_EQ(retired.vacated + retired.pinned, 0u);
        EXPECT_TRUE(stack.empty());
    }

    using Forward10Fn = std::int64_t (*)(
        std::int64_t,
        std::int64_t,
        std::int64_t,
        std::int64_t,
        std::int64_t,
        std::int64_t,
        std::int64_t,
        std::int64_t,
        std::int64_t,
        std::int64_t
    );

    DMK_PROOF_TARGET std::int64_t weighted_ten(
        std::int64_t a,
        std::int64_t b,
        std::int64_t c,
        std::int64_t d,
        std::int64_t e,
        std::int64_t f,
        std::int64_t g,
        std::int64_t h,
        std::int64_t i,
        std::int64_t j
    )
    {
        volatile std::int64_t sum = a + 2 * b + 3 * c + 4 * d + 5 * e + 6 * f + 7 * g + 8 * h + 9 * i + 10 * j;
        return sum;
    }

    DMK_PROOF_TARGET std::int64_t frame_ten_target(
        std::int64_t a,
        std::int64_t b,
        std::int64_t c,
        std::int64_t d,
        std::int64_t e,
        std::int64_t f,
        std::int64_t g,
        std::int64_t h,
        std::int64_t i,
        std::int64_t j
    )
    {
        volatile std::int64_t sum = 10 * a + 9 * b + 8 * c + 7 * d + 6 * e + 5 * f + 4 * g + 3 * h + 2 * i + j;
        return sum;
    }

    std::atomic<Forward10Fn> s_ten_original{nullptr};

    DMK_TEST_NOINLINE std::int64_t forward_ten_detour(
        std::int64_t a,
        std::int64_t b,
        std::int64_t c,
        std::int64_t d,
        std::int64_t e,
        std::int64_t f,
        std::int64_t g,
        std::int64_t h,
        std::int64_t i,
        std::int64_t j
    ) noexcept
    {
        return s_ten_original.load(std::memory_order_acquire)(a, b, c, d, e, f, g, h, i, j) + FORWARD_DELTA;
    }

    std::atomic<Forward10Fn> s_frame_ten_original{nullptr};
    std::atomic<void *> s_frame_ten_return{nullptr};

    DMK_TEST_NOINLINE std::int64_t frame_ten_detour(
        CallerFrame frame,
        std::int64_t a,
        std::int64_t b,
        std::int64_t c,
        std::int64_t d,
        std::int64_t e,
        std::int64_t f,
        std::int64_t g,
        std::int64_t h,
        std::int64_t i,
        std::int64_t j
    ) noexcept
    {
        s_frame_ten_return.store(frame.return_address(), std::memory_order_release);
        return s_frame_ten_original.load(std::memory_order_acquire)(a, b, c, d, e, f, g, h, i, j) + FRAME_DELTA;
    }

    /// The game caller of frame_ten_target. The volatile result forbids a tail jump, so the call returns here.
    DMK_TEST_NOINLINE std::int64_t call_frame_ten_target(std::int64_t base)
    {
        const Forward10Fn volatile target = &frame_ten_target;
        volatile std::int64_t result =
            target(base, base + 1, base + 2, base + 3, base + 4, base + 5, base + 6, base + 7, base + 8, base + 9);
        return result;
    }

    using BlendFn = double (*)(float, double, float, double, float, double);
    using ShrinkFn = float (*)(double, float, std::int32_t, float, float);

    /// The detour and the expectation add this delta in one identical operation, so the results compare exactly.
    constexpr double FLOAT_DELTA = 1024.0;

    DMK_PROOF_TARGET double blend_target(float a, double b, float c, double d, float e, double f)
    {
        volatile double blended = a * 1.5 + b * 2.25 - c * 0.5 + d * 3.0 + e * 0.75 - f * 1.25;
        return blended;
    }

    DMK_PROOF_TARGET float shrink_target(double a, float b, std::int32_t c, float d, float e)
    {
        volatile float shrunk = static_cast<float>(a) * 0.5f + b * 0.25f + static_cast<float>(c) * 2.0f - d + e * 4.0f;
        return shrunk;
    }

    std::atomic<BlendFn> s_blend_original{nullptr};
    std::atomic<ShrinkFn> s_shrink_original{nullptr};

    DMK_TEST_NOINLINE double blend_detour(float a, double b, float c, double d, float e, double f) noexcept
    {
        return s_blend_original.load(std::memory_order_acquire)(a, b, c, d, e, f) + FLOAT_DELTA;
    }

    DMK_TEST_NOINLINE float shrink_detour(double a, float b, std::int32_t c, float d, float e) noexcept
    {
        return s_shrink_original.load(std::memory_order_acquire)(a, b, c, d, e) + static_cast<float>(FLOAT_DELTA);
    }

    /// The Win64 convention passes this eight-byte struct in one register.
    struct SmallPod
    {
        std::int32_t x;
        std::int32_t y;
    };

    /// The Win64 convention passes this 24-byte struct by a pointer to a copy and returns it by a hidden pointer.
    struct LargePod
    {
        std::int64_t first;
        std::int64_t second;
        std::int64_t third;

        bool operator==(const LargePod &) const = default;
    };

    static_assert(sizeof(SmallPod) == 8 && std::is_trivially_copyable_v<SmallPod>);
    static_assert(sizeof(LargePod) == 24 && std::is_trivially_copyable_v<LargePod>);

    using SmallPodFn = std::int64_t (*)(SmallPod, std::int64_t);
    using LargePodFn = std::int64_t (*)(std::int64_t, LargePod, std::int64_t);
    using LargeResultFn = LargePod (*)(std::int64_t, std::int64_t);

    DMK_PROOF_TARGET std::int64_t small_pod_target(SmallPod pod, std::int64_t scale)
    {
        volatile std::int64_t mixed =
            static_cast<std::int64_t>(pod.x) * 7 + static_cast<std::int64_t>(pod.y) * 13 + scale * 17;
        return mixed;
    }

    DMK_PROOF_TARGET std::int64_t large_pod_target(std::int64_t lead, LargePod pod, std::int64_t tail)
    {
        volatile std::int64_t mixed = lead * 3 + pod.first * 5 + pod.second * 7 + pod.third * 11 + tail * 13;
        return mixed;
    }

    DMK_PROOF_TARGET LargePod large_result_target(std::int64_t seed, std::int64_t step)
    {
        volatile std::int64_t base = seed * 3;
        volatile std::int64_t stride = step;
        return LargePod{
            .first = base,
            .second = base + stride,
            .third = base + stride * 2,
        };
    }

    std::atomic<SmallPodFn> s_small_pod_original{nullptr};
    std::atomic<LargePodFn> s_large_pod_original{nullptr};
    std::atomic<LargeResultFn> s_large_result_original{nullptr};

    DMK_TEST_NOINLINE std::int64_t small_pod_detour(SmallPod pod, std::int64_t scale) noexcept
    {
        return s_small_pod_original.load(std::memory_order_acquire)(pod, scale) + FORWARD_DELTA;
    }

    DMK_TEST_NOINLINE std::int64_t large_pod_detour(std::int64_t lead, LargePod pod, std::int64_t tail) noexcept
    {
        return s_large_pod_original.load(std::memory_order_acquire)(lead, pod, tail) + FORWARD_DELTA;
    }

    DMK_TEST_NOINLINE LargePod large_result_detour(std::int64_t seed, std::int64_t step) noexcept
    {
        LargePod pod = s_large_result_original.load(std::memory_order_acquire)(seed, step);
        pod.first += FORWARD_DELTA;
        pod.second += 2 * FORWARD_DELTA;
        pod.third += 3 * FORWARD_DELTA;
        return pod;
    }

    /// Returns @p pod with each field shifted as large_result_detour shifts it.
    [[nodiscard]] LargePod shifted(LargePod pod) noexcept
    {
        return LargePod{
            .first = pod.first + FORWARD_DELTA,
            .second = pod.second + 2 * FORWARD_DELTA,
            .third = pod.third + 3 * FORWARD_DELTA,
        };
    }

    /// An object that the rvalue target takes over through a reference.
    struct MovePayload
    {
        std::int64_t value;
        std::int64_t moves;
    };

    using LvalueFn = int (*)(int &, int);
    using RvalueFn = std::int64_t (*)(MovePayload &&);
    using VoidFn = void (*)(std::int64_t, std::int64_t, std::int64_t *);

    constexpr int REFERENCE_DELTA = 0x800;

    DMK_PROOF_TARGET int lvalue_target(int &slot, int delta)
    {
        volatile int scaled = delta * 3;
        volatile int previous = slot;
        slot = previous + scaled;
        return slot;
    }

    DMK_PROOF_TARGET std::int64_t rvalue_target(MovePayload &&payload)
    {
        volatile std::int64_t taken = payload.value;
        payload.value = 0;
        payload.moves += 1;
        return taken;
    }

    DMK_PROOF_TARGET void void_target(std::int64_t a, std::int64_t b, std::int64_t *out)
    {
        volatile std::int64_t mixed = a * 3 + b * 5;
        *out = mixed;
    }

    std::atomic<LvalueFn> s_lvalue_original{nullptr};
    std::atomic<const int *> s_lvalue_seen{nullptr};

    DMK_TEST_NOINLINE int lvalue_detour(int &slot, int delta) noexcept
    {
        s_lvalue_seen.store(&slot, std::memory_order_release);
        const int forwarded = s_lvalue_original.load(std::memory_order_acquire)(slot, delta);
        slot += REFERENCE_DELTA;
        return forwarded + REFERENCE_DELTA;
    }

    std::atomic<RvalueFn> s_rvalue_original{nullptr};
    std::atomic<const MovePayload *> s_rvalue_seen{nullptr};

    DMK_TEST_NOINLINE std::int64_t rvalue_detour(MovePayload &&payload) noexcept
    {
        s_rvalue_seen.store(&payload, std::memory_order_release);
        const std::int64_t taken = s_rvalue_original.load(std::memory_order_acquire)(std::move(payload));
        payload.moves += REFERENCE_DELTA;
        return taken + REFERENCE_DELTA;
    }

    std::atomic<VoidFn> s_void_original{nullptr};
    std::atomic<int> s_void_detour_calls{0};

    DMK_TEST_NOINLINE void void_detour(std::int64_t a, std::int64_t b, std::int64_t *out) noexcept
    {
        s_void_original.load(std::memory_order_acquire)(a, b, out);
        *out += FORWARD_DELTA;
        s_void_detour_calls.fetch_add(1, std::memory_order_relaxed);
    }

    /// The Win64 convention returns an __m128 in a vector register and passes one by a pointer to a caller copy.
    using VectorFn = __m128 (*)(__m128, float, __m128);
    using Lanes = std::array<float, 4>;

    DMK_PROOF_TARGET __m128 vector_target(__m128 a, float scale, __m128 b)
    {
        volatile float weight = scale;
        const __m128 scaled = _mm_mul_ps(a, _mm_set1_ps(weight));
        return _mm_sub_ps(scaled, _mm_shuffle_ps(b, b, _MM_SHUFFLE(0, 1, 2, 3)));
    }

    std::atomic<VectorFn> s_vector_original{nullptr};

    DMK_TEST_NOINLINE __m128 vector_detour(__m128 a, float scale, __m128 b) noexcept
    {
        const __m128 forwarded = s_vector_original.load(std::memory_order_acquire)(a, scale, b);
        return _mm_add_ps(forwarded, _mm_set1_ps(static_cast<float>(FLOAT_DELTA)));
    }

    [[nodiscard]] Lanes lanes_of(__m128 value) noexcept
    {
        Lanes lanes{};
        _mm_storeu_ps(lanes.data(), value);
        return lanes;
    }

    /// Adds the delta of @ref vector_detour to each lane, in the same single-precision addition.
    [[nodiscard]] Lanes with_vector_delta(Lanes lanes) noexcept
    {
        for (float &lane : lanes)
        {
            lane += static_cast<float>(FLOAT_DELTA);
        }
        return lanes;
    }

    /// Ten arguments of six kinds: four in registers by position, and six on the stack.
    using MixedTenFn = double (*)(
        std::int32_t,
        double,
        float,
        std::int64_t,
        const std::int32_t *,
        float,
        std::uint8_t,
        double,
        std::int16_t,
        SmallPod
    );

    DMK_PROOF_TARGET double mixed_ten_target(
        std::int32_t a,
        double b,
        float c,
        std::int64_t d,
        const std::int32_t *e,
        float f,
        std::uint8_t g,
        double h,
        std::int16_t i,
        SmallPod j
    )
    {
        volatile double sum = a * 1.0 + b * 2.0 + c * 3.0 + static_cast<double>(d) * 4.0 + *e * 5.0 + f * 6.0 +
                              g * 7.0 + h * 8.0 + i * 9.0 + (j.x * 10.0 - j.y * 11.0);
        return sum;
    }

    std::atomic<MixedTenFn> s_mixed_ten_original{nullptr};

    DMK_TEST_NOINLINE double mixed_ten_detour(
        std::int32_t a,
        double b,
        float c,
        std::int64_t d,
        const std::int32_t *e,
        float f,
        std::uint8_t g,
        double h,
        std::int16_t i,
        SmallPod j
    ) noexcept
    {
        return s_mixed_ten_original.load(std::memory_order_acquire)(a, b, c, d, e, f, g, h, i, j) + FLOAT_DELTA;
    }

    /**
     * @brief Checks the detour forms that the counted inline_at admits and the forms that it rejects.
     * @details The checks run in a template, so only the instantiation from a test case evaluates them.
     */
    template <class Frame> [[nodiscard]] constexpr bool counted_signatures_classify() noexcept
    {
        using DetourModKit::hook::detail::CountedSignature;
        static_assert(!CountedSignature<int (*)(int), Frame>::valid, "a detour that can throw has no counted thunk");
        static_assert(!CountedSignature<int (*)(int, ...) noexcept, Frame>::valid, "a variadic detour has none");
        static_assert(!CountedSignature<int (*)(Frame &, int) noexcept, Frame>::valid, "a frame by reference has none");
        static_assert(!CountedSignature<int (*)(int, Frame) noexcept, Frame>::valid, "a second frame has none");
        static_assert(
            !CountedSignature<int (*)(std::string) noexcept, Frame>::valid,
            "a std::string by value has none"
        );
        static_assert(CountedSignature<int (*)(int) noexcept, Frame>::valid);
        static_assert(CountedSignature<int (*)(Frame, int) noexcept, Frame>::valid);
        static_assert(CountedSignature<void (*)() noexcept, Frame>::valid);
        static_assert(CountedSignature<void (*)(int &, MovePayload &&, const std::string &) noexcept, Frame>::valid);
        static_assert(CountedSignature<LargePod (*)(Frame, SmallPod, LargePod, double, float) noexcept, Frame>::valid);
        static_assert(CountedSignature<__m128 (*)(Frame, __m128, float, __m128) noexcept, Frame>::valid);
        return true;
    }

    constexpr int FAKE_THUNK_DELTA = 0x700;

    /**
     * @brief The detour behind every fake thunk.
     * @details It calls no trampoline, so a thread released after a wrong retirement runs no freed code.
     */
    DMK_TEST_NOINLINE int fake_thunk_detour(int value) noexcept
    {
        return value + FAKE_THUNK_DELTA;
    }

    constinit EchoFn volatile s_fake_thunk_detour = &fake_thunk_detour;
    constinit DetourModKit::hook::detail::CountedBlock s_refused_thunk_block{};
    constinit DetourModKit::hook::detail::CountedBlock s_helper_thunk_block{};
    volatile int s_fake_thunk_sink = 0;

    std::atomic<bool> s_helper_armed{false};
    std::atomic<bool> s_helper_parked{false};
    std::atomic<bool> s_helper_released{false};

// The fake thunks take the attributes and the counter intrinsics of CountedEntry. Each one therefore keeps the shape
// that its name states at every optimization level.
#if defined(_MSC_VER)
#define DMK_TEST_FAKE_THUNK __declspec(noinline) __declspec(safebuffers) __declspec(no_sanitize_address)
#define DMK_TEST_FAKE_INCREMENT(counter) _InterlockedIncrement64(reinterpret_cast<volatile long long *>(&(counter)))
#else
#define DMK_TEST_FAKE_THUNK [[gnu::noipa, gnu::no_sanitize_address]]
#define DMK_TEST_FAKE_INCREMENT(counter) __atomic_add_fetch(&(counter), 1, __ATOMIC_SEQ_CST)
#endif

    /// The call that helper_site_thunk makes before its enter count. The next armed call parks until its release.
    DMK_TEST_FAKE_THUNK void fake_thunk_helper() noexcept
    {
        if (!s_helper_armed.exchange(false, std::memory_order_acq_rel))
        {
            return;
        }
        s_helper_parked.store(true, std::memory_order_release);
        const ULONGLONG deadline = GetTickCount64() + static_cast<ULONGLONG>(PARK_BOUND.count()) * 1000;
        while (!s_helper_released.load(std::memory_order_acquire) && GetTickCount64() < deadline)
        {
            YieldProcessor();
        }
    }

    /// A fake thunk with a conditional call between its counts. No compiler turns a call into branch-free code.
    DMK_TEST_FAKE_THUNK int branching_thunk(int value) noexcept
    {
        DMK_TEST_FAKE_INCREMENT(s_refused_thunk_block.stripes[0].enters);
        const int result = s_fake_thunk_detour(value);
        if (s_fake_thunk_sink != 0)
        {
            fake_thunk_helper();
        }
        DMK_TEST_FAKE_INCREMENT(s_refused_thunk_block.stripes[0].exits);
        return result;
    }

    /// A straight-line fake thunk with one locked increment. The volatile store keeps the call from a tail jump.
    DMK_TEST_FAKE_THUNK int single_count_thunk(int value) noexcept
    {
        DMK_TEST_FAKE_INCREMENT(s_refused_thunk_block.stripes[0].enters);
        const int result = s_fake_thunk_detour(value);
        s_fake_thunk_sink = result;
        return result;
    }

    /// A straight-line fake thunk that calls fake_thunk_helper before its enter count.
    DMK_TEST_FAKE_THUNK int helper_site_thunk(int value) noexcept
    {
        fake_thunk_helper();
        DMK_TEST_FAKE_INCREMENT(s_helper_thunk_block.stripes[0].enters);
        const int result = s_fake_thunk_detour(value);
        DMK_TEST_FAKE_INCREMENT(s_helper_thunk_block.stripes[0].exits);
        return result;
    }

#undef DMK_TEST_FAKE_INCREMENT
#undef DMK_TEST_FAKE_THUNK

    DMK_PROOF_SEEDED_TARGET(branching_thunk_target, 367)
    DMK_PROOF_SEEDED_TARGET(single_count_thunk_target, 373)
    DMK_PROOF_SEEDED_TARGET(helper_site_target, 359)

    /// Installs the fake thunk @p entry on @p target through the counted install.
    [[nodiscard]] Result<Hook>
    install_fake_thunk(const char *name, EchoFn target, EchoFn entry, DetourModKit::hook::detail::CountedBlock &block)
    {
        return DetourModKit::hook::detail::inline_at_counted(
            request_for(name, target),
            DetourModKit::hook::detail::CountedInstall{
                .entry = reinterpret_cast<void *>(entry),
                .block = &block,
            }
        );
    }

    /**
     * @brief Expects the counted install to refuse the fake thunk @p entry on @p target and to log @p cause.
     * @details The refusal leaves the target unpatched and unbooked, and it books no intentional leak.
     */
    void expect_thunk_refused(const char *name, EchoFn target, EchoFn entry, std::string_view cause)
    {
        const int pristine = dmk_test::call_unfolded(target, 5);
        const std::array<std::uint8_t, 16> pristine_bytes = entry_bytes(target);
        const std::size_t manager_before = hook_manager_leaks();
        const std::size_t residue_before = hook_residue_leaks();
        bool installed = false;
        ErrorCode code = ErrorCode::Ok;
        std::string text;
        {
            dmk_test::LoggerFileCapture capture{LogLevel::Error};
            const Result<Hook> refused = install_fake_thunk(name, target, entry, s_refused_thunk_block);
            installed = refused.has_value();
            code = installed ? ErrorCode::Ok : refused.error().code;
            text = capture.read_all();
        }
        ASSERT_FALSE(installed) << "the install accepted a thunk that the drain proof cannot cover";
        EXPECT_EQ(code, ErrorCode::InvalidDetourFunction);
        const std::string line =
            std::string{"'"} + name + "' has a shape that the drain proof cannot cover: " + std::string{cause} + ".";
        EXPECT_NE(text.find(line), std::string::npos) << "the fake thunk lost its shape in this build: " << text;
        EXPECT_FALSE(is_target_hooked(addr_of(target)));
        EXPECT_EQ(entry_bytes(target), pristine_bytes);
        EXPECT_EQ(dmk_test::call_unfolded(target, 5), pristine);
        EXPECT_EQ(hook_manager_leaks(), manager_before);
        EXPECT_EQ(hook_residue_leaks(), residue_before);
    }

#if defined(DMK_ENABLE_TEST_SEAMS)
    using DetourModKit::detail::counted_thunk_for_test;
    using DetourModKit::detail::CountedDrainStage;
    using DetourModKit::detail::CountedThunkProbe;

    using SplitEntry =
        DetourModKit::hook::detail::CountedSignature<decltype(&split_detour), CallerFrame>::entry<&split_detour>;

    std::atomic<bool> s_split_injected{false};

    // An enters-first reader reads enters before this entry and exits after it, so its equal sums report Retired.
    void inject_enter_between_reads(CountedDrainStage stage) noexcept
    {
        if (stage == CountedDrainStage::BetweenCounterReads && !s_split_injected.exchange(true))
        {
            std::atomic_ref<std::uint64_t>(SplitEntry::block.stripes[0].enters).fetch_add(1, std::memory_order_seq_cst);
        }
    }

    /// The state that the tail probe shares with its test case.
    struct TailScenario
    {
        ParkedCall *call{nullptr};
        void *after_exit_count{nullptr};
        std::atomic<bool> fired{false};
        bool joined{false};
        int result{0};
        std::optional<SuspendedThreadAt> thread;
    };

    TailScenario s_tail;

    /// Moves the parked call out of the thunk, then stops a synthetic thread just past the exit count.
    void park_a_thread_in_the_tail(CountedDrainStage stage) noexcept
    {
        if (stage != CountedDrainStage::AfterFirstPass || s_tail.fired.exchange(true))
        {
            return;
        }
        try
        {
            s_tail.result = s_tail.call->release_and_join();
            s_tail.joined = true;
        }
        catch (...)
        {
            return;
        }
        s_tail.thread.emplace(s_tail.after_exit_count);
    }

    /// Ends the synthetic tail thread and clears the shared tail state on every exit path.
    struct TailScenarioReset
    {
        ~TailScenarioReset() noexcept
        {
            s_tail.thread.reset();
            s_tail.call = nullptr;
            s_tail.after_exit_count = nullptr;
        }
    };

    constexpr std::size_t RELAY_STACK_WORDS = 1024;

    std::atomic<std::uintptr_t *> s_relay_stack_area{nullptr};
    std::atomic<bool> s_relay_spin_release{false};
    std::atomic<bool> s_relay_landed{false};
    std::atomic<int> s_relay_result{0};

    /// Publishes a buffer in its own stack frame, then spins in user mode until the test redirects it.
    DWORD WINAPI relay_parking_thread(void *) noexcept
    {
        volatile std::uintptr_t stack_area[RELAY_STACK_WORDS] = {};
        s_relay_stack_area.store(const_cast<std::uintptr_t *>(stack_area), std::memory_order_release);
        // GetTickCount64 reads shared user data, so the spin never enters the kernel.
        const ULONGLONG deadline = GetTickCount64() + static_cast<ULONGLONG>(PARK_BOUND.count()) * 1000;
        while (!s_relay_spin_release.load(std::memory_order_acquire) && GetTickCount64() < deadline)
        {
            YieldProcessor();
        }
        return 0;
    }

    /// The end of the return chain of the redirected thread: it records the result of the hooked call and exits.
    [[noreturn]] void relay_landing(std::uintptr_t result) noexcept
    {
        s_relay_result.store(static_cast<int>(result), std::memory_order_release);
        s_relay_landed.store(true, std::memory_order_release);
        ExitThread(0);
    }

    /**
     * @brief Plants the return target of the redirected thread at offset zero of @p page.
     * @details The stub passes rax to relay_landing as its argument and aligns the stack for the call.
     */
    void plant_relay_landing(dmk_test::ScratchPage &page) noexcept
    {
        page.put(0, {0x48, 0x89, 0xC1});       // mov rcx, rax
        page.put(3, {0x48, 0x83, 0xE4, 0xF0}); // and rsp, -16
        page.put(7, {0x48, 0x83, 0xEC, 0x20}); // sub rsp, 0x20
        page.put(11, {0x48, 0xB8});            // mov rax, imm64
        const auto landing = reinterpret_cast<std::uintptr_t>(&relay_landing);
        std::memcpy(reinterpret_cast<std::uint8_t *>(page.base()) + 13, &landing, sizeof(landing));
        page.put(21, {0xFF, 0xD0, 0xCC}); // call rax, then int3
        FlushInstructionCache(GetCurrentProcess(), page.base(), dmk_test::ScratchPage::PAGE_SIZE);
    }

    /**
     * @brief A real thread that the test suspends and points at one instruction with a stack of its own.
     * @details The destructor ends the thread on every exit path. A thread that the test never resumed ends by
     *          termination, so it never runs code that a failed proof freed.
     */
    class RedirectedThread
    {
    public:
        RedirectedThread() noexcept
        {
            s_relay_stack_area.store(nullptr, std::memory_order_release);
            s_relay_spin_release.store(false, std::memory_order_release);
            s_relay_landed.store(false, std::memory_order_release);
            s_relay_result.store(0, std::memory_order_release);
            m_thread = CreateThread(nullptr, 0, &relay_parking_thread, nullptr, 0, nullptr);
        }

        ~RedirectedThread() noexcept
        {
            if (m_thread == nullptr)
            {
                return;
            }
            if (m_redirected && !m_resumed)
            {
                (void)TerminateThread(m_thread, 0);
            }
            else if (m_suspended && !m_redirected)
            {
                s_relay_spin_release.store(true, std::memory_order_release);
                (void)ResumeThread(m_thread);
            }
            else
            {
                s_relay_spin_release.store(true, std::memory_order_release);
            }
            (void)WaitForSingleObject(m_thread, static_cast<DWORD>(PARK_BOUND.count() * 1000));
            (void)CloseHandle(m_thread);
        }

        RedirectedThread(const RedirectedThread &) = delete;
        RedirectedThread &operator=(const RedirectedThread &) = delete;
        RedirectedThread(RedirectedThread &&) = delete;
        RedirectedThread &operator=(RedirectedThread &&) = delete;

        /**
         * @brief Suspends the thread and sets it at @p instruction with @p argument in rcx.
         * @details The stack pointer sits like a function entry inside the published buffer, and its slot returns
         *          to @p landing. The buffer words above the slot serve as home space.
         * @return False when a step failed. The thread then spins on until the destructor releases it.
         */
        [[nodiscard]] bool redirect(const void *instruction, const void *landing, int argument) noexcept
        {
            if (m_thread == nullptr)
            {
                return false;
            }
            const auto deadline = std::chrono::steady_clock::now() + PARK_BOUND;
            while (s_relay_stack_area.load(std::memory_order_acquire) == nullptr &&
                   std::chrono::steady_clock::now() < deadline)
            {
                std::this_thread::sleep_for(std::chrono::milliseconds{1});
            }
            std::uintptr_t *const area = s_relay_stack_area.load(std::memory_order_acquire);
            if (area == nullptr || SuspendThread(m_thread) == static_cast<DWORD>(-1))
            {
                return false;
            }
            m_suspended = true;
            CONTEXT context{};
            context.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
            if (GetThreadContext(m_thread, &context) == FALSE)
            {
                return false;
            }
            const std::uintptr_t top = reinterpret_cast<std::uintptr_t>(area + RELAY_STACK_WORDS - 16);
            const std::uintptr_t slot = (top & ~std::uintptr_t{15}) - sizeof(std::uintptr_t);
            *reinterpret_cast<std::uintptr_t *>(slot) = reinterpret_cast<std::uintptr_t>(landing);
            context.Rsp = slot;
            context.Rip = reinterpret_cast<DWORD64>(instruction);
            context.Rcx = static_cast<DWORD64>(argument);
            if (SetThreadContext(m_thread, &context) == FALSE)
            {
                return false;
            }
            m_redirected = true;
            return true;
        }

        /// Resumes the redirected thread and reports whether the resume succeeded.
        [[nodiscard]] bool resume() noexcept
        {
            m_resumed = ResumeThread(m_thread) != static_cast<DWORD>(-1);
            return m_resumed;
        }

        /// Waits for the resumed thread to end. Returns false when it did not end in time.
        [[nodiscard]] bool join() noexcept
        {
            return m_resumed &&
                   WaitForSingleObject(m_thread, static_cast<DWORD>(PARK_BOUND.count() * 1000)) == WAIT_OBJECT_0;
        }

    private:
        HANDLE m_thread{nullptr};
        bool m_suspended{false};
        bool m_redirected{false};
        bool m_resumed{false};
    };

    DMK_PROOF_SEEDED_TARGET(entry_gap_target, 353)

    constexpr int ENTRY_GAP_DELTA = 0x600;
    constexpr int ENTRY_GAP_ARGUMENT = 43;

    std::atomic<bool> s_entry_gap_parked{false};
    std::atomic<bool> s_entry_gap_released{false};

    /**
     * @brief Parks each call until its release or @ref PARK_BOUND.
     * @details It calls no trampoline, so a wrong retirement frees no code on the path of the parked thread.
     */
    DMK_TEST_NOINLINE int entry_gap_detour(int value) noexcept
    {
        s_entry_gap_parked.store(true, std::memory_order_release);
        const ULONGLONG deadline = GetTickCount64() + static_cast<ULONGLONG>(PARK_BOUND.count()) * 1000;
        while (!s_entry_gap_released.load(std::memory_order_acquire) && GetTickCount64() < deadline)
        {
            YieldProcessor();
        }
        return value + ENTRY_GAP_DELTA;
    }

    /// The state that the entry gap probe shares with its test case.
    struct EntryGapScenario
    {
        RedirectedThread *thread{nullptr};
        std::atomic<bool> fired{false};
    };

    EntryGapScenario s_entry_gap;

    /// After the counter reads, resumes the thread at the thunk entry and waits until it parks inside the detour.
    void enter_the_detour_after_the_reads(CountedDrainStage stage) noexcept
    {
        if (stage != CountedDrainStage::AfterCounterReads || s_entry_gap.fired.exchange(true))
        {
            return;
        }
        if (s_entry_gap.thread != nullptr && s_entry_gap.thread->resume())
        {
            (void)wait_for(s_entry_gap_parked);
        }
    }

    /// Releases the entry gap detour and clears the probe state on every exit path.
    struct EntryGapReset
    {
        ~EntryGapReset() noexcept
        {
            s_entry_gap_released.store(true, std::memory_order_release);
            s_entry_gap.thread = nullptr;
        }
    };

    /// The calls that the decode of one thunk found outside and inside its counted window.
    struct ThunkCalls
    {
        std::size_t helper{0};
        std::size_t counted{0};
    };

    /**
     * @brief Counts the calls of the thunk of @p hook, decoded on a new thread.
     * @details The idle pass also reads the stack of the thread that retires. A probe on that stack holds the enter
     *          count, which equals the helper return when the locked increment follows the helper call.
     */
    [[nodiscard]] ThunkCalls thunk_calls_of(const Hook &hook)
    {
        ThunkCalls calls{};
        std::jthread(
            [&calls, &hook]
            {
                const CountedThunkProbe probe = counted_thunk_for_test(hook);
                calls = ThunkCalls{
                    .helper = probe.helper_calls,
                    .counted = probe.counted_calls,
                };
            }
        ).join();
        return calls;
    }

    /// Releases the parked fake thunk helper on every exit path.
    struct HelperRelease
    {
        ~HelperRelease() noexcept
        {
            s_helper_armed.store(false, std::memory_order_release);
            s_helper_released.store(true, std::memory_order_release);
        }
    };
#endif
} // namespace

// The thunk forwards eight arguments, four of them on the stack, both to an in-image target and to an export of
// another image.
TEST(HookCounted, ForwardsEightArgumentsIntact)
{
    {
        SCOPED_TRACE("in-image target");
        expect_eight_arguments_forwarded<1>(&weighted_eight, "CountedEight");
    }

    const HMODULE module = LoadLibraryA("hook_target_lib.dll");
    ASSERT_NE(module, nullptr) << "hook_target_lib.dll did not load: " << GetLastError();
    const auto exported =
        reinterpret_cast<Forward8Fn>(reinterpret_cast<void *>(GetProcAddress(module, "compute_mixed_eight")));
    EXPECT_NE(exported, nullptr) << "hook_target_lib.dll does not export compute_mixed_eight";
    if (exported != nullptr)
    {
        SCOPED_TRACE("exported target");
        expect_eight_arguments_forwarded<2>(exported, "CountedEightExport");
    }
    (void)FreeLibrary(module);
}

// Ten arguments put six on the stack, past the home space of the thunk frame.
TEST(HookCounted, ForwardsTenArgumentsIntact)
{
    const std::int64_t pristine = dmk_test::call_unfolded(&weighted_ten, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10);
    ASSERT_NE(dmk_test::call_unfolded(&weighted_ten, 1, 2, 3, 4, 5, 6, 7, 8, 10, 9), pristine)
        << "the target cannot tell a swapped stack argument";
    HookStack stack;
    ASSERT_NO_FATAL_FAILURE(arm_counted<&forward_ten_detour>(stack, "CountedTen", &weighted_ten, s_ten_original));

    EXPECT_EQ(dmk_test::call_unfolded(&weighted_ten, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10), pristine + FORWARD_DELTA);
    EXPECT_EQ(
        dmk_test::call_unfolded(&weighted_ten, -10, 9, -8, 7, -6, 5, -4, 3, -2, 1),
        dmk_test::call_unfolded(s_ten_original.load(), -10, 9, -8, 7, -6, 5, -4, 3, -2, 1) + FORWARD_DELTA
    );

    expect_restored(stack, 1);
    EXPECT_EQ(dmk_test::call_unfolded(&weighted_ten, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10), pristine);
}

// The frame takes the first parameter of the detour, so the thunk shifts all ten arguments by one position, six of
// them on the stack.
TEST(HookCounted, CallerFrameForwardsStackArguments)
{
    // A direct call with a constant lets GCC call a clone of the caller, which has an unwind record of its own.
    const std::int64_t pristine = dmk_test::call_unfolded(&call_frame_ten_target, 3);
    HookStack stack;
    ASSERT_NO_FATAL_FAILURE(
        arm_counted<&frame_ten_detour>(stack, "CountedFrameTen", &frame_ten_target, s_frame_ten_original)
    );
    s_frame_ten_return.store(nullptr, std::memory_order_release);

    EXPECT_EQ(dmk_test::call_unfolded(&call_frame_ten_target, 3), pristine + FRAME_DELTA);
    const void *const returned = s_frame_ten_return.load(std::memory_order_acquire);
    ASSERT_NE(returned, nullptr) << "the detour did not run";
    EXPECT_TRUE(returns_into(returned, reinterpret_cast<const void *>(&call_frame_ten_target)))
        << "the frame names " << returned << ", which is not a return into the caller of the hooked target";
    EXPECT_EQ(
        dmk_test::call_unfolded(&frame_ten_target, -10, 9, -8, 7, -6, 5, -4, 3, -2, 1),
        dmk_test::call_unfolded(s_frame_ten_original.load(), -10, 9, -8, 7, -6, 5, -4, 3, -2, 1) + FRAME_DELTA
    );

    expect_restored(stack, 1);
    EXPECT_EQ(dmk_test::call_unfolded(&call_frame_ten_target, 3), pristine);
}

// The thunk forwards float and double arguments in their vector registers and on the stack, and both result kinds.
TEST(HookCounted, ForwardsFloatingPointArgumentsAndResults)
{
    const double blend_pristine = dmk_test::call_unfolded(&blend_target, 1.5f, 2.5, -3.5f, 4.5, 5.5f, -6.5);
    ASSERT_NE(dmk_test::call_unfolded(&blend_target, 1.5f, 2.5, -3.5f, 4.5, 5.5f, 6.5), blend_pristine)
        << "the target cannot tell a changed stack argument";
    const float shrink_pristine = dmk_test::call_unfolded(&shrink_target, 8.0, 0.5f, 3, -1.5f, 2.25f);
    HookStack stack;
    ASSERT_NO_FATAL_FAILURE(arm_counted<&blend_detour>(stack, "CountedBlend", &blend_target, s_blend_original));
    ASSERT_NO_FATAL_FAILURE(arm_counted<&shrink_detour>(stack, "CountedShrink", &shrink_target, s_shrink_original));

    EXPECT_EQ(dmk_test::call_unfolded(&blend_target, 1.5f, 2.5, -3.5f, 4.5, 5.5f, -6.5), blend_pristine + FLOAT_DELTA);
    EXPECT_EQ(
        dmk_test::call_unfolded(&blend_target, -0.25f, 7.0, 0.125f, -9.5, 3.0f, 11.75),
        dmk_test::call_unfolded(s_blend_original.load(), -0.25f, 7.0, 0.125f, -9.5, 3.0f, 11.75) + FLOAT_DELTA
    );
    EXPECT_EQ(
        dmk_test::call_unfolded(&shrink_target, 8.0, 0.5f, 3, -1.5f, 2.25f),
        shrink_pristine + static_cast<float>(FLOAT_DELTA)
    );
    EXPECT_EQ(
        dmk_test::call_unfolded(&shrink_target, -4.0, 1.5f, -7, 0.75f, -0.5f),
        dmk_test::call_unfolded(s_shrink_original.load(), -4.0, 1.5f, -7, 0.75f, -0.5f) +
            static_cast<float>(FLOAT_DELTA)
    );

    expect_restored(stack, 2);
    EXPECT_EQ(dmk_test::call_unfolded(&blend_target, 1.5f, 2.5, -3.5f, 4.5, 5.5f, -6.5), blend_pristine);
    EXPECT_EQ(dmk_test::call_unfolded(&shrink_target, 8.0, 0.5f, 3, -1.5f, 2.25f), shrink_pristine);
}

// The thunk returns an __m128 in its vector register and forwards two __m128 arguments, each through a pointer to a
// caller copy, around a float in a vector register.
TEST(HookCounted, ForwardsVectorArgumentsAndAVectorResult)
{
    const __m128 first = _mm_setr_ps(1.5f, -2.0f, 3.25f, 4.0f);
    const __m128 second = _mm_setr_ps(-0.5f, 6.0f, 7.75f, -8.0f);
    const Lanes pristine = lanes_of(dmk_test::call_unfolded(&vector_target, first, 2.0f, second));
    ASSERT_NE(lanes_of(dmk_test::call_unfolded(&vector_target, second, 2.0f, first)), pristine)
        << "the target cannot tell swapped vector arguments";
    HookStack stack;
    ASSERT_NO_FATAL_FAILURE(arm_counted<&vector_detour>(stack, "CountedVector", &vector_target, s_vector_original));

    EXPECT_EQ(lanes_of(dmk_test::call_unfolded(&vector_target, first, 2.0f, second)), with_vector_delta(pristine));
    EXPECT_EQ(
        lanes_of(dmk_test::call_unfolded(&vector_target, second, -3.0f, first)),
        with_vector_delta(lanes_of(dmk_test::call_unfolded(s_vector_original.load(), second, -3.0f, first)))
    );

    expect_restored(stack, 1);
    EXPECT_EQ(lanes_of(dmk_test::call_unfolded(&vector_target, first, 2.0f, second)), pristine);
}

// Ten arguments of six kinds take the integer and vector registers by position. The stack carries a pointer, a float,
// a byte, a double, a short, and an eight-byte struct.
TEST(HookCounted, ForwardsTenMixedArgumentsIntact)
{
    const std::int32_t pointed = 7;
    const std::int32_t other_pointed = -9;
    const SmallPod pod{
        .x = 11,
        .y = -3,
    };
    const SmallPod other_pod{
        .x = -2,
        .y = 5,
    };
    constexpr std::int64_t WIDE = std::int64_t{1} << 40;
    const double pristine = dmk_test::call_unfolded(
        &mixed_ten_target,
        -5,
        2.5,
        0.75f,
        WIDE,
        &pointed,
        -1.25f,
        std::uint8_t{200},
        3.5,
        std::int16_t{-300},
        pod
    );
    ASSERT_NE(
        dmk_test::call_unfolded(
            &mixed_ten_target,
            -5,
            2.5,
            0.75f,
            WIDE,
            &pointed,
            -1.25f,
            std::uint8_t{201},
            3.5,
            std::int16_t{-300},
            pod
        ),
        pristine
    ) << "the target cannot tell a changed stack argument";
    HookStack stack;
    ASSERT_NO_FATAL_FAILURE(
        arm_counted<&mixed_ten_detour>(stack, "CountedMixedTen", &mixed_ten_target, s_mixed_ten_original)
    );

    EXPECT_EQ(
        dmk_test::call_unfolded(
            &mixed_ten_target,
            -5,
            2.5,
            0.75f,
            WIDE,
            &pointed,
            -1.25f,
            std::uint8_t{200},
            3.5,
            std::int16_t{-300},
            pod
        ),
        pristine + FLOAT_DELTA
    );
    EXPECT_EQ(
        dmk_test::call_unfolded(
            &mixed_ten_target,
            9,
            -0.125,
            4.5f,
            -WIDE,
            &other_pointed,
            0.5f,
            std::uint8_t{3},
            -7.25,
            std::int16_t{1234},
            other_pod
        ),
        dmk_test::call_unfolded(
            s_mixed_ten_original.load(),
            9,
            -0.125,
            4.5f,
            -WIDE,
            &other_pointed,
            0.5f,
            std::uint8_t{3},
            -7.25,
            std::int16_t{1234},
            other_pod
        ) + FLOAT_DELTA
    );

    expect_restored(stack, 1);
    EXPECT_EQ(
        dmk_test::call_unfolded(
            &mixed_ten_target,
            -5,
            2.5,
            0.75f,
            WIDE,
            &pointed,
            -1.25f,
            std::uint8_t{200},
            3.5,
            std::int16_t{-300},
            pod
        ),
        pristine
    );
}

// A small struct travels in one register, and a large one through a pointer to a caller copy. A large result returns
// through the hidden result pointer, which shifts the other arguments by one register.
TEST(HookCounted, ForwardsStructsByValueAndThroughTheHiddenResult)
{
    const SmallPod narrow{
        .x = 3,
        .y = -4,
    };
    const LargePod wide{
        .first = 5,
        .second = -6,
        .third = 7,
    };
    const std::int64_t small_pristine = dmk_test::call_unfolded(&small_pod_target, narrow, 9);
    const std::int64_t large_pristine = dmk_test::call_unfolded(&large_pod_target, 2, wide, -8);
    const LargePod result_pristine = dmk_test::call_unfolded(&large_result_target, 11, 4);
    HookStack stack;
    ASSERT_NO_FATAL_FAILURE(
        arm_counted<&small_pod_detour>(stack, "CountedSmallPod", &small_pod_target, s_small_pod_original)
    );
    ASSERT_NO_FATAL_FAILURE(
        arm_counted<&large_pod_detour>(stack, "CountedLargePod", &large_pod_target, s_large_pod_original)
    );
    ASSERT_NO_FATAL_FAILURE(
        arm_counted<&large_result_detour>(stack, "CountedLargeResult", &large_result_target, s_large_result_original)
    );

    EXPECT_EQ(dmk_test::call_unfolded(&small_pod_target, narrow, 9), small_pristine + FORWARD_DELTA);
    EXPECT_EQ(dmk_test::call_unfolded(&large_pod_target, 2, wide, -8), large_pristine + FORWARD_DELTA);
    EXPECT_EQ(dmk_test::call_unfolded(&large_result_target, 11, 4), shifted(result_pristine));
    const LargePod other{
        .first = -1,
        .second = 2,
        .third = -3,
    };
    EXPECT_EQ(
        dmk_test::call_unfolded(&large_pod_target, -5, other, 6),
        dmk_test::call_unfolded(s_large_pod_original.load(), -5, other, 6) + FORWARD_DELTA
    );
    EXPECT_EQ(
        dmk_test::call_unfolded(&large_result_target, -2, 9),
        shifted(dmk_test::call_unfolded(s_large_result_original.load(), -2, 9))
    );

    expect_restored(stack, 3);
    EXPECT_EQ(dmk_test::call_unfolded(&small_pod_target, narrow, 9), small_pristine);
    EXPECT_EQ(dmk_test::call_unfolded(&large_pod_target, 2, wide, -8), large_pristine);
    EXPECT_EQ(dmk_test::call_unfolded(&large_result_target, 11, 4), result_pristine);
}

// A reference reaches the detour and the target as the address of the caller's object, and a void detour runs.
TEST(HookCounted, ForwardsReferencesAndAVoidResult)
{
    int slot = 10;
    const int lvalue_pristine = call_forwarding(&lvalue_target, slot, 4);
    ASSERT_EQ(slot, lvalue_pristine);
    MovePayload payload{
        .value = 77,
        .moves = 0,
    };
    const std::int64_t rvalue_pristine = call_forwarding(&rvalue_target, static_cast<MovePayload &&>(payload));
    std::int64_t out = 0;
    call_forwarding(&void_target, 6, -2, &out);
    const std::int64_t void_pristine = out;
    HookStack stack;
    ASSERT_NO_FATAL_FAILURE(arm_counted<&lvalue_detour>(stack, "CountedLvalue", &lvalue_target, s_lvalue_original));
    ASSERT_NO_FATAL_FAILURE(arm_counted<&rvalue_detour>(stack, "CountedRvalue", &rvalue_target, s_rvalue_original));
    ASSERT_NO_FATAL_FAILURE(arm_counted<&void_detour>(stack, "CountedVoid", &void_target, s_void_original));

    slot = 10;
    EXPECT_EQ(call_forwarding(&lvalue_target, slot, 4), lvalue_pristine + REFERENCE_DELTA);
    EXPECT_EQ(slot, lvalue_pristine + REFERENCE_DELTA) << "the target and the detour did not write the caller's object";
    EXPECT_EQ(s_lvalue_seen.load(std::memory_order_acquire), &slot);

    MovePayload moved{
        .value = 77,
        .moves = 0,
    };
    EXPECT_EQ(call_forwarding(&rvalue_target, static_cast<MovePayload &&>(moved)), rvalue_pristine + REFERENCE_DELTA);
    EXPECT_EQ(s_rvalue_seen.load(std::memory_order_acquire), &moved);
    EXPECT_EQ(moved.value, 0) << "the target did not take over the caller's object";
    EXPECT_EQ(moved.moves, 1 + REFERENCE_DELTA);

    const int void_calls = s_void_detour_calls.load(std::memory_order_relaxed);
    out = 0;
    call_forwarding(&void_target, 6, -2, &out);
    EXPECT_EQ(out, void_pristine + FORWARD_DELTA);
    EXPECT_EQ(s_void_detour_calls.load(std::memory_order_relaxed), void_calls + 1);

    expect_restored(stack, 3);
    slot = 10;
    EXPECT_EQ(call_forwarding(&lvalue_target, slot, 4), lvalue_pristine);
    out = 0;
    call_forwarding(&void_target, 6, -2, &out);
    EXPECT_EQ(out, void_pristine);
}

TEST(HookCounted, SignatureAdmitsOnlyForwardableDetours)
{
    EXPECT_TRUE(counted_signatures_classify<CallerFrame>());
}

TEST(HookCounted, InstallRefusesABranchingThunk)
{
    expect_thunk_refused(
        "CountedBranchingThunk",
        &branching_thunk_target,
        &branching_thunk,
        "the thunk branches or traps, so its code is not straight-line"
    );
}

TEST(HookCounted, InstallRefusesAThunkWithOneCount)
{
    expect_thunk_refused(
        "CountedSingleCountThunk",
        &single_count_thunk_target,
        &single_count_thunk,
        "the thunk does not hold exactly two locked increments"
    );
}

// The relay jumps into the thunk, so the frame names the return into the function that called the hooked target.
TEST(HookCounted, CallerFrameCarriesTheGameReturnAddress)
{
    const int pristine = call_frame_return_target(5);
    Result<Hook> installed = inline_at<&frame_return_detour>(request_for("CountedFrameReturn", &frame_return_target));
    ASSERT_TRUE(installed.has_value()) << installed.error().message();
    HookStack stack;
    Hook &hook = stack.push(std::move(*installed));
    s_frame_return_original.store(hook.original<EchoFn>(), std::memory_order_release);
    ASSERT_TRUE(hook.enable().has_value());
    s_frame_return_address.store(nullptr, std::memory_order_release);

    EXPECT_EQ(call_frame_return_target(5), pristine + FRAME_DELTA);
    const void *const returned = s_frame_return_address.load(std::memory_order_acquire);
    ASSERT_NE(returned, nullptr) << "the detour did not run";
    EXPECT_TRUE(returns_into(returned, reinterpret_cast<const void *>(&call_frame_return_target)))
        << "the frame names " << returned << ", which is not a return into the caller of the hooked target";

    EXPECT_EQ(stack.retire(RETIRE_DEADLINE).outcome, RetirementOutcome::Retired);
}

// The slot is the stack word of the game call. It lies on the current stack, above every frame of the detour and
// below the frame of the caller.
TEST(HookCounted, CallerFrameSlotMatchesTheCallerStack)
{
    const int pristine = call_frame_slot_target(7);
    Result<Hook> installed = inline_at<&frame_slot_detour>(request_for("CountedFrameSlot", &frame_slot_target));
    ASSERT_TRUE(installed.has_value()) << installed.error().message();
    HookStack stack;
    Hook &hook = stack.push(std::move(*installed));
    s_frame_slot_original.store(hook.original<EchoFn>(), std::memory_order_release);
    ASSERT_TRUE(hook.enable().has_value());
    s_frame_slot = FrameSlotObservation{};

    EXPECT_EQ(call_frame_slot_target(7), pristine + FRAME_DELTA);
    const FrameSlotObservation observed = s_frame_slot;
    ASSERT_NE(observed.slot, nullptr) << "the detour did not run";
    EXPECT_TRUE(returns_into(observed.return_address, reinterpret_cast<const void *>(&call_frame_slot_target)));
    const auto slot = reinterpret_cast<std::uintptr_t>(observed.slot);
    EXPECT_GE(slot, observed.stack_low);
    EXPECT_LT(slot, observed.stack_high);
    EXPECT_LT(observed.detour_local, slot) << "the slot lies inside the frame of the detour";
    EXPECT_LT(slot, s_frame_slot_caller_local.load(std::memory_order_acquire))
        << "the slot lies above the frame of the caller";

    EXPECT_EQ(stack.retire(RETIRE_DEADLINE).outcome, RetirementOutcome::Retired);
}

#if defined(DMK_ENABLE_TEST_SEAMS)
// The unwind record of the thunk covers its entry and the return from the detour. The two counts bound the call. A
// scalar and pointer signature compiles to a thunk with one call inside the counts, none outside, and a balanced frame.
TEST(HookCounted, ThunkRangeCoversEntryAndReturn)
{
    Result<Hook> installed = inline_at<&thunk_range_detour>(request_for("CountedThunkRange", &thunk_range_target));
    ASSERT_TRUE(installed.has_value()) << installed.error().message();
    HookStack stack;
    Hook &hook = stack.push(std::move(*installed));
    s_thunk_range_original.store(hook.original<PointerFn>(), std::memory_order_release);
    ASSERT_TRUE(hook.enable().has_value());

    const CountedThunkProbe probe = counted_thunk_for_test(hook);
    ASSERT_NE(probe.entry, nullptr) << "the hook has no decoded thunk";
    using Entry = DetourModKit::hook::detail::CountedSignature<decltype(&thunk_range_detour), CallerFrame>::entry<
        &thunk_range_detour>;
    EXPECT_EQ(probe.entry, reinterpret_cast<void *>(&Entry::entry));
    const auto begin = reinterpret_cast<std::uintptr_t>(probe.entry);
    const auto end = reinterpret_cast<std::uintptr_t>(probe.range_end);
    const auto enter_count = reinterpret_cast<std::uintptr_t>(probe.enter_count);
    const auto after_exit_count = reinterpret_cast<std::uintptr_t>(probe.after_exit_count);
    EXPECT_LE(begin, enter_count);
    EXPECT_LT(enter_count, after_exit_count);
    EXPECT_LE(after_exit_count, end);
    EXPECT_EQ(probe.helper_calls, 0u);
    EXPECT_EQ(probe.counted_calls, 1u);
    EXPECT_EQ(probe.pushes, probe.pops) << "the thunk frame is not balanced before its return";

    s_thunk_range_return.store(nullptr, std::memory_order_release);
    int out = 0;
    EXPECT_EQ(dmk_test::call_unfolded(&thunk_range_target, 5, &out), 12);
    EXPECT_EQ(out, 10);
    const auto returned = reinterpret_cast<std::uintptr_t>(s_thunk_range_return.load(std::memory_order_acquire));
    ASSERT_NE(returned, 0u) << "the detour did not run";
    EXPECT_GE(returned, begin);
    EXPECT_LT(returned, end);
    EXPECT_GT(returned, enter_count) << "the detour returns to a point before the enter count";
    EXPECT_LT(returned, after_exit_count) << "the detour returns to a point after the exit count";

    EXPECT_EQ(stack.retire(RETIRE_DEADLINE).outcome, RetirementOutcome::Retired);
}

// A longjmp out of the detour unwinds through the thunk and skips its exit count. The call stays counted, so retire
// reports Busy and changes nothing, and the teardown keeps the backend pinned. This detour serves no other case.
TEST(HookCounted, SehUnwindThroughTheThunkReportsBusyNotACrash)
{
    Result<Hook> installed = inline_at<&unwind_detour>(request_for("CountedUnwind", &unwind_target));
    ASSERT_TRUE(installed.has_value()) << installed.error().message();
    HookStack stack;
    Hook &hook = stack.push(std::move(*installed));
    ASSERT_TRUE(hook.enable().has_value());
    ASSERT_EQ(dmk_test::call_unfolded(&unwind_target, 5), 5 + UNWIND_DELTA);
    const std::array<std::uint8_t, 16> armed = entry_bytes(&unwind_target);

    s_unwind_escape.store(true, std::memory_order_release);
    ASSERT_TRUE(unwind_out_of_detour(5)) << "the detour did not leave through the unwind";

    const HookRetirement busy = stack.retire(BUSY_DEADLINE);
    ASSERT_EQ(busy.outcome, RetirementOutcome::Busy);
    EXPECT_EQ(busy.refusal, ErrorCode::Ok);
    EXPECT_EQ(busy.in_flight, 1u);
    EXPECT_EQ(stack.size(), 1u);
    EXPECT_TRUE(hook.is_enabled());
    EXPECT_EQ(entry_bytes(&unwind_target), armed);
    EXPECT_EQ(dmk_test::call_unfolded(&unwind_target, 5), 5 + UNWIND_DELTA) << "the Busy retirement kept the relay off";

    const std::size_t manager_before = hook_manager_leaks();
    stack.clear();
    EXPECT_EQ(hook_manager_leaks(), manager_before + 1) << "the stuck count did not keep the backend pinned";
}

TEST(HookCounted, SplitCountersReadExitsFirst)
{
    Result<Hook> installed = inline_at<&split_detour>(request_for("CountedSplit", &split_target));
    ASSERT_TRUE(installed.has_value()) << installed.error().message();
    HookStack stack;
    Hook &hook = stack.push(std::move(*installed));
    ASSERT_TRUE(hook.enable().has_value());
    ASSERT_EQ(dmk_test::call_unfolded(&split_target, 5), 5 + SPLIT_DELTA);
    const std::array<std::uint8_t, 16> armed = entry_bytes(&split_target);

    s_split_injected.store(false, std::memory_order_release);
    HookRetirement busy{};
    {
        const CountedDrainProbeScope scope{&inject_enter_between_reads};
        busy = stack.retire(BUSY_DEADLINE);
    }
    ASSERT_TRUE(s_split_injected.load(std::memory_order_acquire)) << "the drain never read the counters";
    ASSERT_EQ(busy.outcome, RetirementOutcome::Busy);
    EXPECT_EQ(busy.refusal, ErrorCode::Ok);
    EXPECT_EQ(busy.in_flight, 1u);
    EXPECT_EQ(stack.size(), 1u);
    EXPECT_TRUE(hook.is_enabled());
    EXPECT_EQ(entry_bytes(&split_target), armed);
    EXPECT_EQ(dmk_test::call_unfolded(&split_target, 5), 5 + SPLIT_DELTA);

    // The matching exit closes the injected call.
    std::atomic_ref<std::uint64_t>(SplitEntry::block.stripes[0].exits).fetch_add(1, std::memory_order_seq_cst);
    const HookRetirement retired = stack.retire(RETIRE_DEADLINE);
    EXPECT_EQ(retired.outcome, RetirementOutcome::Retired);
    EXPECT_EQ(retired.restored, 1u);
}

// A thread at the thunk entry sits before its enter count. The sums miss it, and the pass over the thunk range keeps
// the retirement Busy.
TEST(HookCounted, ThreadInThePrologueKeepsBusy)
{
    Result<Hook> installed = inline_at<&prologue_detour>(request_for("CountedPrologue", &prologue_target));
    ASSERT_TRUE(installed.has_value()) << installed.error().message();
    HookStack stack;
    Hook &hook = stack.push(std::move(*installed));
    ASSERT_TRUE(hook.enable().has_value());
    const CountedThunkProbe probe = counted_thunk_for_test(hook);
    ASSERT_NE(probe.entry, nullptr) << "the hook has no decoded thunk";

    {
        const SuspendedThreadAt parked{probe.entry};
        ASSERT_TRUE(parked.ready()) << "the synthetic thread did not take the thunk entry";
        const HookRetirement busy = stack.retire(BUSY_DEADLINE);
        ASSERT_EQ(busy.outcome, RetirementOutcome::Busy);
        EXPECT_EQ(busy.refusal, ErrorCode::Ok);
        EXPECT_EQ(busy.in_flight, 0u);
        EXPECT_EQ(stack.size(), 1u);
        EXPECT_TRUE(hook.is_enabled());
        EXPECT_EQ(dmk_test::call_unfolded(&prologue_target, 5), 5 + PROLOGUE_DELTA);
    }

    const HookRetirement retired = stack.retire(RETIRE_DEADLINE);
    EXPECT_EQ(retired.outcome, RetirementOutcome::Retired);
    EXPECT_EQ(retired.restored, 1u);
}

// A real thread waits at the thunk entry, before its enter count. Pass 1 sees it there, so the drain never reads the
// counters, and the probe never runs. Without pass 1, the probe lets the thread into the detour after equal reads.
// Pass 2 cannot see it there, so the retirement wrongly retires.
TEST(HookCounted, ThreadBeforeItsEnterCountKeepsBusy)
{
    dmk_test::ScratchPage landing;
    ASSERT_TRUE(landing.ok());
    plant_relay_landing(landing);
    Result<Hook> installed = inline_at<&entry_gap_detour>(request_for("CountedEntryGap", &entry_gap_target));
    ASSERT_TRUE(installed.has_value()) << installed.error().message();
    HookStack stack;
    Hook &hook = stack.push(std::move(*installed));
    ASSERT_TRUE(hook.enable().has_value());
    const CountedThunkProbe probe = counted_thunk_for_test(hook);
    ASSERT_NE(probe.entry, nullptr) << "the hook has no decoded thunk";

    s_entry_gap_parked.store(false, std::memory_order_release);
    s_entry_gap_released.store(false, std::memory_order_release);
    s_entry_gap.fired.store(false, std::memory_order_release);
    RedirectedThread thread;
    // Declared after the thread, so the release precedes the join on every exit path.
    const EntryGapReset reset;
    ASSERT_TRUE(thread.redirect(probe.entry, landing.base(), ENTRY_GAP_ARGUMENT));
    s_entry_gap.thread = &thread;

    HookRetirement busy{};
    {
        const CountedDrainProbeScope scope{&enter_the_detour_after_the_reads};
        busy = stack.retire(BUSY_DEADLINE);
    }
    EXPECT_FALSE(s_entry_gap.fired.load(std::memory_order_acquire))
        << "the drain read the counters while a thread sat at the thunk entry";
    ASSERT_EQ(busy.outcome, RetirementOutcome::Busy) << "the drain missed a thread before its enter count";
    EXPECT_EQ(busy.refusal, ErrorCode::Ok);
    EXPECT_EQ(busy.in_flight, 0u);
    EXPECT_EQ(stack.size(), 1u);
    EXPECT_TRUE(hook.is_enabled());

    ASSERT_TRUE(thread.resume());
    ASSERT_TRUE(wait_for(s_entry_gap_parked)) << "the resumed thread never reached the detour";
    s_entry_gap_released.store(true, std::memory_order_release);
    ASSERT_TRUE(thread.join()) << "the redirected thread did not end";
    EXPECT_TRUE(s_relay_landed.load(std::memory_order_acquire)) << "the thread did not return to the landing";
    EXPECT_EQ(s_relay_result.load(std::memory_order_acquire), ENTRY_GAP_ARGUMENT + ENTRY_GAP_DELTA);

    const HookRetirement retired = stack.retire(RETIRE_DEADLINE);
    EXPECT_EQ(retired.outcome, RetirementOutcome::Retired);
    EXPECT_EQ(retired.restored, 1u);
}

// A thread inside a call before the enter count runs outside the thunk range and outside the counts. Only the stack
// read finds its return into the thunk, so the retirement stays Busy until the call returns.
TEST(HookCounted, ThreadInAHelperBeforeTheEnterCountKeepsBusy)
{
    Result<Hook> installed =
        install_fake_thunk("CountedHelperSite", &helper_site_target, &helper_site_thunk, s_helper_thunk_block);
    ASSERT_TRUE(installed.has_value()) << installed.error().message();
    HookStack stack;
    Hook &hook = stack.push(std::move(*installed));
    ASSERT_TRUE(hook.enable().has_value());
    const ThunkCalls calls = thunk_calls_of(hook);
    ASSERT_EQ(calls.helper, 1u) << "the fake thunk lost its call before the enter count in this build";
    ASSERT_EQ(calls.counted, 1u);

    s_helper_parked.store(false, std::memory_order_release);
    s_helper_released.store(false, std::memory_order_release);
    s_helper_armed.store(true, std::memory_order_release);
    std::atomic<int> parked_result{0};
    std::jthread caller(
        [&parked_result]
        { parked_result.store(dmk_test::call_unfolded(&helper_site_target, 5), std::memory_order_release); }
    );
    // Declared after the caller, so the release precedes the join on every exit path.
    const HelperRelease release;
    ASSERT_TRUE(wait_for(s_helper_parked)) << "the call never reached the helper";

    const HookRetirement busy = stack.retire(BUSY_DEADLINE);
    ASSERT_EQ(busy.outcome, RetirementOutcome::Busy) << "the drain missed a thread inside the helper";
    EXPECT_EQ(busy.refusal, ErrorCode::Ok);
    EXPECT_EQ(busy.in_flight, 0u);
    EXPECT_EQ(stack.size(), 1u);
    EXPECT_TRUE(hook.is_enabled());

    s_helper_released.store(true, std::memory_order_release);
    caller.join();
    EXPECT_EQ(parked_result.load(std::memory_order_acquire), 5 + FAKE_THUNK_DELTA);
    const HookRetirement retired = stack.retire(RETIRE_DEADLINE);
    EXPECT_EQ(retired.outcome, RetirementOutcome::Retired);
    EXPECT_EQ(retired.restored, 1u);
}

// A thread inside the detour sits between its counts, so the sums differ until the call returns.
TEST(HookCounted, ThreadInTheBodyKeepsBusy)
{
    const int pristine = dmk_test::call_unfolded(&body_target, 5);
    Result<Hook> installed = inline_at<&parked_detour<1>>(request_for("CountedBody", &body_target));
    ASSERT_TRUE(installed.has_value()) << installed.error().message();
    HookStack stack;
    Hook &hook = stack.push(std::move(*installed));
    park_signals<1>.next.store(hook.original<EchoFn>(), std::memory_order_release);
    ASSERT_TRUE(hook.enable().has_value());

    ParkedCall call{park_signals<1>, &body_target, 5};
    ASSERT_TRUE(call.wait_until_parked()) << "the call never reached the detour";
    const HookRetirement busy = stack.retire(BUSY_DEADLINE);
    ASSERT_EQ(busy.outcome, RetirementOutcome::Busy);
    EXPECT_EQ(busy.refusal, ErrorCode::Ok);
    EXPECT_EQ(busy.in_flight, 1u);
    EXPECT_EQ(stack.size(), 1u);
    EXPECT_TRUE(hook.is_enabled());

    EXPECT_EQ(call.release_and_join(), pristine + PARKED_DELTA);
    const HookRetirement retired = stack.retire(RETIRE_DEADLINE);
    EXPECT_EQ(retired.outcome, RetirementOutcome::Retired);
    EXPECT_EQ(retired.restored, 1u);
}

// The probe lets the parked call return and then stops a thread just past the exit count. The sums are then equal, so
// only pass 2 sees the thread in the tail.
TEST(HookCounted, ThreadInTheTailKeepsBusy)
{
    const int pristine = dmk_test::call_unfolded(&tail_target, 5);
    Result<Hook> installed = inline_at<&parked_detour<2>>(request_for("CountedTail", &tail_target));
    ASSERT_TRUE(installed.has_value()) << installed.error().message();
    HookStack stack;
    Hook &hook = stack.push(std::move(*installed));
    park_signals<2>.next.store(hook.original<EchoFn>(), std::memory_order_release);
    ASSERT_TRUE(hook.enable().has_value());
    const CountedThunkProbe probe = counted_thunk_for_test(hook);
    ASSERT_NE(probe.after_exit_count, nullptr) << "the hook has no decoded thunk";

    ParkedCall call{park_signals<2>, &tail_target, 5};
    const TailScenarioReset reset;
    ASSERT_TRUE(call.wait_until_parked()) << "the call never reached the detour";
    s_tail.call = &call;
    s_tail.after_exit_count = probe.after_exit_count;
    s_tail.fired.store(false, std::memory_order_release);
    s_tail.joined = false;

    HookRetirement busy{};
    {
        const CountedDrainProbeScope scope{&park_a_thread_in_the_tail};
        busy = stack.retire(BUSY_DEADLINE);
    }
    ASSERT_TRUE(s_tail.fired.load(std::memory_order_acquire)) << "pass 1 never succeeded";
    ASSERT_TRUE(s_tail.joined) << "the parked call did not return";
    EXPECT_EQ(s_tail.result, pristine + PARKED_DELTA);
    ASSERT_TRUE(s_tail.thread.has_value() && s_tail.thread->ready()) << "no synthetic thread took the tail";
    ASSERT_EQ(busy.outcome, RetirementOutcome::Busy) << "pass 2 missed the thread past the exit count";
    EXPECT_EQ(busy.in_flight, 0u);
    EXPECT_EQ(stack.size(), 1u);
    EXPECT_TRUE(hook.is_enabled());

    s_tail.thread.reset();
    const HookRetirement retired = stack.retire(RETIRE_DEADLINE);
    EXPECT_EQ(retired.outcome, RetirementOutcome::Retired);
    EXPECT_EQ(retired.restored, 1u);
}

// A thread at the relay instruction is outside the thunk, so the stack retires. The restore sees the thread inside the
// trampoline and keeps it as HookResidue. Resumed, the thread runs the original through the kept trampoline.
TEST(HookCounted, ThreadAtTheRelayRetires)
{
    const int pristine = dmk_test::call_unfolded(&relay_target, RELAY_ARGUMENT);
    const std::array<std::uint8_t, 16> pristine_bytes = entry_bytes(&relay_target);
    dmk_test::ScratchPage landing;
    ASSERT_TRUE(landing.ok());
    plant_relay_landing(landing);

    Result<Hook> installed = inline_at<&relay_detour>(request_for("CountedRelay", &relay_target));
    ASSERT_TRUE(installed.has_value()) << installed.error().message();
    HookStack stack;
    Hook &hook = stack.push(std::move(*installed));
    s_relay_original.store(hook.original<EchoFn>(), std::memory_order_release);
    ASSERT_TRUE(hook.enable().has_value());
    ASSERT_EQ(dmk_test::call_unfolded(&relay_target, RELAY_ARGUMENT), pristine + RELAY_DELTA);
    const int detour_calls = s_relay_detour_calls.load(std::memory_order_relaxed);

    const auto *const entry = reinterpret_cast<const std::uint8_t *>(&relay_target);
    ASSERT_EQ(entry[0], 0xE9) << "the top layer patch is not a rel32 jump";
    std::int32_t displacement = 0;
    std::memcpy(&displacement, entry + 1, sizeof(displacement));
    const std::uint8_t *const relay = entry + 5 + displacement;
    ASSERT_EQ(relay[0], 0xFF) << "the jump does not reach an indirect relay";
    ASSERT_EQ(relay[1], 0x25) << "the jump does not reach an indirect relay";

    RedirectedThread thread;
    ASSERT_TRUE(thread.redirect(relay, landing.base(), RELAY_ARGUMENT));
    const std::size_t residue_before = hook_residue_leaks();
    const std::size_t manager_before = hook_manager_leaks();

    const HookRetirement retired = stack.retire(RETIRE_DEADLINE);
    EXPECT_EQ(retired.outcome, RetirementOutcome::Retired);
    EXPECT_EQ(retired.restored, 1u);
    EXPECT_EQ(retired.pinned, 0u);
    const bool trampoline_kept = hook_residue_leaks() == residue_before + 1;
    EXPECT_TRUE(trampoline_kept) << "the restore freed a trampoline that a thread at the relay still runs";
    EXPECT_EQ(hook_manager_leaks(), manager_before);
    EXPECT_EQ(entry_bytes(&relay_target), pristine_bytes);

    // A freed trampoline must never run, so a failed proof leaves the thread to the destructor, which terminates it.
    if (trampoline_kept)
    {
        ASSERT_TRUE(thread.resume() && thread.join()) << "the redirected thread did not end";
        EXPECT_TRUE(s_relay_landed.load(std::memory_order_acquire)) << "the thread did not return to the landing";
        EXPECT_EQ(s_relay_result.load(std::memory_order_acquire), pristine);
        EXPECT_EQ(s_relay_detour_calls.load(std::memory_order_relaxed), detour_calls) << "the retired detour ran";
    }
    EXPECT_EQ(dmk_test::call_unfolded(&relay_target, RELAY_ARGUMENT), pristine);
}
#endif
