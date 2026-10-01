#include <gtest/gtest.h>
#include <windows.h>

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include "DetourModKit/diagnostics.hpp"
#include "DetourModKit/hook.hpp"
#include "DetourModKit/logger.hpp"

#include "fixtures/proof_section.hpp"
#include "fixtures/scratch_page.hpp"
#include "fixtures/hook_fixture.hpp"
#include "fixtures/log_capture.hpp"

using namespace DetourModKit;
using namespace DetourModKit::hook;
using namespace dmk_test::hook_fixture;

using VmtTransformFn = int (*)(void *self, int x);

// Hooked transform: original(this, x) + 500, used to prove two independent slots hook without cross-talk.
int vmt_detour_transform(void *self, int x)
{
    if (s_method_vmt == nullptr)
    {
        return -1;
    }
    const VmtTransformFn original = s_method_vmt->original<VmtTransformFn>(VMT_TRANSFORM_INDEX);
    if (original == nullptr)
    {
        return -1;
    }
    return original(self, x) + 500;
}

DMK_TEST_NOINLINE int dispatch_transform(VmtTestInterface *object, int x)
{
    return object->transform(x);
}

TEST(HookVmt, CreateSuccess)
{
    auto target = std::make_unique<VmtTestTarget>();
    Result<VmtHook> r = vmt_for("TestVmt", target.get());
    ASSERT_TRUE(r.has_value()) << r.error().message();
    VmtHook vh = std::move(*r);
    EXPECT_TRUE(static_cast<bool>(vh));
    EXPECT_EQ(vh.name(), "TestVmt");
}

TEST(HookVmt, CreateNullObject)
{
    Result<VmtHook> r = vmt_for("NullVmt", nullptr);
    ASSERT_FALSE(r.has_value());
    EXPECT_EQ(r.error().code, ErrorCode::InvalidObject);
}

// An executable-looking table can extend indefinitely. The slot cap must refuse that forged object with InvalidObject.
TEST(HookVmt, SlotWalkHardCapRejectsMalformedVtable)
{
    constexpr std::size_t OVER_CAP = 5000; // exceeds the internal MAX_VMT_SLOTS (4096)
    static std::vector<std::uintptr_t> fake_vtable(OVER_CAP, reinterpret_cast<std::uintptr_t>(&echo));
    struct FakeObject
    {
        std::uintptr_t vptr;
    } object{reinterpret_cast<std::uintptr_t>(fake_vtable.data())};

    Result<VmtHook> r = vmt_for("MalformedVtable", &object);
    ASSERT_FALSE(r.has_value());
    EXPECT_EQ(r.error().code, ErrorCode::InvalidObject);
}

// The vtable starts at the readable second page. Its backward RTTI prefix enters the first PAGE_NOACCESS page while the
// forward slot walk stays valid.
TEST(HookVmt, PreflightGuardsHeaderPrefixBelowVptr)
{
    SYSTEM_INFO si{};
    ::GetSystemInfo(&si);
    const SIZE_T page = si.dwPageSize;

    // The PAGE_NOACCESS allocation remains reserved for the process lifetime. Address reuse cannot change its fault
    // premise.
    auto *region =
        static_cast<std::uint8_t *>(::VirtualAlloc(nullptr, page * 2, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
    ASSERT_NE(region, nullptr);

    // Slot 0 is executable, and slot 1 terminates the walk. The backward prefix lies in the first page, which becomes
    // unreadable.
    auto *vtable = reinterpret_cast<std::uintptr_t *>(region + page);
    vtable[0] = reinterpret_cast<std::uintptr_t>(&echo); // executable slot
    vtable[1] = 0;                                       // non-executable terminator

    struct FakeObject
    {
        std::uintptr_t vptr;
    } object{reinterpret_cast<std::uintptr_t>(vtable)};

    DWORD old_protect = 0;
    ASSERT_NE(::VirtualProtect(region, page, PAGE_NOACCESS, &old_protect), 0);

    Result<VmtHook> r = vmt_for("HeaderPrefixOnUnmappedPage", &object);
    ASSERT_FALSE(r.has_value());
    EXPECT_EQ(r.error().code, ErrorCode::InvalidObject);
    // region is deliberately not freed (see the leak note above): the no-access page stays reserved for process life.
}

namespace DetourModKit::detail
{
#if defined(DMK_ENABLE_TEST_SEAMS)
    extern void (*g_vmt_teardown_warning_probe)() noexcept;
#endif
} // namespace DetourModKit::detail

namespace
{
    /// Counts non-overlapping occurrences of @p needle in @p haystack.
    [[nodiscard]] std::size_t count_occurrences(const std::string &haystack, std::string_view needle)
    {
        std::size_t hits = 0;
        for (std::size_t pos = haystack.find(needle, 0); pos != std::string::npos;
             pos = haystack.find(needle, pos + needle.size()))
            ++hits;
        return hits;
    }

#if defined(DMK_ENABLE_TEST_SEAMS)
    std::atomic<bool> s_vmt_warning_probe_entered{false};
    std::atomic<bool> s_vmt_warning_inner_done{false};
    std::atomic<bool> s_vmt_warning_inner_done_in_window{false};

    void wait_for_vmt_warning_inner_operation() noexcept
    {
        s_vmt_warning_probe_entered.store(true, std::memory_order_release);
        for (int i = 0; i < 500 && !s_vmt_warning_inner_done.load(std::memory_order_acquire); ++i)
        {
            Sleep(1);
        }
        s_vmt_warning_inner_done_in_window.store(
            s_vmt_warning_inner_done.load(std::memory_order_acquire),
            std::memory_order_release
        );
    }

    class VmtTeardownWarningProbeScope
    {
    public:
        VmtTeardownWarningProbeScope() noexcept
        {
            s_vmt_warning_probe_entered.store(false, std::memory_order_relaxed);
            s_vmt_warning_inner_done.store(false, std::memory_order_relaxed);
            s_vmt_warning_inner_done_in_window.store(false, std::memory_order_relaxed);
            DetourModKit::detail::g_vmt_teardown_warning_probe = &wait_for_vmt_warning_inner_operation;
        }

        ~VmtTeardownWarningProbeScope() noexcept { DetourModKit::detail::g_vmt_teardown_warning_probe = nullptr; }

        VmtTeardownWarningProbeScope(const VmtTeardownWarningProbeScope &) = delete;
        VmtTeardownWarningProbeScope &operator=(const VmtTeardownWarningProbeScope &) = delete;
    };
#endif
} // namespace

// A subscriber starts a concurrent VMT operation during Created delivery. Its bounded result detects an object gate
// that remains held during the event.
TEST(HookVmt, ObjectGateReleasedBeforeCreateLifecycleEmit)
{
    auto outer_target = std::make_unique<VmtTestTarget>();
    auto inner_target = std::make_unique<VmtTestTarget>();

    std::atomic<bool> reentered{false};
    std::atomic<bool> inner_done{false};
    std::atomic<bool> inner_ok{false};
    std::atomic<bool> inner_done_in_window{false};
    std::thread inner_thread;

    auto sub = diagnostics::hook_lifecycle().subscribe(
        [&](const diagnostics::HookLifecycleEvent &e)
        {
            if (e.kind != diagnostics::HookKind::Vmt || e.transition != diagnostics::HookTransition::Created)
            {
                return;
            }
            // The concurrent vmt_for also emits Created on inner_thread. The probe must re-enter only once.
            if (reentered.exchange(true))
            {
                return;
            }
            inner_thread = std::thread(
                [&]
                {
                    Result<VmtHook> inner = vmt_for("InnerConcurrent", inner_target.get());
                    inner_ok.store(inner.has_value(), std::memory_order_release);
                    inner_done.store(true, std::memory_order_release);
                    // `inner` (if present) destructs here, restoring inner_target's vptr under the free object gate.
                }
            );
            // This thread owns the outer gate until vmt_for returns. A concurrent operation cannot pass a gate that
            // remains held.
            for (int i = 0; i < 500 && !inner_done.load(std::memory_order_acquire); ++i)
            {
                Sleep(1);
            }
            inner_done_in_window.store(inner_done.load(std::memory_order_acquire), std::memory_order_release);
        }
    );

    Result<VmtHook> outer = vmt_for("OuterConcurrent", outer_target.get());
    ASSERT_TRUE(outer.has_value()) << outer.error().message();
    VmtHook outer_hold = std::move(*outer);

    if (inner_thread.joinable())
    {
        inner_thread.join();
    }
    EXPECT_TRUE(reentered.load(std::memory_order_acquire)) << "the Created lifecycle event was never observed";
    EXPECT_TRUE(inner_done_in_window.load(std::memory_order_acquire))
        << "vmt_for held the object gate across its Created emit; a concurrent VMT op could not proceed";
    EXPECT_TRUE(inner_ok.load(std::memory_order_acquire)) << "the concurrent re-entrant vmt_for failed";
}

// fail_if_already_hooked refuses a second clone of an object already on a clone owned by this kit.
TEST(HookVmt, FailIfAlreadyHookedRefusesDoubleCreate)
{
    auto target = std::make_unique<VmtTestTarget>();

    Result<VmtHook> first = vmt_for(
        "FirstVmt",
        target.get(),
        VmtOptions{
            .fail_if_already_hooked = true,
        }
    );
    ASSERT_TRUE(first.has_value()) << first.error().message();
    VmtHook vh = std::move(*first);

    Result<VmtHook> second = vmt_for(
        "SecondVmt",
        target.get(),
        VmtOptions{
            .fail_if_already_hooked = true,
        }
    );
    ASSERT_FALSE(second.has_value());
    EXPECT_EQ(second.error().code, ErrorCode::HookAlreadyExists);
}

// A permissive clone-of-clone succeeds and warns. The first clean clone stays quiet, so the warning identifies the
// second layer.
TEST(HookVmt, PermissiveCloneOfCloneWarnsButProceeds)
{
    dmk_test::LoggerFileCapture capture{DetourModKit::LogLevel::Warning};
    auto object = std::make_unique<VmtTestTarget>();

    {
        // A pristine object needs no clone warning.
        Result<VmtHook> first = vmt_for("CloneWarnFirst", object.get());
        ASSERT_TRUE(first.has_value()) << first.error().message();
        VmtHook a = std::move(*first);

        // Second clone (permissive) on the SAME object: its vptr is now a's clone base, so the detection fires. It
        // still succeeds: the permissive contract proceeds rather than refuses.
        Result<VmtHook> second = vmt_for("CloneWarnSecond", object.get());
        ASSERT_TRUE(second.has_value()) << second.error().message();
        VmtHook b = std::move(*second);

        const std::string content = capture.read_all();
        EXPECT_NE(content.find("CloneWarnSecond"), std::string::npos)
            << "the clone-of-clone must be detected and warned on the permissive path";
        EXPECT_NE(content.find("Another DMK VMT hook owns that clone"), std::string::npos);
        EXPECT_EQ(content.find("CloneWarnFirst"), std::string::npos) << "a clean first clone must not warn";

        // b (newest) then a (oldest) destruct here as the scope closes: newest-first, so each restores its vptr layer
        // cleanly with no leak-on-inversion.
    }
}

TEST(HookVmt, DestructorRestoresVptr)
{
    auto target = std::make_unique<VmtTestTarget>();
    const auto original_vptr = *reinterpret_cast<std::uintptr_t *>(target.get());
    EXPECT_EQ(target->compute(1, 2), 3);

    {
        Result<VmtHook> r = vmt_for("RestoreVmt", target.get());
        ASSERT_TRUE(r.has_value()) << r.error().message();
        VmtHook vh = std::move(*r);
        EXPECT_NE(*reinterpret_cast<std::uintptr_t *>(target.get()), original_vptr); // on the clone now
    }

    EXPECT_EQ(*reinterpret_cast<std::uintptr_t *>(target.get()), original_vptr);
    EXPECT_EQ(target->compute(1, 2), 3);
}

// Destruction must restore the objects newest-first.
TEST(HookVmt, ApplyToAndRemoveFromMultipleObjects)
{
    auto target1 = std::make_unique<VmtTestTarget>();
    auto target2 = std::make_unique<VmtTestTarget>();
    const auto vptr2_original = *reinterpret_cast<std::uintptr_t *>(target2.get());

    Result<VmtHook> r = vmt_for("MultiVmt", target1.get());
    ASSERT_TRUE(r.has_value()) << r.error().message();
    VmtHook vh = std::move(*r);

    ASSERT_TRUE(vh.apply_to(target2.get()).has_value());
    EXPECT_NE(*reinterpret_cast<std::uintptr_t *>(target2.get()), vptr2_original); // target2 on the clone

    ASSERT_TRUE(vh.remove_from(target2.get()).has_value());
    EXPECT_EQ(*reinterpret_cast<std::uintptr_t *>(target2.get()), vptr2_original); // restored
}

// apply_to accepts its own clone as a no-op and refuses another live clone.
TEST(HookVmt, ApplyToOwnCloneIsNoOpAnotherCloneFails)
{
    auto target_a = std::make_unique<VmtTestTarget>();
    auto target_b = std::make_unique<VmtTestTarget>();

    Result<VmtHook> ra = vmt_for("CloneOwnerA", target_a.get());
    ASSERT_TRUE(ra.has_value()) << ra.error().message();
    VmtHook va = std::move(*ra);

    Result<VmtHook> rb = vmt_for("CloneOwnerB", target_b.get());
    ASSERT_TRUE(rb.has_value()) << rb.error().message();
    VmtHook vb = std::move(*rb);

    // target_b is already on vb's clone. Applying va onto target_b with fail_if_already_hooked must be refused.
    Result<void> cross = va.apply_to(
        target_b.get(),
        VmtOptions{
            .fail_if_already_hooked = true,
        }
    );
    ASSERT_FALSE(cross.has_value());
    EXPECT_EQ(cross.error().code, ErrorCode::HookAlreadyExists);
}

// A foreign clone needs the permissive warning. A tracked reapply of the handle's own clone returns before that warning
// path.
TEST(HookVmt, PermissiveApplyOntoForeignCloneWarnsOwnCloneStaysQuiet)
{
    dmk_test::LoggerFileCapture capture{DetourModKit::LogLevel::Warning};
    auto owner_object = std::make_unique<VmtTestTarget>();
    auto mover_object = std::make_unique<VmtTestTarget>();

    {
        // Each pristine object receives its first clone, so neither create emits a warning.
        Result<VmtHook> ro = vmt_for("ApplyOwner", owner_object.get());
        ASSERT_TRUE(ro.has_value()) << ro.error().message();
        VmtHook owner = std::move(*ro);

        Result<VmtHook> rm = vmt_for("ApplyMover", mover_object.get());
        ASSERT_TRUE(rm.has_value()) << rm.error().message();
        VmtHook mover = std::move(*rm);

        // Foreign clone: owner_object's vptr is owner's clone base, not mover's. mover.apply_to sees a clone owned by
        // another handle, warns, and proceeds. Undo the cross-apply immediately so each object is restored by a single
        // owning handle at teardown (remove_from restores owner_object to owner's clone base).
        ASSERT_TRUE(mover.apply_to(owner_object.get()).has_value());
        ASSERT_TRUE(mover.remove_from(owner_object.get()).has_value());

        // Own clone: mover_object is already tracked on mover's clone, so the early success no-op suppresses the
        // warning.
        ASSERT_TRUE(mover.apply_to(mover_object.get()).has_value());

        const std::string content = capture.read_all();
        EXPECT_EQ(count_occurrences(content, "Another DMK VMT hook owns that clone"), 1u)
            << "exactly the foreign-clone apply warns; the own-clone re-apply must stay quiet";
        EXPECT_NE(content.find("ApplyMover"), std::string::npos) << "the foreign-clone warning names the applying hook";

        // mover (newest) then owner destruct here: mover restores mover_object, owner restores owner_object, each a
        // single-owner restore with no cross-ownership left over.
    }
}

TEST(HookVmt, ApplyNullObject)
{
    auto target = std::make_unique<VmtTestTarget>();
    Result<VmtHook> r = vmt_for("ApplyNullVmt", target.get());
    ASSERT_TRUE(r.has_value()) << r.error().message();
    VmtHook vh = std::move(*r);

    Result<void> applied = vh.apply_to(nullptr);
    ASSERT_FALSE(applied.has_value());
    EXPECT_EQ(applied.error().code, ErrorCode::InvalidObject);
}

TEST(HookVmt, RemoveFromNullObject)
{
    auto target = std::make_unique<VmtTestTarget>();
    Result<VmtHook> r = vmt_for("RemNullVmt", target.get());
    ASSERT_TRUE(r.has_value()) << r.error().message();
    VmtHook vh = std::move(*r);

    Result<void> removed = vh.remove_from(nullptr);
    EXPECT_FALSE(removed.has_value());
}

TEST(HookVmt, MovedFromVmtHandleIsInert)
{
    auto target = std::make_unique<VmtTestTarget>();
    const auto original_vptr = *reinterpret_cast<std::uintptr_t *>(target.get());
    {
        Result<VmtHook> r = vmt_for("MovedVmt", target.get());
        ASSERT_TRUE(r.has_value()) << r.error().message();
        VmtHook a = std::move(*r);
        VmtHook b = std::move(a);
        EXPECT_FALSE(static_cast<bool>(a)); // Only b owns teardown.
        EXPECT_TRUE(static_cast<bool>(b));
    }
    EXPECT_EQ(*reinterpret_cast<std::uintptr_t *>(target.get()), original_vptr);
}

// Only executable slots reach the byte classifier. Static data can cause an earlier zero-slot refusal and make the
// negative cases vacuous.

// The jump stub must sit in a code section of this image, not on the slot_bodies() page. For an EB or E9 slot, the
// classifier resolves the module of the slot address FIRST and refuses a slot with no module. It thus refuses a stub on
// privately allocated memory before the same-module comparison that this stub pins. In .text, the stub and its rel32
// destination both map to this module. That is the shape of an incremental-link thunk or a patched slot.
//
// The bytes encode E9 jmp +3, which lands on the ret three bytes past the end of the jmp. The trailing int3s stop a
// decode that continues past the ret.
#if defined(_MSC_VER)
#pragma section(".text$dmk", read, execute)
__declspec(allocate(".text$dmk")) extern const std::uint8_t SAME_MODULE_JMP_STUB[16] =
    {0xE9, 0x03, 0x00, 0x00, 0x00, 0x90, 0x90, 0x90, 0xC3, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC};
#else
__attribute__((section(".text$dmk"), used)) extern const std::uint8_t SAME_MODULE_JMP_STUB[16] =
    {0xE9, 0x03, 0x00, 0x00, 0x00, 0x90, 0x90, 0x90, 0xC3, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC};
#endif

TEST(HookVmt, PreFlightRefusesInt3FirstSlot)
{
    // The RTTI prefix needs one word on MSVC and two on MinGW. The fixture reserves the larger prefix and a
    // non-executable terminator.
    struct Int3VTable
    {
        void *rtti[2];
        void *methods[3];
    };
    Int3VTable vtable{};
    vtable.methods[0] = slot_bodies().at(SlotBodyPage::INT3);
    vtable.methods[1] = slot_bodies().at(SlotBodyPage::RET);
    vtable.methods[2] = nullptr; // terminates the slot walk in bounds
    void *vptr = &vtable.methods[0];

    // The default policy admits this counted slot. The handle restores the local table before the strict classifier
    // attempt.
    {
        Result<VmtHook> permissive = vmt_for("Int3VmtPermissive", &vptr);
        ASSERT_TRUE(permissive.has_value()) << permissive.error().message();
        VmtHook dropped = std::move(*permissive);
    }
    ASSERT_EQ(vptr, static_cast<void *>(&vtable.methods[0]));

    Result<VmtHook> r = vmt_for(
        "Int3Vmt",
        &vptr,
        VmtOptions{
            .fail_on_non_function_pointer = true,
        }
    );
    ASSERT_FALSE(r.has_value());
    EXPECT_EQ(r.error().code, ErrorCode::InvalidObject);

    // The refused create did not touch the vptr: it still points at our local vtable.
    EXPECT_EQ(vptr, static_cast<void *>(&vtable.methods[0]));
}

TEST(HookVmt, PreFlightAcceptsFunctionPrologue)
{
    // The first byte 0x48 is a normal prologue. The fixture prefix fits the larger RTTI header, so capture remains
    // inside the object.
    struct PrologueVTable
    {
        void *rtti[2];
        void *methods[2];
    };
    PrologueVTable vtable{};
    vtable.methods[0] = slot_bodies().at(SlotBodyPage::PROLOGUE);
    void *vptr = &vtable.methods[0];

    Result<VmtHook> r = vmt_for(
        "PrologueVmt",
        &vptr,
        VmtOptions{
            .fail_on_non_function_pointer = true,
        }
    );
    ASSERT_TRUE(r.has_value()) << r.error().message();
    {
        VmtHook vh = std::move(*r);
        EXPECT_EQ(vh.name(), "PrologueVmt");
    }
    EXPECT_EQ(vptr, static_cast<void *>(&vtable.methods[0]));
}

TEST(HookVmt, PreFlightOffByDefault)
{
    // The bare ret counts as executable but fails the byte classifier. One structurally valid object isolates the
    // opt-in policy.
    struct RetVTable
    {
        void *rtti[2];
        void *methods[2];
    };
    RetVTable vtable{};
    vtable.methods[0] = slot_bodies().at(SlotBodyPage::RET);
    void *vptr = &vtable.methods[0];

    {
        Result<VmtHook> r = vmt_for("RetSlotVmt", &vptr);
        ASSERT_TRUE(r.has_value()) << r.error().message();
        VmtHook dropped = std::move(*r);
    }
    ASSERT_EQ(vptr, static_cast<void *>(&vtable.methods[0]));

    Result<VmtHook> strict = vmt_for(
        "RetSlotVmtStrict",
        &vptr,
        VmtOptions{
            .fail_on_non_function_pointer = true,
        }
    );
    ASSERT_FALSE(strict.has_value());
    EXPECT_EQ(strict.error().code, ErrorCode::InvalidObject);
}

TEST(HookVmt, PreFlightRefusesSameModuleJumpStub)
{
    // As in the int3 case: the leading rtti words and the terminator keep the backend's clone copy in bounds.
    struct StubVTable
    {
        void *rtti[2];
        void *methods[3];
    };
    StubVTable vtable{};
    vtable.methods[0] = const_cast<std::uint8_t *>(&SAME_MODULE_JMP_STUB[0]);
    vtable.methods[1] = slot_bodies().at(SlotBodyPage::RET);
    vtable.methods[2] = nullptr;
    void *vptr = &vtable.methods[0];

    // As above: prove the default admits it, so the strict refusal is the classifier's verdict and not a slot walk
    // that counted nothing.
    {
        Result<VmtHook> permissive = vmt_for("JmpStubVmtPermissive", &vptr);
        ASSERT_TRUE(permissive.has_value()) << permissive.error().message();
        VmtHook dropped = std::move(*permissive);
    }
    ASSERT_EQ(vptr, static_cast<void *>(&vtable.methods[0]));

    Result<VmtHook> r = vmt_for(
        "JmpStubVmt",
        &vptr,
        VmtOptions{
            .fail_on_non_function_pointer = true,
        }
    );
    ASSERT_FALSE(r.has_value());
    EXPECT_EQ(r.error().code, ErrorCode::InvalidObject);
    EXPECT_EQ(vptr, static_cast<void *>(&vtable.methods[0]));
}

TEST(HookVmt, ApplyPreFlightRefusesInt3FirstSlot)
{
    // The apply path runs the same slot-0 pre-flight as create: applying onto an object whose current vtable starts
    // with an int3 slot must be refused.
    auto seed = std::make_unique<VmtTestTarget>();
    Result<VmtHook> r = vmt_for("ApplyPreFlightVmt", seed.get());
    ASSERT_TRUE(r.has_value()) << r.error().message();
    VmtHook vh = std::move(*r);

    struct Int3VTable
    {
        void *methods[2];
    };
    Int3VTable vtable{};
    vtable.methods[0] = slot_bodies().at(SlotBodyPage::INT3);
    vtable.methods[1] = slot_bodies().at(SlotBodyPage::RET);
    void *vptr = &vtable;

    Result<void> applied = vh.apply_to(
        &vptr,
        VmtOptions{
            .fail_on_non_function_pointer = true,
        }
    );
    ASSERT_FALSE(applied.has_value());
    EXPECT_EQ(applied.error().code, ErrorCode::InvalidObject);
    EXPECT_EQ(vptr, static_cast<void *>(&vtable));
}

// apply_to installs an existing clone, so its default path needs a readable, writable object word but does not clone or
// inspect the displaced vtable. The opt-in slot policy owns that additional classification.
TEST(HookVmt, ApplyDefaultNeedsOnlyWritableObjectWord)
{
    auto seed = std::make_unique<VmtTestTarget>();
    Result<VmtHook> r = vmt_for("ApplyWritableWordSeed", seed.get());
    ASSERT_TRUE(r.has_value()) << r.error().message();
    VmtHook vh = std::move(*r);

    struct FakeObject
    {
        std::uintptr_t vptr{0};
    } object;

    ASSERT_TRUE(vh.apply_to(&object).has_value());
    EXPECT_NE(object.vptr, 0u);
    ASSERT_TRUE(vh.remove_from(&object).has_value());
    EXPECT_EQ(object.vptr, 0u);
}

TEST(HookVmt, ReleaseLeavesCloneInstalled)
{
    auto target = std::make_unique<VmtTestTarget>();
    const auto original_vptr = *reinterpret_cast<std::uintptr_t *>(target.get());

    Result<VmtHook> r = vmt_for("ReleasedVmt", target.get());
    ASSERT_TRUE(r.has_value()) << r.error().message();
    VmtHook vh = std::move(*r);
    vh.release();

    EXPECT_FALSE(static_cast<bool>(vh));
    // No vptr restore: the clone is leaked for the process lifetime, so the vptr still points at the clone.
    EXPECT_NE(*reinterpret_cast<std::uintptr_t *>(target.get()), original_vptr);
    // Manually restore so the stack object does not dispatch through a leaked clone after this scope.
    *reinterpret_cast<std::uintptr_t *>(target.get()) = original_vptr;
}

// VMT per-method hooking (hook_method / original<Fn>(index) / remove_method)

// The detoured compute returns original + 1000. Its typed original snapshot must still return the unmodified sum.
TEST(HookVmtMethod, HookMethodRedirectsSlotAndOriginalReachesPreHook)
{
    auto target = std::make_unique<VmtTestTarget>();
    EXPECT_EQ(dispatch_compute(target.get(), 3, 4), 7);

    Result<VmtHook> r = vmt_for("MethodVmt", target.get());
    ASSERT_TRUE(r.has_value()) << r.error().message();
    VmtHook vh = std::move(*r);
    MethodVmtScope method_scope(vh);

    ASSERT_TRUE(vh.hook_method(VMT_COMPUTE_INDEX, &vmt_detour_compute).has_value());

    // Dispatch through the object now routes to the detour: original(3, 4) + 1000.
    EXPECT_EQ(dispatch_compute(target.get(), 3, 4), 1007);

    // The typed snapshot reaches the original body directly, so it yields the unmodified 7.
    auto *orig = vh.original<VmtComputeFn>(VMT_COMPUTE_INDEX);
    ASSERT_NE(orig, nullptr);
    EXPECT_EQ(orig(target.get(), 3, 4), 7);
}

// Two independent slots hook without cross-talk, and each original<Fn>(index) resolves to its own method.
TEST(HookVmtMethod, MultipleSlotsHookIndependently)
{
    auto target = std::make_unique<VmtTestTarget>();
    EXPECT_EQ(dispatch_compute(target.get(), 2, 3), 5);
    EXPECT_EQ(dispatch_transform(target.get(), 6), 12);

    Result<VmtHook> r = vmt_for("MultiSlotVmt", target.get());
    ASSERT_TRUE(r.has_value()) << r.error().message();
    VmtHook vh = std::move(*r);
    MethodVmtScope method_scope(vh);

    ASSERT_TRUE(vh.hook_method(VMT_COMPUTE_INDEX, &vmt_detour_compute).has_value());
    ASSERT_TRUE(vh.hook_method(VMT_TRANSFORM_INDEX, &vmt_detour_transform).has_value());

    EXPECT_EQ(dispatch_compute(target.get(), 2, 3), 1005);
    EXPECT_EQ(dispatch_transform(target.get(), 6), 512);
}

// A second slot install records the first detour as its original.
TEST(HookVmtMethod, DuplicateMethodHookFails)
{
    auto target = std::make_unique<VmtTestTarget>();

    Result<VmtHook> r = vmt_for("DupMethodVmt", target.get());
    ASSERT_TRUE(r.has_value()) << r.error().message();
    VmtHook vh = std::move(*r);

    ASSERT_TRUE(vh.hook_method(VMT_COMPUTE_INDEX, &vmt_detour_compute).has_value());

    Result<void> second = vh.hook_method(VMT_COMPUTE_INDEX, &vmt_detour_compute);
    ASSERT_FALSE(second.has_value());
    EXPECT_EQ(second.error().code, ErrorCode::MethodAlreadyHooked);
}

// A null detour is rejected before it can be stored into a vtable slot.
TEST(HookVmtMethod, NullDetourRejected)
{
    auto target = std::make_unique<VmtTestTarget>();

    Result<VmtHook> r = vmt_for("NullDetourVmt", target.get());
    ASSERT_TRUE(r.has_value()) << r.error().message();
    VmtHook vh = std::move(*r);

    VmtComputeFn null_detour = nullptr;
    Result<void> hooked = vh.hook_method(VMT_COMPUTE_INDEX, null_detour);
    ASSERT_FALSE(hooked.has_value());
    EXPECT_EQ(hooked.error().code, ErrorCode::InvalidArg);
}

// An out-of-range index is rejected before the backend can index through the cloned vtable.
TEST(HookVmtMethod, OutOfRangeIndexRejected)
{
    auto target = std::make_unique<VmtTestTarget>();

    Result<VmtHook> r = vmt_for("OutOfRangeMethodVmt", target.get());
    ASSERT_TRUE(r.has_value()) << r.error().message();
    VmtHook vh = std::move(*r);

    constexpr std::size_t INVALID_INDEX = VMT_TRANSFORM_INDEX + 1;
    Result<void> hooked = vh.hook_method(INVALID_INDEX, &vmt_detour_compute);
    ASSERT_FALSE(hooked.has_value());
    EXPECT_EQ(hooked.error().code, ErrorCode::InvalidArg);
    EXPECT_EQ(dispatch_compute(target.get(), 4, 5), 9);
    EXPECT_EQ(vh.original<VmtComputeFn>(INVALID_INDEX), nullptr);
}

// A repeated method removal must report MethodNotFound.
TEST(HookVmtMethod, RemoveMethodRestoresSlot)
{
    auto target = std::make_unique<VmtTestTarget>();

    Result<VmtHook> r = vmt_for("RemMethodVmt", target.get());
    ASSERT_TRUE(r.has_value()) << r.error().message();
    VmtHook vh = std::move(*r);
    MethodVmtScope method_scope(vh);

    ASSERT_TRUE(vh.hook_method(VMT_COMPUTE_INDEX, &vmt_detour_compute).has_value());
    EXPECT_EQ(dispatch_compute(target.get(), 5, 5), 1010);

    ASSERT_TRUE(vh.remove_method(VMT_COMPUTE_INDEX).has_value());
    EXPECT_EQ(dispatch_compute(target.get(), 5, 5), 10);
    EXPECT_EQ(vh.original<VmtComputeFn>(VMT_COMPUTE_INDEX), nullptr);

    Result<void> re_remove = vh.remove_method(VMT_COMPUTE_INDEX);
    ASSERT_FALSE(re_remove.has_value());
    EXPECT_EQ(re_remove.error().code, ErrorCode::MethodNotFound);
}

TEST(HookVmtMethod, DroppingHandleRestoresMethod)
{
    auto target = std::make_unique<VmtTestTarget>();
    EXPECT_EQ(dispatch_compute(target.get(), 1, 2), 3);

    {
        Result<VmtHook> r = vmt_for("DropMethodVmt", target.get());
        ASSERT_TRUE(r.has_value()) << r.error().message();
        VmtHook vh = std::move(*r);
        MethodVmtScope method_scope(vh);

        ASSERT_TRUE(vh.hook_method(VMT_COMPUTE_INDEX, &vmt_detour_compute).has_value());
        EXPECT_EQ(dispatch_compute(target.get(), 1, 2), 1003);
    }

    // The handle's destructor restored the original vptr, so the method hook is gone with it.
    EXPECT_EQ(dispatch_compute(target.get(), 1, 2), 3);
}

// A later apply_to inherits the method hook. remove_from must restore that object without changes to the seed.
TEST(HookVmtMethod, MethodHookAppliesToAdditionalObjects)
{
    auto target1 = std::make_unique<VmtTestTarget>();
    auto target2 = std::make_unique<VmtTestTarget>();

    Result<VmtHook> r = vmt_for("MultiObjMethodVmt", target1.get());
    ASSERT_TRUE(r.has_value()) << r.error().message();
    VmtHook vh = std::move(*r);
    MethodVmtScope method_scope(vh);

    ASSERT_TRUE(vh.hook_method(VMT_COMPUTE_INDEX, &vmt_detour_compute).has_value());
    EXPECT_EQ(dispatch_compute(target1.get(), 1, 1), 1002);
    EXPECT_EQ(dispatch_compute(target2.get(), 1, 1), 2);

    ASSERT_TRUE(vh.apply_to(target2.get()).has_value());
    EXPECT_EQ(dispatch_compute(target2.get(), 1, 1), 1002);

    ASSERT_TRUE(vh.remove_from(target2.get()).has_value());
    EXPECT_EQ(dispatch_compute(target2.get(), 1, 1), 2);
    EXPECT_EQ(dispatch_compute(target1.get(), 1, 1), 1002);
}

// original<Fn>(index) is a null snapshot for a slot that was never hooked.
TEST(HookVmtMethod, OriginalForUnhookedSlotIsNull)
{
    auto target = std::make_unique<VmtTestTarget>();

    Result<VmtHook> r = vmt_for("UnhookedSlotVmt", target.get());
    ASSERT_TRUE(r.has_value()) << r.error().message();
    VmtHook vh = std::move(*r);

    EXPECT_EQ(vh.original<VmtComputeFn>(VMT_COMPUTE_INDEX), nullptr);
}

// The moved-from handle returns InvalidHookState from mutations and a null original snapshot.
TEST(HookVmtMethod, DisengagedHandleFailsClosed)
{
    auto target = std::make_unique<VmtTestTarget>();

    Result<VmtHook> r = vmt_for("DisengagedMethodVmt", target.get());
    ASSERT_TRUE(r.has_value()) << r.error().message();
    VmtHook a = std::move(*r);
    VmtHook b = std::move(a);
    EXPECT_TRUE(static_cast<bool>(b));

    Result<void> hooked = a.hook_method(VMT_COMPUTE_INDEX, &vmt_detour_compute);
    ASSERT_FALSE(hooked.has_value());
    EXPECT_EQ(hooked.error().code, ErrorCode::InvalidHookState);

    Result<void> removed = a.remove_method(VMT_COMPUTE_INDEX);
    ASSERT_FALSE(removed.has_value());
    EXPECT_EQ(removed.error().code, ErrorCode::InvalidHookState);

    EXPECT_EQ(a.original<VmtComputeFn>(VMT_COMPUTE_INDEX), nullptr);
}

// VMT zero-slot refusal, layered clones, and clone teardown

// An engaged zero count differs from an unreadable table. A zero-slot clone contains only its RTTI prefix and exposes
// no callable address point.
TEST(HookVmt, PreFlightRefusesVtableWithNoCallableSlots)
{
    // Mapped and readable but not executable, so the walk reads slot 0 fine and terminates on it, yielding zero.
    static std::uintptr_t data_sink = 0;
    // The fake vptr points into the MIDDLE of the table so the RTTI header prefix below it (vptr - VMT_HEADER) is
    // mapped and readable. That keeps the engaged-zero check the only thing that can refuse this object.
    static std::uintptr_t data_vtable[8];
    for (std::uintptr_t &slot : data_vtable)
    {
        slot = reinterpret_cast<std::uintptr_t>(&data_sink);
    }

    struct FakeObject
    {
        std::uintptr_t vptr;
    } object{reinterpret_cast<std::uintptr_t>(&data_vtable[4])};
    const std::uintptr_t vptr_before = object.vptr;

    const Result<VmtHook> created = vmt_for("ZeroSlotVmt", &object);
    ASSERT_FALSE(created.has_value());
    EXPECT_EQ(created.error().code, ErrorCode::InvalidObject);
    // The unchanged vptr proves that no one-past-the-end address point reached the object.
    EXPECT_EQ(object.vptr, vptr_before) << "a refused create must leave the object's vptr untouched";
}

// Newest-first teardown restores B to A, then A to the pristine table. No layer is outranked in this order.
TEST(HookVmtLayered, NewestFirstTeardownRestoresPristineTable)
{
    auto object = std::make_unique<VmtTestTarget>();
    const std::uintptr_t pristine_vptr = *reinterpret_cast<std::uintptr_t *>(object.get());
    // Measure a delta rather than resetting the process-wide counters, so this test does not perturb any other
    // leak-count assertion in the suite.
    const std::size_t before = diagnostics::intentional_leak_count(diagnostics::LeakSubsystem::HookManager);

    {
        // Capture the expected clone-of-clone warning.
        dmk_test::LoggerFileCapture capture{DetourModKit::LogLevel::Warning};

        Result<VmtHook> ra = vmt_for("LayerVmtOrderA", object.get());
        ASSERT_TRUE(ra.has_value()) << ra.error().message();
        std::optional<VmtHook> a(std::move(*ra));

        Result<VmtHook> rb = vmt_for("LayerVmtOrderB", object.get());
        ASSERT_TRUE(rb.has_value()) << rb.error().message();
        std::optional<VmtHook> b(std::move(*rb));

        b.reset();
        a.reset();
    }

    EXPECT_EQ(*reinterpret_cast<std::uintptr_t *>(object.get()), pristine_vptr)
        << "newest-first VMT teardown must land the object back on its pristine table";
    EXPECT_EQ(diagnostics::intentional_leak_count(diagnostics::LeakSubsystem::HookManager), before)
        << "no layer is outranked in newest-first order, so nothing may be leaked";
    EXPECT_EQ(dispatch_compute(object.get(), 2, 3), 5);
}

// Oldest-first teardown retains A's clone because B records it as its original. The final object names that retained
// clone rather than freed storage.
TEST(HookVmtLayered, OldestFirstTeardownLeaksOutrankedClone)
{
    auto object = std::make_unique<VmtTestTarget>();
    auto peer = std::make_unique<VmtTestTarget>();
    const std::uintptr_t pristine_vptr = *reinterpret_cast<std::uintptr_t *>(object.get());
    const std::uintptr_t peer_pristine_vptr = *reinterpret_cast<std::uintptr_t *>(peer.get());
    const std::size_t before = diagnostics::intentional_leak_count(diagnostics::LeakSubsystem::HookManager);
    std::uintptr_t a_clone_base = 0;

    {
        dmk_test::LoggerFileCapture capture{DetourModKit::LogLevel::Warning};

        Result<VmtHook> ra = vmt_for("LayerVmtLeakA", object.get());
        ASSERT_TRUE(ra.has_value()) << ra.error().message();
        std::optional<VmtHook> a(std::move(*ra));
        a_clone_base = *reinterpret_cast<std::uintptr_t *>(object.get());
        ASSERT_TRUE(a->apply_to(peer.get()).has_value());
        ASSERT_NE(*reinterpret_cast<std::uintptr_t *>(peer.get()), peer_pristine_vptr);

        Result<VmtHook> rb = vmt_for("LayerVmtLeakB", object.get());
        ASSERT_TRUE(rb.has_value()) << rb.error().message();
        std::optional<VmtHook> b(std::move(*rb));

        // Inverted order: destroy the OLDER clone while B still records A's clone base as the original it will write
        // back into the live object.
        a.reset();
        EXPECT_EQ(diagnostics::intentional_leak_count(diagnostics::LeakSubsystem::HookManager), before + 1)
            << "an outranked VMT clone must be leaked, not freed under its successor's recorded original";
        EXPECT_EQ(*reinterpret_cast<std::uintptr_t *>(peer.get()), peer_pristine_vptr)
            << "an outranked object must not prevent independent objects from being restored";
        EXPECT_NE(capture.read_all().find("leaked this clone to avoid a vtable use-after-free"), std::string::npos)
            << "the leak-on-inversion branch must warn so the condition is diagnosable";

        // B unwinds onto A's leaked clone base. Leaked, so still mapped: the store is not a dangling pointer.
        b.reset();
        EXPECT_EQ(*reinterpret_cast<std::uintptr_t *>(object.get()), a_clone_base);
    }

    EXPECT_NE(*reinterpret_cast<std::uintptr_t *>(object.get()), pristine_vptr)
        << "the documented trade: an inverted teardown leaves the object on the leaked clone, not the original table";
    EXPECT_EQ(diagnostics::intentional_leak_count(diagnostics::LeakSubsystem::HookManager), before + 1);
    // The leaked clone is a faithful copy of the original table, so dispatch still works rather than jumping through
    // freed memory.
    EXPECT_EQ(dispatch_compute(object.get(), 2, 3), 5);
}

TEST(HookVmt, TeardownReleasesAlreadyOriginalReadOnlyBinding)
{
    auto donor = std::make_unique<VmtTestTarget>();
    const std::uintptr_t original_vptr = *reinterpret_cast<std::uintptr_t *>(donor.get());
    dmk_test::ScratchPage object_page;
    ASSERT_TRUE(object_page.ok());
    auto *const object_word = static_cast<std::uintptr_t *>(object_page.base());
    *object_word = original_vptr;
    const std::size_t before = diagnostics::intentional_leak_count(diagnostics::LeakSubsystem::HookManager);

    Result<VmtHook> created = vmt_for("AlreadyOriginalReadOnly", object_word);
    ASSERT_TRUE(created.has_value()) << created.error().message();
    std::optional<VmtHook> hook(std::move(*created));
    ASSERT_NE(*object_word, original_vptr);

    *object_word = original_vptr;
    DWORD previous_protection = 0;
    ASSERT_NE(::VirtualProtect(object_word, sizeof(*object_word), PAGE_READONLY, &previous_protection), 0);
    EXPECT_EQ(previous_protection, PAGE_EXECUTE_READWRITE);

    hook.reset();
    EXPECT_EQ(*object_word, original_vptr);
    EXPECT_EQ(diagnostics::intentional_leak_count(diagnostics::LeakSubsystem::HookManager), before)
        << "an already-original binding needs no write and must not force a clone leak";
}

#if defined(DMK_ENABLE_TEST_SEAMS)
// The warning probe pauses teardown at the logging boundary while another thread enters vmt_for. A bounded wait fails
// without hanging if teardown still owns the object gate there.
TEST(HookVmtLayered, TeardownWarningRunsAfterObjectGateRelease)
{
    auto object = std::make_unique<VmtTestTarget>();
    auto inner_object = std::make_unique<VmtTestTarget>();
    dmk_test::LoggerFileCapture capture{DetourModKit::LogLevel::Warning};

    Result<VmtHook> older_result = vmt_for("WarningGateOlder", object.get());
    ASSERT_TRUE(older_result.has_value()) << older_result.error().message();
    std::optional<VmtHook> older(std::move(*older_result));

    Result<VmtHook> newer_result = vmt_for("WarningGateNewer", object.get());
    ASSERT_TRUE(newer_result.has_value()) << newer_result.error().message();
    std::optional<VmtHook> newer(std::move(*newer_result));

    const VmtTeardownWarningProbeScope probe_scope;
    std::atomic<bool> inner_ok{false};
    std::thread inner_thread(
        [&]
        {
            for (int i = 0; i < 500 && !s_vmt_warning_probe_entered.load(std::memory_order_acquire); ++i)
            {
                Sleep(1);
            }
            if (!s_vmt_warning_probe_entered.load(std::memory_order_acquire))
            {
                return;
            }
            Result<VmtHook> inner = vmt_for("WarningGateInner", inner_object.get());
            inner_ok.store(inner.has_value(), std::memory_order_release);
            s_vmt_warning_inner_done.store(true, std::memory_order_release);
        }
    );

    older.reset();
    inner_thread.join();

    EXPECT_TRUE(s_vmt_warning_probe_entered.load(std::memory_order_acquire));
    EXPECT_TRUE(s_vmt_warning_inner_done_in_window.load(std::memory_order_acquire))
        << "the teardown warning path held the process-wide VMT object gate while logging";
    EXPECT_TRUE(inner_ok.load(std::memory_order_acquire));
    newer.reset();
}
#endif

TEST(HookVmtLayered, OutrankedRemoveRetainsOriginalForLaterRestore)
{
    auto object = std::make_unique<VmtTestTarget>();
    const std::uintptr_t pristine_vptr = *reinterpret_cast<std::uintptr_t *>(object.get());
    const std::size_t before = diagnostics::intentional_leak_count(diagnostics::LeakSubsystem::HookManager);

    dmk_test::LoggerFileCapture capture{DetourModKit::LogLevel::Warning};
    Result<VmtHook> ra = vmt_for("RemoveRestoreA", object.get());
    ASSERT_TRUE(ra.has_value()) << ra.error().message();
    std::optional<VmtHook> a(std::move(*ra));
    const std::uintptr_t a_clone_base = *reinterpret_cast<std::uintptr_t *>(object.get());

    Result<VmtHook> rb = vmt_for("RemoveRestoreB", object.get());
    ASSERT_TRUE(rb.has_value()) << rb.error().message();
    std::optional<VmtHook> b(std::move(*rb));

    // A cannot restore while B outranks it, so remove_from must retain A's DMK binding.
    ASSERT_TRUE(a->remove_from(object.get()).has_value());

    b.reset();
    ASSERT_EQ(*reinterpret_cast<std::uintptr_t *>(object.get()), a_clone_base);

    // A's retained binding restores the pristine table after B unwinds to A's clone.
    a.reset();
    EXPECT_EQ(*reinterpret_cast<std::uintptr_t *>(object.get()), pristine_vptr);
    EXPECT_EQ(diagnostics::intentional_leak_count(diagnostics::LeakSubsystem::HookManager), before);
    EXPECT_EQ(dispatch_compute(object.get(), 2, 3), 5);
}

// The binding is the restoration record that B later uses. A cannot free its clone while that record still reaches it.
TEST(HookVmtLayered, RemoveFromOutrankedObjectKeepsCloneReachable)
{
    auto object = std::make_unique<VmtTestTarget>();
    const std::size_t before = diagnostics::intentional_leak_count(diagnostics::LeakSubsystem::HookManager);
    std::uintptr_t a_clone_base = 0;

    {
        dmk_test::LoggerFileCapture capture{DetourModKit::LogLevel::Warning};

        Result<VmtHook> ra = vmt_for("RemoveOutrankedA", object.get());
        ASSERT_TRUE(ra.has_value()) << ra.error().message();
        std::optional<VmtHook> a(std::move(*ra));
        a_clone_base = *reinterpret_cast<std::uintptr_t *>(object.get());

        std::optional<VmtHook> b;
        {
            MethodVmtScope scope(*a);
            ASSERT_TRUE(a->hook_method<VmtTransformFn>(VMT_TRANSFORM_INDEX, &vmt_detour_transform).has_value());
            EXPECT_EQ(dispatch_transform(object.get(), 7), 514);

            Result<VmtHook> rb = vmt_for("RemoveOutrankedB", object.get());
            ASSERT_TRUE(rb.has_value()) << rb.error().message();
            b.emplace(std::move(*rb));

            // B cloned A's clone, so A's detour came along and still fires through B's table.
            EXPECT_EQ(dispatch_transform(object.get(), 7), 514);

            // A releases its object while B outranks it. DMK must retain the binding that keeps A's clone reachable.
            ASSERT_TRUE(a->remove_from(object.get()).has_value());
        }

        // The leaked clone retains its detour. Clear the published handle before handle destruction.
        a.reset();
        EXPECT_EQ(diagnostics::intentional_leak_count(diagnostics::LeakSubsystem::HookManager), before + 1)
            << "remove_from must not drop the binding of an object it could not release: ~A then frees a "
               "clone B still records as its original";

        b.reset();
        EXPECT_EQ(*reinterpret_cast<std::uintptr_t *>(object.get()), a_clone_base);
    }

    // Clone allocations churn the backend VirtualAlloc pool. CRT allocations do not touch that pool.
    for (int i = 0; i < 16; ++i)
    {
        auto churn_object = std::make_unique<VmtTestTarget>();
        Result<VmtHook> churn = vmt_for("RemoveOutrankedChurn", churn_object.get());
        ASSERT_TRUE(churn.has_value()) << churn.error().message();
        VmtHook churn_hook = std::move(*churn);
        ASSERT_TRUE(churn_hook.hook_method<VmtComputeFn>(VMT_COMPUTE_INDEX, &vmt_detour_compute).has_value());
    }

    // The leaked clone still holds A's transform detour. With s_method_vmt null, its marker proves that the slot
    // remains valid.
    EXPECT_EQ(dispatch_transform(object.get(), 7), -1)
        << "the object must still dispatch through A's leaked clone rather than freed or recycled memory";
    EXPECT_EQ(diagnostics::intentional_leak_count(diagnostics::LeakSubsystem::HookManager), before + 1);
}

// A recorded original must remain true after B replaces A. A reapply discards B and leaves its eventual restore at risk
// of freed storage.
TEST(HookVmtLayered, ReapplyAcrossNewerLayerIsRefused)
{
    auto object = std::make_unique<VmtTestTarget>();
    const std::uintptr_t pristine_vptr = *reinterpret_cast<std::uintptr_t *>(object.get());
    const std::size_t before = diagnostics::intentional_leak_count(diagnostics::LeakSubsystem::HookManager);

    {
        dmk_test::LoggerFileCapture capture{DetourModKit::LogLevel::Warning};

        Result<VmtHook> ra = vmt_for("ReapplyLayerA", object.get());
        ASSERT_TRUE(ra.has_value()) << ra.error().message();
        std::optional<VmtHook> a(std::move(*ra));
        const std::uintptr_t a_clone_base = *reinterpret_cast<std::uintptr_t *>(object.get());

        Result<VmtHook> rb = vmt_for("ReapplyLayerB", object.get());
        ASSERT_TRUE(rb.has_value()) << rb.error().message();
        std::optional<VmtHook> b(std::move(*rb));
        const std::uintptr_t b_clone_base = *reinterpret_cast<std::uintptr_t *>(object.get());
        ASSERT_NE(a_clone_base, b_clone_base);

        const Result<void> reapplied = a->apply_to(object.get());
        ASSERT_FALSE(reapplied.has_value()) << "a re-apply across a newer layer must not silently republish";
        EXPECT_EQ(reapplied.error().code, ErrorCode::HookAlreadyExists);
        EXPECT_EQ(*reinterpret_cast<std::uintptr_t *>(object.get()), b_clone_base)
            << "a refused apply must leave the object where the newer layer put it";

        // A's original binding remains true. Its teardown must detect B's newer layer and retain the clone.
        a.reset();
        EXPECT_EQ(diagnostics::intentional_leak_count(diagnostics::LeakSubsystem::HookManager), before + 1)
            << "the refused re-apply must leave A's binding able to detect that it is outranked";

        b.reset();
        EXPECT_EQ(*reinterpret_cast<std::uintptr_t *>(object.get()), a_clone_base);
    }

    EXPECT_NE(*reinterpret_cast<std::uintptr_t *>(object.get()), pristine_vptr);
    EXPECT_EQ(dispatch_compute(object.get(), 2, 3), 5);
}

// The untracked object already names this clone, but the handle has no original for it. Both policies must refuse that
// self-reference.
TEST(HookVmt, ApplyToUntrackedObjectOnOwnCloneIsRefusedUnderEveryPolicy)
{
    auto seed = std::make_unique<VmtTestTarget>();
    auto stowaway = std::make_unique<VmtTestTarget>();
    const std::uintptr_t stowaway_pristine = *reinterpret_cast<std::uintptr_t *>(stowaway.get());

    Result<VmtHook> r = vmt_for("StowawaySeed", seed.get());
    ASSERT_TRUE(r.has_value()) << r.error().message();
    VmtHook vh = std::move(*r);
    const std::uintptr_t clone_base = *reinterpret_cast<std::uintptr_t *>(seed.get());

    // The shape a host produces by byte-copying, pooling or recycling an instance whose vptr word was captured while
    // it was on the clone. No kit call put this object here, so no binding exists for it.
    *reinterpret_cast<std::uintptr_t *>(stowaway.get()) = clone_base;

    // The stowaway must come off the clone even when an assertion below returns early. Declared after vh, this guard
    // restores before vh frees the clone and before ~VmtTestTarget dispatches its virtual destructor.
    struct RestoreStowaway
    {
        void *object;
        std::uintptr_t vptr;
        ~RestoreStowaway() noexcept { *reinterpret_cast<std::uintptr_t *>(object) = vptr; }
    } const restore{stowaway.get(), stowaway_pristine};

    const std::array<VmtOptions, 2> policies{
        VmtOptions{},
        VmtOptions{
            .fail_if_already_hooked = true,
        }
    };
    for (const VmtOptions &options : policies)
    {
        const Result<void> applied = vh.apply_to(stowaway.get(), options);
        ASSERT_FALSE(applied.has_value()) << "fail_if_already_hooked=" << options.fail_if_already_hooked;
        EXPECT_EQ(applied.error().code, ErrorCode::HookAlreadyExists)
            << "fail_if_already_hooked=" << options.fail_if_already_hooked;
    }
}
