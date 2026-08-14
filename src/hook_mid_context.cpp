/**
 * @file hook_mid_context.cpp
 * @brief This TU implements the hook::MidContext accessor bridge over the backend register frame.
 */

#include "DetourModKit/hook.hpp"

#include "internal/hook_backend.hpp"

#include <cstddef>
#include <cstdint>
#include <cstring>

namespace DetourModKit
{
    namespace hook
    {
        // The hook::MidContext accessor bridge keeps MidContext incomplete. These accessors alone recover the real
        // safetyhook::Context64 through reinterpret_cast. The reference always denotes the exact Context64 from the
        // backend, so the cast is well-defined.
        std::uintptr_t &gpr(MidContext &ctx, Gpr reg) noexcept
        {
            auto &context = reinterpret_cast<safetyhook::Context64 &>(ctx);
            switch (reg)
            {
            case Gpr::Rax:
                return context.rax;
            case Gpr::Rbx:
                return context.rbx;
            case Gpr::Rcx:
                return context.rcx;
            case Gpr::Rdx:
                return context.rdx;
            case Gpr::Rsi:
                return context.rsi;
            case Gpr::Rdi:
                return context.rdi;
            case Gpr::Rbp:
                return context.rbp;
            case Gpr::R8:
                return context.r8;
            case Gpr::R9:
                return context.r9;
            case Gpr::R10:
                return context.r10;
            case Gpr::R11:
                return context.r11;
            case Gpr::R12:
                return context.r12;
            case Gpr::R13:
                return context.r13;
            case Gpr::R14:
                return context.r14;
            case Gpr::R15:
                return context.r15;
            }
            // Every enumerator returns above. The rax return keeps the function well-formed.
            return context.rax;
        }

        std::uintptr_t stack_pointer(const MidContext &ctx) noexcept
        {
            return reinterpret_cast<const safetyhook::Context64 &>(ctx).rsp;
        }

        std::uintptr_t &resume_stack_pointer(MidContext &ctx) noexcept
        {
            return reinterpret_cast<safetyhook::Context64 &>(ctx).trampoline_rsp;
        }

        std::uintptr_t &instruction_pointer(MidContext &ctx) noexcept
        {
            return reinterpret_cast<safetyhook::Context64 &>(ctx).rip;
        }

        std::uintptr_t &flags(MidContext &ctx) noexcept
        {
            return reinterpret_cast<safetyhook::Context64 &>(ctx).rflags;
        }

        // The mid-hook assembly stub stores each captured register at a fixed offset. These assertions pin the C++
        // layout to the complete frame ABI, with the XMM prefix and integer/resume tail (T-XMM). Pointer
        // arithmetic from &xmm0 across distinct members is undefined C++. Layout assertions do not legalize it, so the
        // switch below uses explicit member selection.
        static_assert(sizeof(safetyhook::Xmm) == 16);
        static_assert(offsetof(safetyhook::Context64, xmm0) == 0);
        static_assert(offsetof(safetyhook::Context64, xmm1) == 16);
        static_assert(offsetof(safetyhook::Context64, xmm2) == 32);
        static_assert(offsetof(safetyhook::Context64, xmm3) == 48);
        static_assert(offsetof(safetyhook::Context64, xmm4) == 64);
        static_assert(offsetof(safetyhook::Context64, xmm5) == 80);
        static_assert(offsetof(safetyhook::Context64, xmm6) == 96);
        static_assert(offsetof(safetyhook::Context64, xmm7) == 112);
        static_assert(offsetof(safetyhook::Context64, xmm8) == 128);
        static_assert(offsetof(safetyhook::Context64, xmm9) == 144);
        static_assert(offsetof(safetyhook::Context64, xmm10) == 160);
        static_assert(offsetof(safetyhook::Context64, xmm11) == 176);
        static_assert(offsetof(safetyhook::Context64, xmm12) == 192);
        static_assert(offsetof(safetyhook::Context64, xmm13) == 208);
        static_assert(offsetof(safetyhook::Context64, xmm14) == 224);
        static_assert(offsetof(safetyhook::Context64, xmm15) == 240);
        static_assert(offsetof(safetyhook::Context64, rflags) == 256);
        static_assert(offsetof(safetyhook::Context64, r15) == 264);
        static_assert(offsetof(safetyhook::Context64, r14) == 272);
        static_assert(offsetof(safetyhook::Context64, r13) == 280);
        static_assert(offsetof(safetyhook::Context64, r12) == 288);
        static_assert(offsetof(safetyhook::Context64, r11) == 296);
        static_assert(offsetof(safetyhook::Context64, r10) == 304);
        static_assert(offsetof(safetyhook::Context64, r9) == 312);
        static_assert(offsetof(safetyhook::Context64, r8) == 320);
        static_assert(offsetof(safetyhook::Context64, rdi) == 328);
        static_assert(offsetof(safetyhook::Context64, rsi) == 336);
        static_assert(offsetof(safetyhook::Context64, rdx) == 344);
        static_assert(offsetof(safetyhook::Context64, rcx) == 352);
        static_assert(offsetof(safetyhook::Context64, rbx) == 360);
        static_assert(offsetof(safetyhook::Context64, rax) == 368);
        static_assert(offsetof(safetyhook::Context64, rbp) == 376);
        static_assert(offsetof(safetyhook::Context64, rsp) == 384);
        static_assert(offsetof(safetyhook::Context64, trampoline_rsp) == 392);
        static_assert(offsetof(safetyhook::Context64, rip) == 400);
        static_assert(sizeof(safetyhook::Context64) == 408);

        XmmView xmm(const MidContext &ctx, std::size_t index) noexcept
        {
            XmmView view{};
            const auto &context = reinterpret_cast<const safetyhook::Context64 &>(ctx);
            const safetyhook::Xmm *reg = nullptr;
            switch (index)
            {
            case 0:
                reg = &context.xmm0;
                break;
            case 1:
                reg = &context.xmm1;
                break;
            case 2:
                reg = &context.xmm2;
                break;
            case 3:
                reg = &context.xmm3;
                break;
            case 4:
                reg = &context.xmm4;
                break;
            case 5:
                reg = &context.xmm5;
                break;
            case 6:
                reg = &context.xmm6;
                break;
            case 7:
                reg = &context.xmm7;
                break;
            case 8:
                reg = &context.xmm8;
                break;
            case 9:
                reg = &context.xmm9;
                break;
            case 10:
                reg = &context.xmm10;
                break;
            case 11:
                reg = &context.xmm11;
                break;
            case 12:
                reg = &context.xmm12;
                break;
            case 13:
                reg = &context.xmm13;
                break;
            case 14:
                reg = &context.xmm14;
                break;
            case 15:
                reg = &context.xmm15;
                break;
            default:
                // Fail closed: an out-of-range index returns the zeroed view.
                return view;
            }
            // The 16 bytes are copied out by value: XMM is surfaced read-only.
            std::memcpy(view.bytes.data(), reg->u8, view.bytes.size());
            return view;
        }
    } // namespace hook
} // namespace DetourModKit
