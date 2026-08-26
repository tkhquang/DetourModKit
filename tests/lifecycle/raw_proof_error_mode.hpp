#ifndef DETOURMODKIT_TESTS_LIFECYCLE_RAW_PROOF_ERROR_MODE_HPP
#define DETOURMODKIT_TESTS_LIFECYCLE_RAW_PROOF_ERROR_MODE_HPP

#include <windows.h>

namespace dmk_lifecycle
{
    inline constexpr wchar_t WER_CAPTURE_ENV[] = L"DMK_LIFECYCLE_WER_ACTIVE";

    /**
     * @brief Suppresses modal fault dialogs unless the release soak needs WER dumps.
     * @details The release soak clears the inherited error mode and sets @ref WER_CAPTURE_ENV.
     *          SEM_NOGPFAULTERRORBOX prevents WER, so an armed proof must preserve the cleared mode.
     */
    inline void configure_raw_proof_error_mode() noexcept
    {
        if (::GetEnvironmentVariableW(WER_CAPTURE_ENV, nullptr, 0) != 0)
        {
            const UINT mode = ::GetErrorMode();
            ::SetErrorMode(mode & ~SEM_NOGPFAULTERRORBOX);
            return;
        }

#if defined(_MSC_VER)
        ::SetErrorMode(SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS);
#endif
    }
} // namespace dmk_lifecycle

#endif // DETOURMODKIT_TESTS_LIFECYCLE_RAW_PROOF_ERROR_MODE_HPP
