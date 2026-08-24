/**
 * @file internal/config_diagnostics.cpp
 * @brief Opens and drains the deferred diagnostic record list.
 * @details internal/config_diagnostics.hpp owns the contract.
 */

#include "internal/config_diagnostics.hpp"

namespace DetourModKit::config::detail
{
    DeferredDiagnostics open_deferred_diagnostics() noexcept
    {
        return DeferredDiagnostics{
            .threshold = log().get_log_level(),
            .records = {},
        };
    }

    void emit_deferred_diagnostics(DeferredDiagnostics &diags) noexcept
    {
        Logger &logger = log();
        for (const DeferredDiagnostic &record : diags.records)
        {
            (void)logger.log_noexcept(record.level, record.line);
        }
        diags.records.clear();
    }
} // namespace DetourModKit::config::detail
