#ifndef DETOURMODKIT_INTERNAL_CONFIG_DIAGNOSTICS_HPP
#define DETOURMODKIT_INTERNAL_CONFIG_DIAGNOSTICS_HPP

/**
 * @file internal/config_diagnostics.hpp
 * @brief Deferred diagnostic records for a critical section.
 * @details A config producer records a source-stamped line under its lock. The caller emits that line after unlock.
 */

#include "DetourModKit/logger.hpp"

#include <format>
#include <source_location>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

namespace DetourModKit::detail
{
    /**
     * @class LoggerDropAccess
     * @brief Provides private drop-count access to internal no-throw record adapters.
     */
    class LoggerDropAccess
    {
    public:
        /// Adds one internal record loss to @p logger without sink delivery.
        static void record(Logger &logger) noexcept
        {
            logger.m_dropped_messages.fetch_add(1, std::memory_order_relaxed);
        }

    private:
        LoggerDropAccess() = delete;
    };
} // namespace DetourModKit::detail

namespace DetourModKit::config::detail
{
    /**
     * @struct DeferredDiagnostic
     * @brief One config diagnostic for emission after unlock.
     */
    struct DeferredDiagnostic
    {
        LogLevel level{LogLevel::Info};
        std::string line;
    };

    /**
     * @struct DeferredDiagnostics
     * @brief The config records of one critical section and the threshold captured before its lock.
     * @details @ref threshold preserves the direct logger's lazy format rule.
     */
    struct DeferredDiagnostics
    {
        LogLevel threshold{LogLevel::Trace};
        std::vector<DeferredDiagnostic> records;
    };

    /// Returns an empty record list whose threshold is the current process logger level.
    [[nodiscard]] DeferredDiagnostics open_deferred_diagnostics() noexcept;

    [[nodiscard]] constexpr std::string_view deferred_source_basename(std::string_view path) noexcept
    {
        const auto pos = path.find_last_of("/\\");
        return pos == std::string_view::npos ? path : path.substr(pos + 1);
    }

    /**
     * @brief Records one line with the explicit @p where stamp when @p level passes the captured threshold.
     * @details The format and list append allocate. Keep this off callback paths.
     */
    template <typename... Args>
    void defer_diagnostic_at(
        DeferredDiagnostics &diags,
        LogLevel level,
        std::source_location where,
        std::format_string<std::type_identity_t<Args>...> fmt,
        Args &&...args
    )
    {
        if (level < diags.threshold)
        {
            return;
        }
        diags.records.push_back({
            .level = level,
            .line = std::format(
                "[{}:{}] {}",
                deferred_source_basename(where.file_name()),
                where.line(),
                std::format(fmt, std::forward<Args>(args)...)
            ),
        });
    }

    /**
     * @brief Records one source-stamped line when @p level passes the captured threshold.
     * @details The format and list append allocate. Keep this off callback paths.
     */
    template <typename... Args>
    void defer_diagnostic(
        DeferredDiagnostics &diags,
        LogLevel level,
        LocatedFormat<std::type_identity_t<Args>...> fmt,
        Args &&...args
    )
    {
        defer_diagnostic_at(diags, level, fmt.where, fmt.fmt, std::forward<Args>(args)...);
    }

    /**
     * @brief Records the canonical StoppableWorker start line through a type-erased context.
     * @details The context must point to DeferredDiagnostics. A format failure increments the logger drop count and
     *          suppresses the exception.
     * @param context The DeferredDiagnostics address.
     * @param name The worker name.
     * @param where The original record source.
     */
    inline void defer_worker_start_diagnostic(void *context, std::string_view name, std::source_location where) noexcept
    {
        if (context == nullptr)
        {
            return;
        }
        auto &diags = *static_cast<DeferredDiagnostics *>(context);
        try
        {
            defer_diagnostic_at(diags, LogLevel::Debug, where, "StoppableWorker '{}' started.", name);
        }
        catch (...)
        {
            DetourModKit::detail::LoggerDropAccess::record(log());
        }
    }

    /**
     * @brief Emits every record in @p diags through the process logger, then clears the list.
     * @details The caller must hold no lock that a producer of these records took. Delivery is best-effort: a sink or
     *          format failure drops the record and leaves the count in Logger::dropped_count().
     */
    void emit_deferred_diagnostics(DeferredDiagnostics &diags) noexcept;
} // namespace DetourModKit::config::detail

#endif // DETOURMODKIT_INTERNAL_CONFIG_DIAGNOSTICS_HPP
