#ifndef DETOURMODKIT_INTERNAL_CONFIG_PASS_HPP
#define DETOURMODKIT_INTERNAL_CONFIG_PASS_HPP

/**
 * @file internal/config_pass.hpp
 * @brief Data-plane pass vocabulary owned by config.cpp.
 * @details The reload control plane (src/internal/config_reload.cpp) and the watcher control plane (config_watch.cpp)
 *          drive the registry pass and the combo grammar through this seam. The registry state, the SimpleIni
 *          pipeline, and the grammar itself stay confined to config.cpp.
 */

#include "DetourModKit/input.hpp"
#include "DetourModKit/logger.hpp"

#include <filesystem>
#include <string>
#include <string_view>

namespace DetourModKit::config::detail
{
    class BackgroundReloadGuard;

    /**
     * @brief Reloads configuration and reports whether setters ran.
     * @param[out] out_setters_ran True once at least one deferred setter is invoked. False when the hash skip, a
     *                             read/parse failure, an empty setter list, or an unload latch stopped the pass before
     *                             the first setter.
     * @param background_guard Optional admission guard for a background pass. The setter loop aborts when the guard
     *                         leaves its enabled lifecycle mid-pass.
     * @return true if a previous load() path was available. False if reload() preceded any load(), or if
     *         ReloadApplyLock refused a same-thread re-entry.
     */
    [[nodiscard]] bool reload_impl(bool &out_setters_ran, const BackgroundReloadGuard *background_guard = nullptr);

    /// Takes the config mutex and returns a tear-free copy of the INI path last passed to load().
    [[nodiscard]] std::string snapshot_last_loaded_ini_path();

    /// Determines the full absolute path for the INI configuration file.
    [[nodiscard]] std::filesystem::path get_ini_file_path(const std::string &ini_filename, Logger &logger);

    /**
     * @brief Parses a comma-separated string of key combos (OR logic) into a KeyComboList.
     * @details Two opt-out sentinels yield an empty result silently: an empty post-trim input and the literal
     *          "NONE". A non-empty non-sentinel input whose every token fails to parse is a user typo and
     *          emits one WARNING that names @p binding_log_name (or "<unnamed>").
     */
    [[nodiscard]] input::KeyComboList
    parse_key_combo_list(const std::string &input, std::string_view binding_log_name = {});
} // namespace DetourModKit::config::detail

#endif // DETOURMODKIT_INTERNAL_CONFIG_PASS_HPP
