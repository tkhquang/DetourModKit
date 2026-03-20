#pragma once

/**
 * @file DetourModKit.hpp
 * @brief Central header file for DetourModKit library.
 * @details This header provides a single include point for all DetourModKit functionality,
 *          along with convenient namespace aliases for common usage patterns.
 *          Include this header to access all DetourModKit features.
 */

// Core functionality headers
#include "DetourModKit/config.hpp"
#include "DetourModKit/hook_manager.hpp"
#include "DetourModKit/logger.hpp"
#include "DetourModKit/async_logger.hpp"

// Module headers
#include "DetourModKit/filesystem.hpp"
#include "DetourModKit/format.hpp"
#include "DetourModKit/math.hpp"
#include "DetourModKit/memory.hpp"
#include "DetourModKit/scanner.hpp"

/**
 * @brief Convenient namespace aliases for common DetourModKit usage patterns.
 * @details These aliases allow for shorter, more readable code when using DetourModKit
 *          functionality extensively. Example: DMK::Logger instead of DetourModKit::Logger.
 */
namespace DMK = DetourModKit;
namespace DMKConfig = DetourModKit::Config;
namespace DMKScanner = DetourModKit::Scanner;
namespace DMKString = DetourModKit::String;
namespace DMKFormat = DetourModKit::Format;
namespace DMKFilesystem = DetourModKit::Filesystem;
namespace DMKMemory = DetourModKit::Memory;
namespace DMKMath = DetourModKit::Math;

/**
 * @brief Convenient type aliases for commonly used DetourModKit types.
 * @details These aliases provide shorter names for frequently used types.
 */
using DMKLogger = DetourModKit::Logger;
using DMKHookManager = DetourModKit::HookManager;
using DMKLogLevel = DetourModKit::LogLevel;
using DMKHookStatus = DetourModKit::HookStatus;
using DMKHookType = DetourModKit::HookType;
using DMKHookConfig = DetourModKit::HookConfig;
using DMKAsyncLogger = DetourModKit::AsyncLogger;
using DMKAsyncLoggerConfig = DetourModKit::AsyncLoggerConfig;

/**
 * @brief Explicitly shuts down all DetourModKit singletons in the correct order.
 * @details This function should be called before process exit or DLL unload to ensure
 *          proper cleanup without use-after-free errors. It shuts down singletons in
 *          reverse dependency order: HookManager first (which may log), then Logger.
 *          After calling this function, the singletons are in a safe state for destruction.
 *
 * @note This function is idempotent - calling it multiple times is safe.
 */
inline void DMK_Shutdown()
{
    // Shutdown in reverse dependency order:
    // 1. HookManager first (may have been logging via Logger)
    DetourModKit::HookManager::get_instance().shutdown();

    // 2. Clear registered config items (static vector cleanup)
    DetourModKit::Config::clear_registered_items();

    // 3. Logger last (no more logging after this)
    DetourModKit::Logger::get_instance().shutdown();
}
using DMKOverflowPolicy = DetourModKit::OverflowPolicy;
