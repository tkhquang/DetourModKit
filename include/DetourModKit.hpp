#pragma once

/**
 * @file DetourModKit.hpp
 * @brief Central header file for DetourModKit library.
 * @details This header provides a single include point for all DetourModKit functionality,
 *          along with convenient namespace aliases for common usage patterns.
 *          Include this header to access all DetourModKit features.
 */

// Core functionality headers
#include "DetourModKit/aob_scanner.hpp"
#include "DetourModKit/config.hpp"
#include "DetourModKit/hook_manager.hpp"
#include "DetourModKit/logger.hpp"

// Utility headers
#include "DetourModKit/filesystem_utils.hpp"
#include "DetourModKit/math_utils.hpp"
#include "DetourModKit/memory_utils.hpp"
#include "DetourModKit/string_utils.hpp"

/**
 * @brief Convenient namespace aliases for common DetourModKit usage patterns.
 * @details These aliases allow for shorter, more readable code when using DetourModKit
 *          functionality extensively. Example: DMK::Logger instead of DetourModKit::Logger.
 */
namespace DMK = DetourModKit;
namespace DMKConfig = DetourModKit::Config;
namespace DMKScanner = DetourModKit::Scanner;
namespace DMKString = DetourModKit::String;
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
