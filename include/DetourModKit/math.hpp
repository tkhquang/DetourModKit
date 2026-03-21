#pragma once
/**
 * @file math.hpp
 * @brief Provides basic mathematical utility functions.
 */
#include <numbers>

namespace DetourModKit
{
    namespace Math
    {
        /// Converts an angle from degrees to radians.
        constexpr float degrees_to_radians(float degrees) noexcept
        {
            return degrees * (std::numbers::pi_v<float> / 180.0f);
        }

        /// Converts an angle from radians to degrees.
        constexpr float radians_to_degrees(float radians) noexcept
        {
            return radians * (180.0f / std::numbers::pi_v<float>);
        }

    } // namespace Math
} // namespace DetourModKit
