#pragma once
/**
 * @file math.hpp
 * @brief Provides basic mathematical utility functions.
 */
#include <DirectXMath.h>

namespace DetourModKit
{
    namespace Math
    {
        /// Converts an angle from degrees to radians.
        constexpr float degrees_to_radians(float degrees) noexcept
        {
            return degrees * (DirectX::XM_PI / 180.0f);
        }

        /// Converts an angle from radians to degrees.
        constexpr float radians_to_degrees(float radians) noexcept
        {
            return radians * (180.0f / DirectX::XM_PI);
        }

    } // namespace Math
} // namespace DetourModKit
