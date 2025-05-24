#pragma once // Ensures this header is included only once per compilation unit
/**
 * @file math_utils.hpp
 * @brief Provides basic mathematical utility functions.
 */
#include <DirectXMath.h>

namespace DetourModKit
{
    namespace Math
    {
        /**
         * @brief Converts an angle from degrees to radians.
         * @param degrees The angle in degrees.
         * @return float The angle converted to radians.
         */
        inline float DegreesToRadians(float degrees)
        {
            // DirectX::XM_PI is a high-precision constant for PI.
            return degrees * (DirectX::XM_PI / 180.0f);
        }

        /**
         * @brief Converts an angle from radians to degrees.
         * @param radians The angle in radians.
         * @return float The angle converted to degrees.
         */
        inline float RadiansToDegrees(float radians)
        {
            return radians * (180.0f / DirectX::XM_PI);
        }

    } // namespace Math
} // namespace DetourModKit
