// Unit tests for Math utilities module
#include <gtest/gtest.h>
#include <cmath>

#include "DetourModKit/math_utils.hpp"

using namespace DetourModKit;

// Test DegreesToRadians
TEST(MathUtilsTest, DegreesToRadians)
{
    // 0 degrees = 0 radians
    float result = Math::DegreesToRadians(0.0f);
    EXPECT_FLOAT_EQ(result, 0.0f);

    // 180 degrees = PI radians
    result = Math::DegreesToRadians(180.0f);
    EXPECT_NEAR(result, 3.14159265f, 0.0001f);

    // 90 degrees = PI/2 radians
    result = Math::DegreesToRadians(90.0f);
    EXPECT_NEAR(result, 1.57079633f, 0.0001f);
}

// Test RadiansToDegrees
TEST(MathUtilsTest, RadiansToDegrees)
{
    // 0 radians = 0 degrees
    float result = Math::RadiansToDegrees(0.0f);
    EXPECT_FLOAT_EQ(result, 0.0f);

    // PI radians = 180 degrees
    result = Math::RadiansToDegrees(3.14159265f);
    EXPECT_NEAR(result, 180.0f, 0.0001f);

    // PI/2 radians = 90 degrees
    result = Math::RadiansToDegrees(1.57079633f);
    EXPECT_NEAR(result, 90.0f, 0.0001f);
}

// Test round-trip conversion
TEST(MathUtilsTest, RoundTrip)
{
    float original = 45.0f;
    float radians = Math::DegreesToRadians(original);
    float back_to_degrees = Math::RadiansToDegrees(radians);

    EXPECT_NEAR(back_to_degrees, original, 0.0001f);
}
