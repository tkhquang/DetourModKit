// Unit tests for Math utilities module
#include <gtest/gtest.h>
#include <cmath>

#include "DetourModKit/math.hpp"

using namespace DetourModKit;

// Test DegreesToRadians with zero
TEST(MathUtilsTest, DegreesToRadians_Zero)
{
    float result = Math::DegreesToRadians(0.0f);
    EXPECT_FLOAT_EQ(result, 0.0f);
}

// Test DegreesToRadians with 180 degrees
TEST(MathUtilsTest, DegreesToRadians_180)
{
    float result = Math::DegreesToRadians(180.0f);
    EXPECT_NEAR(result, 3.14159265f, 0.0001f);
}

// Test DegreesToRadians with 90 degrees
TEST(MathUtilsTest, DegreesToRadians_90)
{
    float result = Math::DegreesToRadians(90.0f);
    EXPECT_NEAR(result, 1.57079633f, 0.0001f);
}

// Test DegreesToRadians with 360 degrees
TEST(MathUtilsTest, DegreesToRadians_360)
{
    float result = Math::DegreesToRadians(360.0f);
    EXPECT_NEAR(result, 6.28318530f, 0.0001f);
}

// Test DegreesToRadians with negative angle
TEST(MathUtilsTest, DegreesToRadians_Negative)
{
    float result = Math::DegreesToRadians(-90.0f);
    EXPECT_NEAR(result, -1.57079633f, 0.0001f);
}

// Test DegreesToRadians with 45 degrees
TEST(MathUtilsTest, DegreesToRadians_45)
{
    float result = Math::DegreesToRadians(45.0f);
    EXPECT_NEAR(result, 0.78539816f, 0.0001f);
}

// Test RadiansToDegrees with zero
TEST(MathUtilsTest, RadiansToDegrees_Zero)
{
    float result = Math::RadiansToDegrees(0.0f);
    EXPECT_FLOAT_EQ(result, 0.0f);
}

// Test RadiansToDegrees with PI
TEST(MathUtilsTest, RadiansToDegrees_PI)
{
    float result = Math::RadiansToDegrees(3.14159265f);
    EXPECT_NEAR(result, 180.0f, 0.0001f);
}

// Test RadiansToDegrees with PI/2
TEST(MathUtilsTest, RadiansToDegrees_HalfPI)
{
    float result = Math::RadiansToDegrees(1.57079633f);
    EXPECT_NEAR(result, 90.0f, 0.0001f);
}

// Test RadiansToDegrees with 2*PI
TEST(MathUtilsTest, RadiansToDegrees_2PI)
{
    float result = Math::RadiansToDegrees(6.28318530f);
    EXPECT_NEAR(result, 360.0f, 0.0001f);
}

// Test RadiansToDegrees with negative angle
TEST(MathUtilsTest, RadiansToDegrees_Negative)
{
    float result = Math::RadiansToDegrees(-1.57079633f);
    EXPECT_NEAR(result, -90.0f, 0.0001f);
}

// Test RadiansToDegrees with PI/4
TEST(MathUtilsTest, RadiansToDegrees_QuarterPI)
{
    float result = Math::RadiansToDegrees(0.78539816f);
    EXPECT_NEAR(result, 45.0f, 0.0001f);
}

// Test round-trip conversion degrees -> radians -> degrees
TEST(MathUtilsTest, RoundTrip_Degrees)
{
    float original = 45.0f;
    float radians = Math::DegreesToRadians(original);
    float back_to_degrees = Math::RadiansToDegrees(radians);

    EXPECT_NEAR(back_to_degrees, original, 0.0001f);
}

// Test round-trip conversion radians -> degrees -> radians
TEST(MathUtilsTest, RoundTrip_Radians)
{
    float original = 1.0f;
    float degrees = Math::RadiansToDegrees(original);
    float back_to_radians = Math::DegreesToRadians(degrees);

    EXPECT_NEAR(back_to_radians, original, 0.0001f);
}

// Test common angle conversions
TEST(MathUtilsTest, CommonAngles)
{
    // Test that common angles convert correctly
    const float PI = 3.14159265f;

    // 30 degrees = PI/6
    EXPECT_NEAR(Math::DegreesToRadians(30.0f), PI / 6.0f, 0.0001f);

    // 60 degrees = PI/3
    EXPECT_NEAR(Math::DegreesToRadians(60.0f), PI / 3.0f, 0.0001f);

    // 120 degrees = 2*PI/3
    EXPECT_NEAR(Math::DegreesToRadians(120.0f), 2.0f * PI / 3.0f, 0.0001f);

    // 270 degrees = 3*PI/2
    EXPECT_NEAR(Math::DegreesToRadians(270.0f), 3.0f * PI / 2.0f, 0.0001f);
}

// Test large angle conversion
TEST(MathUtilsTest, LargeAngles)
{
    // 720 degrees = 4*PI
    float result = Math::DegreesToRadians(720.0f);
    EXPECT_NEAR(result, 12.5663706f, 0.0001f);
}

// Test small angle conversion
TEST(MathUtilsTest, SmallAngles)
{
    // 1 degree
    float result = Math::DegreesToRadians(1.0f);
    EXPECT_NEAR(result, 0.01745329f, 0.0001f);
}
