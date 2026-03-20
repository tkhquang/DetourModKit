// Unit tests for Math utilities module
#include <gtest/gtest.h>
#include <cmath>

#include "DetourModKit/math.hpp"

using namespace DetourModKit;

// Test degrees_to_radians with zero
TEST(MathTest, degrees_to_radians_Zero)
{
    float result = Math::degrees_to_radians(0.0f);
    EXPECT_FLOAT_EQ(result, 0.0f);
}

// Test degrees_to_radians with 180 degrees
TEST(MathTest, degrees_to_radians_180)
{
    float result = Math::degrees_to_radians(180.0f);
    EXPECT_NEAR(result, 3.14159265f, 0.0001f);
}

// Test degrees_to_radians with 90 degrees
TEST(MathTest, degrees_to_radians_90)
{
    float result = Math::degrees_to_radians(90.0f);
    EXPECT_NEAR(result, 1.57079633f, 0.0001f);
}

// Test degrees_to_radians with 360 degrees
TEST(MathTest, degrees_to_radians_360)
{
    float result = Math::degrees_to_radians(360.0f);
    EXPECT_NEAR(result, 6.28318530f, 0.0001f);
}

// Test degrees_to_radians with negative angle
TEST(MathTest, degrees_to_radians_Negative)
{
    float result = Math::degrees_to_radians(-90.0f);
    EXPECT_NEAR(result, -1.57079633f, 0.0001f);
}

// Test degrees_to_radians with 45 degrees
TEST(MathTest, degrees_to_radians_45)
{
    float result = Math::degrees_to_radians(45.0f);
    EXPECT_NEAR(result, 0.78539816f, 0.0001f);
}

// Test radians_to_degrees with zero
TEST(MathTest, radians_to_degrees_Zero)
{
    float result = Math::radians_to_degrees(0.0f);
    EXPECT_FLOAT_EQ(result, 0.0f);
}

// Test radians_to_degrees with PI
TEST(MathTest, radians_to_degrees_PI)
{
    float result = Math::radians_to_degrees(3.14159265f);
    EXPECT_NEAR(result, 180.0f, 0.0001f);
}

// Test radians_to_degrees with PI/2
TEST(MathTest, radians_to_degrees_HalfPI)
{
    float result = Math::radians_to_degrees(1.57079633f);
    EXPECT_NEAR(result, 90.0f, 0.0001f);
}

// Test radians_to_degrees with 2*PI
TEST(MathTest, radians_to_degrees_2PI)
{
    float result = Math::radians_to_degrees(6.28318530f);
    EXPECT_NEAR(result, 360.0f, 0.0001f);
}

// Test radians_to_degrees with negative angle
TEST(MathTest, radians_to_degrees_Negative)
{
    float result = Math::radians_to_degrees(-1.57079633f);
    EXPECT_NEAR(result, -90.0f, 0.0001f);
}

// Test radians_to_degrees with PI/4
TEST(MathTest, radians_to_degrees_QuarterPI)
{
    float result = Math::radians_to_degrees(0.78539816f);
    EXPECT_NEAR(result, 45.0f, 0.0001f);
}

// Test round-trip conversion degrees -> radians -> degrees
TEST(MathTest, RoundTrip_Degrees)
{
    float original = 45.0f;
    float radians = Math::degrees_to_radians(original);
    float back_to_degrees = Math::radians_to_degrees(radians);

    EXPECT_NEAR(back_to_degrees, original, 0.0001f);
}

// Test round-trip conversion radians -> degrees -> radians
TEST(MathTest, RoundTrip_Radians)
{
    float original = 1.0f;
    float degrees = Math::radians_to_degrees(original);
    float back_to_radians = Math::degrees_to_radians(degrees);

    EXPECT_NEAR(back_to_radians, original, 0.0001f);
}

// Test common angle conversions
TEST(MathTest, CommonAngles)
{
    // Test that common angles convert correctly
    const float PI = 3.14159265f;

    // 30 degrees = PI/6
    EXPECT_NEAR(Math::degrees_to_radians(30.0f), PI / 6.0f, 0.0001f);

    // 60 degrees = PI/3
    EXPECT_NEAR(Math::degrees_to_radians(60.0f), PI / 3.0f, 0.0001f);

    // 120 degrees = 2*PI/3
    EXPECT_NEAR(Math::degrees_to_radians(120.0f), 2.0f * PI / 3.0f, 0.0001f);

    // 270 degrees = 3*PI/2
    EXPECT_NEAR(Math::degrees_to_radians(270.0f), 3.0f * PI / 2.0f, 0.0001f);
}

// Test large angle conversion
TEST(MathTest, LargeAngles)
{
    // 720 degrees = 4*PI
    float result = Math::degrees_to_radians(720.0f);
    EXPECT_NEAR(result, 12.5663706f, 0.0001f);
}

// Test small angle conversion
TEST(MathTest, SmallAngles)
{
    // 1 degree
    float result = Math::degrees_to_radians(1.0f);
    EXPECT_NEAR(result, 0.01745329f, 0.0001f);
}
