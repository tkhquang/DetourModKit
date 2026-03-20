#include <gtest/gtest.h>
#include <cmath>
#include <DirectXMath.h>

#include "DetourModKit/math.hpp"

using namespace DetourModKit;

static constexpr float PI = DirectX::XM_PI;

TEST(MathTest, degrees_to_radians_Zero)
{
    EXPECT_FLOAT_EQ(Math::degrees_to_radians(0.0f), 0.0f);
}

TEST(MathTest, degrees_to_radians_90)
{
    EXPECT_NEAR(Math::degrees_to_radians(90.0f), PI / 2.0f, 0.0001f);
}

TEST(MathTest, degrees_to_radians_180)
{
    EXPECT_NEAR(Math::degrees_to_radians(180.0f), PI, 0.0001f);
}

TEST(MathTest, degrees_to_radians_360)
{
    EXPECT_NEAR(Math::degrees_to_radians(360.0f), 2.0f * PI, 0.0001f);
}

TEST(MathTest, degrees_to_radians_Negative)
{
    EXPECT_NEAR(Math::degrees_to_radians(-90.0f), -PI / 2.0f, 0.0001f);
}

TEST(MathTest, degrees_to_radians_Large)
{
    EXPECT_NEAR(Math::degrees_to_radians(720.0f), 4.0f * PI, 0.0001f);
}

TEST(MathTest, radians_to_degrees_Zero)
{
    EXPECT_FLOAT_EQ(Math::radians_to_degrees(0.0f), 0.0f);
}

TEST(MathTest, radians_to_degrees_PI)
{
    EXPECT_NEAR(Math::radians_to_degrees(PI), 180.0f, 0.0001f);
}

TEST(MathTest, radians_to_degrees_HalfPI)
{
    EXPECT_NEAR(Math::radians_to_degrees(PI / 2.0f), 90.0f, 0.0001f);
}

TEST(MathTest, radians_to_degrees_2PI)
{
    EXPECT_NEAR(Math::radians_to_degrees(2.0f * PI), 360.0f, 0.0001f);
}

TEST(MathTest, radians_to_degrees_Negative)
{
    EXPECT_NEAR(Math::radians_to_degrees(-PI / 2.0f), -90.0f, 0.0001f);
}

TEST(MathTest, RoundTrip_Degrees)
{
    float original = 137.0f;
    float radians = Math::degrees_to_radians(original);
    float back = Math::radians_to_degrees(radians);
    EXPECT_NEAR(back, original, 0.0001f);
}

TEST(MathTest, RoundTrip_Radians)
{
    float original = 1.0f;
    float degrees = Math::radians_to_degrees(original);
    float back = Math::degrees_to_radians(degrees);
    EXPECT_NEAR(back, original, 0.0001f);
}
