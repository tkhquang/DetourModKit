#pragma once

#include <cmath>
#include <DirectXMath.h>
#include <string>
#include <sstream>
#include <iomanip>

// Basic Vector3 structure
struct Vector3
{
    float x, y, z;

    Vector3(float _x = 0.0f, float _y = 0.0f, float _z = 0.0f) : x(_x), y(_y), z(_z) {}

    // Basic operations
    Vector3 operator+(const Vector3 &other) const { return Vector3(x + other.x, y + other.y, z + other.z); }
    Vector3 operator-(const Vector3 &other) const { return Vector3(x - other.x, y - other.y, z - other.z); }
    Vector3 operator*(float scalar) const { return Vector3(x * scalar, y * scalar, z * scalar); }
    Vector3 operator/(float scalar) const { return (scalar != 0.0f) ? Vector3(x / scalar, y / scalar, z / scalar) : Vector3(); } // Add basic check

    Vector3 &operator+=(const Vector3 &other)
    {
        x += other.x;
        y += other.y;
        z += other.z;
        return *this;
    }
    Vector3 &operator-=(const Vector3 &other)
    {
        x -= other.x;
        y -= other.y;
        z -= other.z;
        return *this;
    }
    Vector3 &operator*=(float scalar)
    {
        x *= scalar;
        y *= scalar;
        z *= scalar;
        return *this;
    }

    float MagnitudeSquared() const { return x * x + y * y + z * z; }
    float Magnitude() const { return std::sqrt(MagnitudeSquared()); }

    Vector3 Normalized() const
    {
        float mag = Magnitude();
        if (mag == 0.0f)
            return Vector3(); // Avoid division by zero
        return Vector3(x / mag, y / mag, z / mag);
    }
    void Normalize()
    {
        float mag = Magnitude();
        if (mag == 0.0f)
            return;
        x /= mag;
        y /= mag;
        z /= mag;
    }

    Vector3 Cross(const Vector3 &other) const
    {
        return Vector3(
            y * other.z - z * other.y,
            z * other.x - x * other.z,
            x * other.y - y * other.x);
    }

    // DirectXMath conversion
    DirectX::XMVECTOR ToXMVector() const { return DirectX::XMVectorSet(x, y, z, 0.0f); }
    static Vector3 FromXMVector(DirectX::FXMVECTOR v)
    {
        DirectX::XMFLOAT3 f3;
        DirectX::XMStoreFloat3(&f3, v);
        return Vector3(f3.x, f3.y, f3.z);
    }
};

// Basic Quaternion structure
struct Quaternion
{
    float x, y, z, w;

    // Tolerance for floating point comparisons
    static constexpr float QUAT_EPSILON = 1e-4f; // Adjust tolerance as needed

    Quaternion(float _x = 0.0f, float _y = 0.0f, float _z = 0.0f, float _w = 1.0f) : x(_x), y(_y), z(_z), w(_w) {}

    Quaternion &operator=(const Quaternion &other) = default; // Keep default assignment

    bool operator!=(const Quaternion &other) const
    {
        // Compare component-wise with tolerance
        return (std::abs(x - other.x) > QUAT_EPSILON ||
                std::abs(y - other.y) > QUAT_EPSILON ||
                std::abs(z - other.z) > QUAT_EPSILON ||
                std::abs(w - other.w) > QUAT_EPSILON);
    };

    static Quaternion Identity() { return Quaternion(0.0f, 0.0f, 0.0f, 1.0f); }

    // DirectXMath conversion
    DirectX::XMVECTOR ToXMVector() const { return DirectX::XMVectorSet(x, y, z, w); }
    static Quaternion FromXMVector(DirectX::FXMVECTOR v)
    {
        DirectX::XMFLOAT4 f4;
        DirectX::XMStoreFloat4(&f4, v);
        return Quaternion(f4.x, f4.y, f4.z, f4.w);
    }

    // Rotate a vector by this quaternion
    Vector3 Rotate(const Vector3 &v) const
    {
        DirectX::XMVECTOR q = ToXMVector();
        DirectX::XMVECTOR vec = v.ToXMVector();
        DirectX::XMVECTOR rotatedVec = DirectX::XMVector3Rotate(vec, q);
        return Vector3::FromXMVector(rotatedVec);
    }

    // Static function to create a rotation looking along forward vector
    // Ensure forward is normalized, up doesn't need to be normalized but should not be collinear with forward.
    // Assumes Z-Up, Y-Forward convention by default matching CryEngine typical setup
    static Quaternion LookRotation(const Vector3 &forward, const Vector3 &up = Vector3(0, 0, 1))
    {
        DirectX::XMVECTOR forwardVec = forward.ToXMVector();
        DirectX::XMVECTOR upVec = up.ToXMVector();

        // Ensure the forward vector is normalized (required by LookAtRH/LH matrix funcs)
        forwardVec = DirectX::XMVector3Normalize(forwardVec);

        // Create the rotation matrix
        // Note: Use LookToRH for Right-Handed Coordinate System (DirectX default)
        // The "Eye" position is irrelevant for just getting rotation, set to origin.
        // The "Target" point is Eye + Forward direction.
        DirectX::XMMATRIX viewMatrix = DirectX::XMMatrixLookToRH(
            DirectX::XMVectorZero(), // Eye position at origin
            forwardVec,              // Look direction
            upVec                    // Up direction
        );

        // Inverse the view matrix to get the world orientation matrix
        DirectX::XMMATRIX worldMatrix = DirectX::XMMatrixInverse(nullptr, viewMatrix);

        // Convert the rotation part of the world matrix to a quaternion
        DirectX::XMVECTOR rotationQuat = DirectX::XMQuaternionRotationMatrix(worldMatrix);

        return Quaternion::FromXMVector(rotationQuat);
    }

    // Static function for spherical linear interpolation between quaternions
    static Quaternion Slerp(const Quaternion &q1, const Quaternion &q2, float t)
    {
        // Using DirectXMath for the actual implementation
        DirectX::XMVECTOR v1 = q1.ToXMVector();
        DirectX::XMVECTOR v2 = q2.ToXMVector();
        DirectX::XMVECTOR result = DirectX::XMQuaternionSlerp(v1, v2, t);
        return Quaternion::FromXMVector(result);
    }
};

/**
 * @brief Converts a Quaternion to a readable string format.
 * @param q The quaternion to convert.
 * @return Formatted string: "Q(X=0.0000 Y=0.0000 Z=0.0000 W=1.0000)"
 */
inline std::string QuatToString(const Quaternion &q)
{
    std::ostringstream oss;
    oss << std::fixed << std::setprecision(4)
        << "Q(X=" << q.x << " Y=" << q.y << " Z=" << q.z << " W=" << q.w << ")";
    return oss.str();
}

/**
 * @brief Converts a Vector3 to a readable string format.
 * @param v The vector to convert.
 * @return Formatted string: "V(0.0000, 0.0000, 0.0000)"
 */
inline std::string Vector3ToString(const Vector3 &v)
{
    std::ostringstream oss;
    oss << std::fixed << std::setprecision(4)
        << "V(" << v.x << ", " << v.y << ", " << v.z << ")";
    return oss.str();
}
