#define DMK_NO_NAMESPACE_ALIASES
#include "DetourModKit.hpp"

#include <gtest/gtest.h>

// Defining DMK_NO_NAMESPACE_ALIASES before the first DetourModKit include must suppress the optional global aliases
// `namespace dmk = DetourModKit;` / `namespace DMK = DetourModKit;` that defines.hpp otherwise publishes. The real
// proof is this COMPILE-TIME gate, not the runtime assertion below: a namespace alias and a variable of the same name
// in the SAME scope are a redeclaration (MSVC C2365), so declaring ordinary namespace-scope identifiers named `dmk` and
// `DMK` is well-formed ONLY because the macro suppressed both aliases. Remove the `#if
// !defined(DMK_NO_NAMESPACE_ALIASES)` guard in defines.hpp (aliases always emitted) and this translation unit stops
// compiling. The probes must sit at namespace scope to carry that weight: a block-scope local would merely SHADOW the
// alias and compile either way, exercising nothing. `const` at namespace scope has internal linkage, so the probe names
// never reach the shared test link.
const int dmk = 1;
const int DMK = 2;

// The primary DetourModKit namespace is always established regardless of the opt-out, so it still accepts an alias
// under any non-colliding name (this alias is ill-formed if the namespace does not exist).
namespace dmk_root = DetourModKit;

TEST(DefinesTest, NamespaceAliasOptOutLeavesConsumerNamesAvailable)
{
    // Consume the namespace-scope probes so the compile-time gate above is not reduced to an unused-variable
    // diagnostic; the arithmetic is incidental to the gate.
    EXPECT_EQ(dmk + DMK, 3);
}
