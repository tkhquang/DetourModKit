# Error Handling (`error.hpp`)

DetourModKit uses a two-tier error model, not a uniform one. This guide shows how to consume both tiers. The full `ErrorCode` list and the per-code `Error::detail` meanings live in [`error.hpp`](../../include/DetourModKit/error.hpp), which is the source of truth.

## The two tiers

**Result tier.** Fallible operations on the memory, scanner, resolver, anchor, manifest, and hook-core surfaces return `Result<T>`, the single library-wide alias for `std::expected<T, Error>`. An operation with no value returns `Result<void>`. On success the value is present. On failure the `Error` is present.

**Best-effort tier.** Deliberately best-effort and query surfaces return `bool`, `std::optional`, or `void` by design and never surface an `Error`:

- the RTTI query API (`type_name_of`, `vtable_is_type`, `region_has_rtti`),
- config load, reload, and bind (fail-soft to registered defaults, see `config.hpp`),
- `EventDispatcher` emit and subscribe.

A best-effort surface documents its non-`Result` return in its header. Do not assume uniformity across the two tiers. [Public API](../design/public-api.md) owns the exception-use rule.

## Consuming a `Result<T>`

A `Result<T>` is a `std::expected`, so a bool test tells success from failure, `*result` reads the value, and `result.error()` reads the `Error`:

```cpp
namespace mem = DetourModKit::memory;
using DetourModKit::Address;

if (const auto health = mem::read<std::int32_t>(Address{addr}))
{
    use(*health);                       // success: read the value
}
else
{
    const auto &err = health.error();   // failure: read the Error
    log().warning("read failed: {}", err.message());
}
```

## Propagating with `DMK_TRY` and `DMK_TRY_VOID`

When a function itself returns a `Result`, propagate a nested failure with the macro pair instead of a hand-unwrap. `DMK_TRY(var, expr)` binds the success value to `var` or returns the propagated `Error` from the enclosing function. `DMK_TRY_VOID(expr)` propagates a `Result<void>` (or any `Result` whose value is discarded) and binds nothing.

```cpp
DetourModKit::Result<void> load_signatures(const std::filesystem::path &path)
{
    DMK_TRY(loaded, manifest::load(path));   // binds `loaded`, or returns the Error
    DMK_TRY_VOID(apply(loaded));             // propagates on failure, binds nothing
    return {};                               // success
}
```

`DMK_TRY` expands to three statements, so keep it inside a braced block. It cannot be the sole controlled statement of a brace-less `if` or `for`. The enclosing function must return a `Result` or `std::expected` so the early return is well-formed. Each `DMK_TRY` names its temporary after `var`, so several uses in one scope never collide.

## The `Error` record

`Error` is a trivially copyable aggregate. Construction never allocates, so an `Error` can be built on the `noexcept` batch paths:

| Field | Meaning |
| --- | --- |
| `code` | The `ErrorCode`. Its high byte names the raising subsystem. |
| `where` | A static label for the raising site, `"scan"` or `"hook::inline"` for example. |
| `detail` | Primary raw context: an address, instruction pointer, or failing-hop index, per the code's documentation. |
| `extra` | Secondary raw context: a candidate index, slot, or hop count, per the code's documentation. |

`err.message()` composes one greppable diagnostic line, `[category] CodeName @ where (detail=0x..., extra=...)`. It is the only allocating member, so call it off a hot path.

## Branch on the code, recover the category

Branch on the `ErrorCode` enumerator, never on its raw integer value. Each category block is based at `category << 8`, so an inserted enumerator renumbers every later member of its block. `category(code)` recovers the `ErrorCategory` from the high byte with no lookup table, and `to_string(code)` and `to_string(category(code))` render the names.

```cpp
switch (category(err.code))
{
case DetourModKit::ErrorCategory::Memory:
    // a guarded read/write/protection failure
    break;
case DetourModKit::ErrorCategory::Scan:
    // an AOB cascade, RIP-relative, or string-xref miss
    break;
default:
    log().error("{}", err.message());
    break;
}
```

The categories are `General`, `Hook`, `Scan`, `Memory`, `Rtti`, `Manifest`, and `Lifecycle`.

## The `GetLastError()` detail slot

For a Win32 lifecycle failure, `ErrorCode::SystemCallFailed` carries the raw `GetLastError()` value in `Error::detail` (`[B-69]`). Read it to recover the OS reason:

```cpp
auto opened = dmk::Session::start(info);
if (!opened && opened.error().code == dmk::ErrorCode::SystemCallFailed)
{
    const DWORD win32 = static_cast<DWORD>(opened.error().detail);
    log().error("session start failed, GetLastError() = {}", win32);
}
```

Other codes document their own `detail` meaning at the enumerator. A guarded read fault carries the faulting address, a pointer-chain walk carries the failing-hop index, and a resolve carries a candidate ordinal. Read the `error.hpp` doc comment for the code you handle before you interpret `detail`.

## Related

- [`error.hpp`](../../include/DetourModKit/error.hpp): the `ErrorCode` list, `Error`, `Result<T>`, and the macro pair.
- [Public API](../design/public-api.md): the two-tier rule and the API-discipline labels.
- [The Minimal Core](minimal-core.md): a first mod that reads `Result` values end to end.
