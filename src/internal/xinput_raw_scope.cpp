#include "internal/xinput_raw_scope.hpp"

#include <windows.h>

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cwchar>
#include <limits>
#include <new>

namespace DetourModKit
{
    namespace detail
    {
        namespace
        {
            constexpr std::uint64_t DESCRIPTOR_MAGIC = 0x444D4B5849524157ULL;
            constexpr std::uint32_t DESCRIPTOR_VERSION = 3;
            constexpr DWORD DESCRIPTOR_WAIT_MS = 2000;
            constexpr std::uint64_t ADMISSION_CLOSED = std::uint64_t{1} << 63;
            constexpr std::uint64_t SCOPE_COUNT_MASK = ADMISSION_CLOSED - 1;
            constexpr std::uintptr_t CONSUME_BUTTONS_MASK = 0xFFFF;
            constexpr unsigned CONSUME_EXPECTED_SHIFT = 16;
            constexpr std::uintptr_t CONSUME_EXPECTED_MASK = CONSUME_BUTTONS_MASK << CONSUME_EXPECTED_SHIFT;
            constexpr std::uintptr_t CONSUME_VALID = std::uintptr_t{1} << 32;
            constexpr std::uintptr_t CONSUME_DEPTH_MASK = (std::uintptr_t{1} << 29) - 1;
            constexpr unsigned CONSUME_DEPTH_SHIFT = 33;
            constexpr unsigned CONSUME_USER_SHIFT = 62;
            constexpr DWORD CONSUME_USER_MAX = 3;
            static_assert(sizeof(std::uintptr_t) == 8);

            struct RawDescriptor
            {
                std::uint64_t magic;
                std::uint32_t version;
                std::uint32_t bytes;
                std::uint64_t canonical_address;
                std::uint64_t mutex_value;
                std::uint64_t mapping_value;
                std::uint64_t alias_probe;
                std::uint32_t tls_index;
                std::uint32_t owners;
                std::uint32_t poisoned;
                std::uint32_t reserved;
                std::uint32_t consume_identity_index;
                std::uint32_t consume_metadata_index;
                volatile LONG consume_poison;
                std::uint32_t consume_reserved;
            };
            static_assert(sizeof(RawDescriptor) == 80);
            static_assert(offsetof(RawDescriptor, tls_index) == 48);

            SRWLOCK s_owner_lock = SRWLOCK_INIT;
            RawDescriptor *s_descriptor{nullptr};
            std::uint32_t s_local_owners{0};
            bool s_retained_registration{false};
            std::atomic<DWORD> s_cached_index{TLS_OUT_OF_INDEXES};
            std::atomic<DWORD> s_cached_identity_index{TLS_OUT_OF_INDEXES};
            std::atomic<DWORD> s_cached_metadata_index{TLS_OUT_OF_INDEXES};
            std::atomic<std::uint64_t> s_scope_state{ADMISSION_CLOSED};

            class LastErrorGuard
            {
            public:
                LastErrorGuard() noexcept : m_error(::GetLastError()) {}
                ~LastErrorGuard() noexcept { ::SetLastError(m_error); }
                LastErrorGuard(const LastErrorGuard &) = delete;
                LastErrorGuard &operator=(const LastErrorGuard &) = delete;
                LastErrorGuard(LastErrorGuard &&) = delete;
                LastErrorGuard &operator=(LastErrorGuard &&) = delete;

            private:
                DWORD m_error;
            };

#if defined(DMK_ENABLE_TEST_SEAMS)
            constexpr std::size_t FAILURE_THREADS = 8;
            std::array<std::atomic<std::uint64_t>, FAILURE_THREADS> s_failures{};

            [[nodiscard]] bool failure_for_thread(XInputRawScopeFailure failure) noexcept
            {
                const std::uint64_t expected =
                    (static_cast<std::uint64_t>(::GetCurrentThreadId()) << 8) | static_cast<std::uint8_t>(failure);
                for (const auto &slot : s_failures)
                {
                    if (slot.load(std::memory_order_acquire) == expected)
                    {
                        return true;
                    }
                }
                return false;
            }
#endif

            [[nodiscard]] HANDLE descriptor_mutex(const RawDescriptor &descriptor) noexcept
            {
                return reinterpret_cast<HANDLE>(static_cast<std::uintptr_t>(descriptor.mutex_value));
            }

            [[nodiscard]] bool descriptor_header_valid(const RawDescriptor &descriptor) noexcept
            {
#if defined(DMK_ENABLE_TEST_SEAMS)
                const std::uint32_t expected_version = failure_for_thread(XInputRawScopeFailure::DescriptorVersion)
                                                           ? DESCRIPTOR_VERSION + 1
                                                           : DESCRIPTOR_VERSION;
#else
                constexpr std::uint32_t expected_version = DESCRIPTOR_VERSION;
#endif
                return descriptor.magic == DESCRIPTOR_MAGIC && descriptor.version == expected_version &&
                       descriptor.bytes == sizeof(RawDescriptor) && descriptor.reserved == 0 &&
                       descriptor.consume_reserved == 0;
            }

            [[nodiscard]] bool canonical_alias(RawDescriptor *view, RawDescriptor *canonical) noexcept
            {
                MEMORY_BASIC_INFORMATION region{};
                if (canonical == nullptr || ::VirtualQuery(canonical, &region, sizeof(region)) != sizeof(region) ||
                    region.BaseAddress != canonical || region.State != MEM_COMMIT || region.Type != MEM_MAPPED ||
                    region.Protect != PAGE_READWRITE || region.RegionSize < sizeof(RawDescriptor))
                {
                    return false;
                }
                volatile std::uint64_t &written = view->alias_probe;
                const volatile std::uint64_t &observed = canonical->alias_probe;
                const std::uint64_t original = written;
                const std::uint64_t probe = original ^ 1;
                written = probe;
                const bool same = observed == probe;
                written = original;
                return same && observed == original;
            }

            [[nodiscard]] RawDescriptor *connect_descriptor(DWORD &error) noexcept
            {
#if defined(DMK_ENABLE_TEST_SEAMS)
                if (failure_for_thread(XInputRawScopeFailure::DescriptorInit))
                {
                    error = ERROR_NOT_ENOUGH_MEMORY;
                    return nullptr;
                }
#endif
                FILETIME created{}, exited{}, kernel{}, user{};
                if (!::GetProcessTimes(::GetCurrentProcess(), &created, &exited, &kernel, &user))
                {
                    error = ::GetLastError();
                    return nullptr;
                }
                wchar_t mutex_name[128]{};
                wchar_t mapping_name[128]{};
                const int mutex_length = std::swprintf(
                    mutex_name,
                    std::size(mutex_name),
                    L"Local\\DMK.XInputRaw.%lu.%08lx%08lx.Lock",
                    ::GetCurrentProcessId(),
                    created.dwHighDateTime,
                    created.dwLowDateTime
                );
                const int mapping_length = std::swprintf(
                    mapping_name,
                    std::size(mapping_name),
                    L"Local\\DMK.XInputRaw.%lu.%08lx%08lx.Data",
                    ::GetCurrentProcessId(),
                    created.dwHighDateTime,
                    created.dwLowDateTime
                );
                if (mutex_length < 0 || mapping_length < 0)
                {
                    error = ERROR_INSUFFICIENT_BUFFER;
                    return nullptr;
                }
                const HANDLE mutex = ::CreateMutexW(nullptr, FALSE, mutex_name);
                if (mutex == nullptr)
                {
                    error = ::GetLastError();
                    return nullptr;
                }
                const DWORD acquired = ::WaitForSingleObject(mutex, DESCRIPTOR_WAIT_MS);
                if (acquired != WAIT_OBJECT_0 && acquired != WAIT_ABANDONED)
                {
                    error = acquired == WAIT_FAILED ? ::GetLastError() : ERROR_TIMEOUT;
                    ::CloseHandle(mutex);
                    return nullptr;
                }
                const HANDLE mapping = ::CreateFileMappingW(
                    INVALID_HANDLE_VALUE,
                    nullptr,
                    PAGE_READWRITE,
                    0,
                    static_cast<DWORD>(sizeof(RawDescriptor)),
                    mapping_name
                );
                const DWORD mapping_error = ::GetLastError();
                const bool existing = mapping != nullptr && mapping_error == ERROR_ALREADY_EXISTS;
                auto *const view =
                    mapping == nullptr
                        ? nullptr
                        : static_cast<RawDescriptor *>(
                              ::MapViewOfFile(mapping, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, sizeof(RawDescriptor))
                          );
                error = mapping == nullptr ? mapping_error : view == nullptr ? ::GetLastError() : ERROR_INVALID_DATA;
                RawDescriptor *result = nullptr;
                bool process_owner = false;
                if (view != nullptr)
                {
                    if (!existing && acquired == WAIT_OBJECT_0)
                    {
                        ::new (static_cast<void *>(view)) RawDescriptor{
                            .magic = 0,
                            .version = DESCRIPTOR_VERSION,
                            .bytes = sizeof(RawDescriptor),
                            .canonical_address = reinterpret_cast<std::uintptr_t>(view),
                            .mutex_value = reinterpret_cast<std::uintptr_t>(mutex),
                            .mapping_value = reinterpret_cast<std::uintptr_t>(mapping),
                            .alias_probe = 0,
                            .tls_index = TLS_OUT_OF_INDEXES,
                            .owners = 0,
                            .poisoned = 0,
                            .reserved = 0,
                            .consume_identity_index = TLS_OUT_OF_INDEXES,
                            .consume_metadata_index = TLS_OUT_OF_INDEXES,
                            .consume_poison = 0,
                            .consume_reserved = 0,
                        };
                        view->magic = DESCRIPTOR_MAGIC;
                        result = view;
                        process_owner = true;
                    }
                    else if (descriptor_header_valid(*view))
                    {
                        auto *const canonical =
                            reinterpret_cast<RawDescriptor *>(static_cast<std::uintptr_t>(view->canonical_address));
                        if (canonical_alias(view, canonical) && descriptor_header_valid(*canonical))
                        {
                            result = canonical;
                            if (acquired == WAIT_ABANDONED)
                            {
                                result->poisoned = 1;
                            }
                        }
                    }
                    if (!process_owner)
                    {
                        ::UnmapViewOfFile(view);
                    }
                }
                if (mapping != nullptr && !process_owner)
                {
                    ::CloseHandle(mapping);
                }
                ::ReleaseMutex(mutex);
                if (!process_owner)
                {
                    ::CloseHandle(mutex);
                }
                return result;
            }

            [[nodiscard]] bool lock_descriptor(RawDescriptor &descriptor, DWORD &error) noexcept
            {
                const DWORD acquired = ::WaitForSingleObject(descriptor_mutex(descriptor), DESCRIPTOR_WAIT_MS);
                if (acquired == WAIT_ABANDONED)
                {
                    descriptor.poisoned = 1;
                    ::ReleaseMutex(descriptor_mutex(descriptor));
                    error = ERROR_INVALID_DATA;
                    return false;
                }
                if (acquired != WAIT_OBJECT_0)
                {
                    error = acquired == WAIT_FAILED ? ::GetLastError() : ERROR_TIMEOUT;
                    return false;
                }
                const bool indices_empty = descriptor.tls_index == TLS_OUT_OF_INDEXES &&
                                           descriptor.consume_identity_index == TLS_OUT_OF_INDEXES &&
                                           descriptor.consume_metadata_index == TLS_OUT_OF_INDEXES;
                const bool indices_live = descriptor.tls_index != TLS_OUT_OF_INDEXES &&
                                          descriptor.consume_identity_index != TLS_OUT_OF_INDEXES &&
                                          descriptor.consume_metadata_index != TLS_OUT_OF_INDEXES &&
                                          descriptor.tls_index != descriptor.consume_identity_index &&
                                          descriptor.tls_index != descriptor.consume_metadata_index &&
                                          descriptor.consume_identity_index != descriptor.consume_metadata_index;
                if (!descriptor_header_valid(descriptor) || descriptor.poisoned != 0 ||
                    (descriptor.owners == 0 ? !indices_empty : !indices_live))
                {
                    error = ERROR_INVALID_DATA;
                    ::ReleaseMutex(descriptor_mutex(descriptor));
                    return false;
                }
                return true;
            }

            [[nodiscard]] bool store_depth(DWORD index, std::uintptr_t depth, [[maybe_unused]] bool entry) noexcept
            {
#if defined(DMK_ENABLE_TEST_SEAMS)
                if (failure_for_thread(entry ? XInputRawScopeFailure::EntryStore : XInputRawScopeFailure::Restore))
                {
                    return false;
                }
#endif
                return ::TlsSetValue(index, reinterpret_cast<void *>(depth)) != FALSE;
            }

            enum class ConsumeStore : std::uint8_t
            {
                EntryIdentity,
                EntryMetadata,
                Rollback,
                Original,
                RestoreIdentity,
                RestoreMetadata,
            };

            [[nodiscard]] bool
            store_consume(DWORD index, std::uintptr_t value, [[maybe_unused]] ConsumeStore phase) noexcept
            {
#if defined(DMK_ENABLE_TEST_SEAMS)
                const XInputRawScopeFailure fault = [&]() noexcept -> XInputRawScopeFailure
                {
                    switch (phase)
                    {
                    case ConsumeStore::EntryIdentity:
                        return XInputRawScopeFailure::ConsumeEntryIdentity;
                    case ConsumeStore::EntryMetadata:
                        return XInputRawScopeFailure::ConsumeEntryMetadata;
                    case ConsumeStore::Rollback:
                        return XInputRawScopeFailure::ConsumeEntryRollback;
                    case ConsumeStore::Original:
                        return XInputRawScopeFailure::ConsumeOriginalStore;
                    case ConsumeStore::RestoreIdentity:
                        return XInputRawScopeFailure::ConsumeRestoreIdentity;
                    case ConsumeStore::RestoreMetadata:
                        return XInputRawScopeFailure::ConsumeRestoreMetadata;
                    }
                    return XInputRawScopeFailure::None;
                }();
                if (failure_for_thread(fault) || (phase == ConsumeStore::EntryMetadata &&
                                                  failure_for_thread(XInputRawScopeFailure::ConsumeEntryRollback)))
                {
                    return false;
                }
#endif
                return ::TlsSetValue(index, reinterpret_cast<void *>(value)) != FALSE;
            }

            void poison_consume_context() noexcept
            {
                ::InterlockedExchange(&s_descriptor->consume_poison, 1);
            }

            [[nodiscard]] std::uint32_t consume_depth(std::uintptr_t metadata) noexcept
            {
                return static_cast<std::uint32_t>((metadata >> CONSUME_DEPTH_SHIFT) & CONSUME_DEPTH_MASK);
            }

            [[nodiscard]] DWORD consume_user(std::uintptr_t metadata) noexcept
            {
                return static_cast<DWORD>(metadata >> CONSUME_USER_SHIFT);
            }

            [[nodiscard]] bool read_consume(DWORD index, std::uintptr_t &value) noexcept
            {
                value = reinterpret_cast<std::uintptr_t>(::TlsGetValue(index));
                return ::GetLastError() == ERROR_SUCCESS;
            }

            [[nodiscard]] bool reserve_scope_indices(RawDescriptor &descriptor, DWORD &error) noexcept
            {
                std::array<DWORD, 3> indices{TLS_OUT_OF_INDEXES, TLS_OUT_OF_INDEXES, TLS_OUT_OF_INDEXES};
                for (std::size_t i = 0; i < indices.size(); ++i)
                {
#if defined(DMK_ENABLE_TEST_SEAMS)
                    const XInputRawScopeFailure fault = i == 0   ? XInputRawScopeFailure::Reservation
                                                        : i == 1 ? XInputRawScopeFailure::IdentityReservation
                                                                 : XInputRawScopeFailure::MetadataReservation;
                    if (failure_for_thread(fault))
                    {
                        error = ERROR_NOT_ENOUGH_MEMORY;
                    }
                    else
#endif
                    {
                        indices[i] = ::TlsAlloc();
                        if (indices[i] == TLS_OUT_OF_INDEXES)
                        {
                            error = ::GetLastError();
                        }
                    }
                    if (indices[i] == TLS_OUT_OF_INDEXES)
                    {
                        for (const DWORD allocated : indices)
                        {
                            if (allocated != TLS_OUT_OF_INDEXES && !::TlsFree(allocated))
                            {
                                descriptor.poisoned = 1;
                            }
                        }
                        return false;
                    }
                }
                descriptor.tls_index = indices[0];
                descriptor.consume_identity_index = indices[1];
                descriptor.consume_metadata_index = indices[2];
                ::InterlockedExchange(&descriptor.consume_poison, 0);
                return true;
            }

            [[nodiscard]] bool admit_scope() noexcept
            {
                std::uint64_t state = s_scope_state.load(std::memory_order_seq_cst);
                while ((state & ADMISSION_CLOSED) == 0 && (state & SCOPE_COUNT_MASK) != SCOPE_COUNT_MASK)
                {
                    if (s_scope_state.compare_exchange_weak(
                            state,
                            state + 1,
                            std::memory_order_seq_cst,
                            std::memory_order_seq_cst
                        ))
                    {
                        return true;
                    }
                }
                return false;
            }
        } // namespace

        bool acquire_xinput_raw_scope_owner(DWORD *error) noexcept
        {
            const LastErrorGuard preserve_error;
            DWORD failure = ERROR_SUCCESS;
            ::AcquireSRWLockExclusive(&s_owner_lock);
            if (s_local_owners != 0 || s_retained_registration)
            {
                if (s_local_owners == std::numeric_limits<std::uint32_t>::max())
                {
                    failure = ERROR_TOO_MANY_OPEN_FILES;
                }
                else
                {
                    ++s_local_owners;
                    s_retained_registration = false;
                    s_scope_state.fetch_and(SCOPE_COUNT_MASK, std::memory_order_seq_cst);
                    ::ReleaseSRWLockExclusive(&s_owner_lock);
                    if (error != nullptr)
                    {
                        *error = ERROR_SUCCESS;
                    }
                    return true;
                }
            }
            else
            {
#if defined(DMK_ENABLE_TEST_SEAMS)
                if (failure_for_thread(XInputRawScopeFailure::DescriptorInit))
                {
                    failure = ERROR_NOT_ENOUGH_MEMORY;
                }
                else
#endif
                {
                    if (s_descriptor == nullptr)
                    {
                        s_descriptor = connect_descriptor(failure);
                    }
                    if (s_descriptor != nullptr && lock_descriptor(*s_descriptor, failure))
                    {
                        if (s_descriptor->owners == std::numeric_limits<std::uint32_t>::max())
                        {
                            failure = ERROR_TOO_MANY_OPEN_FILES;
                        }
                        else
                        {
                            if (s_descriptor->tls_index == TLS_OUT_OF_INDEXES)
                            {
                                (void)reserve_scope_indices(*s_descriptor, failure);
                            }
                            if (s_descriptor->tls_index != TLS_OUT_OF_INDEXES)
                            {
                                ++s_descriptor->owners;
                                s_local_owners = 1;
                                s_cached_identity_index.store(
                                    s_descriptor->consume_identity_index,
                                    std::memory_order_relaxed
                                );
                                s_cached_metadata_index.store(
                                    s_descriptor->consume_metadata_index,
                                    std::memory_order_relaxed
                                );
                                s_cached_index.store(s_descriptor->tls_index, std::memory_order_release);
                                s_scope_state.store(0, std::memory_order_seq_cst);
                                ::ReleaseMutex(descriptor_mutex(*s_descriptor));
                                ::ReleaseSRWLockExclusive(&s_owner_lock);
                                if (error != nullptr)
                                {
                                    *error = ERROR_SUCCESS;
                                }
                                return true;
                            }
                        }
                        ::ReleaseMutex(descriptor_mutex(*s_descriptor));
                    }
                }
            }
            ::ReleaseSRWLockExclusive(&s_owner_lock);
            if (error != nullptr)
            {
                *error = failure;
            }
            return false;
        }

        void release_xinput_raw_scope_owner() noexcept
        {
            const LastErrorGuard preserve_error;
            ::AcquireSRWLockExclusive(&s_owner_lock);
            if (s_local_owners == 0)
            {
                ::ReleaseSRWLockExclusive(&s_owner_lock);
                return;
            }
            if (--s_local_owners != 0)
            {
                ::ReleaseSRWLockExclusive(&s_owner_lock);
                return;
            }
            const std::uint64_t scopes = s_scope_state.fetch_or(ADMISSION_CLOSED, std::memory_order_seq_cst);
            DWORD error = ERROR_SUCCESS;
            if ((scopes & SCOPE_COUNT_MASK) != 0 || s_descriptor == nullptr || !lock_descriptor(*s_descriptor, error))
            {
                s_retained_registration = true;
                ::ReleaseSRWLockExclusive(&s_owner_lock);
                return;
            }
            s_cached_index.store(TLS_OUT_OF_INDEXES, std::memory_order_release);
            s_cached_identity_index.store(TLS_OUT_OF_INDEXES, std::memory_order_relaxed);
            s_cached_metadata_index.store(TLS_OUT_OF_INDEXES, std::memory_order_relaxed);
            if (--s_descriptor->owners == 0)
            {
                const std::array<DWORD, 3> indices{
                    s_descriptor->tls_index,
                    s_descriptor->consume_identity_index,
                    s_descriptor->consume_metadata_index,
                };
                s_descriptor->tls_index = TLS_OUT_OF_INDEXES;
                s_descriptor->consume_identity_index = TLS_OUT_OF_INDEXES;
                s_descriptor->consume_metadata_index = TLS_OUT_OF_INDEXES;
                for (const DWORD index : indices)
                {
                    if (!::TlsFree(index))
                    {
                        s_descriptor->poisoned = 1;
                    }
                }
            }
            ::ReleaseMutex(descriptor_mutex(*s_descriptor));
            ::ReleaseSRWLockExclusive(&s_owner_lock);
        }

        std::uint64_t active_xinput_raw_scopes() noexcept
        {
            return s_scope_state.load(std::memory_order_seq_cst) & SCOPE_COUNT_MASK;
        }

        bool xinput_consume_context_healthy() noexcept
        {
            if (s_cached_index.load(std::memory_order_acquire) == TLS_OUT_OF_INDEXES)
            {
                return false;
            }
            return ::InterlockedCompareExchange(&s_descriptor->consume_poison, 0, 0) == 0;
        }

        bool is_xinput_raw_call() noexcept
        {
            const DWORD index = s_cached_index.load(std::memory_order_acquire);
            if (index == TLS_OUT_OF_INDEXES)
            {
                return false;
            }
            const LastErrorGuard preserve_error;
            return reinterpret_cast<std::uintptr_t>(::TlsGetValue(index)) != 0;
        }

        XInputRawScope::XInputRawScope() noexcept
        {
            const LastErrorGuard preserve_error;
            if (!admit_scope())
            {
                return;
            }
            m_index = s_cached_index.load(std::memory_order_acquire);
            if (m_index == TLS_OUT_OF_INDEXES)
            {
                s_scope_state.fetch_sub(1, std::memory_order_release);
                return;
            }
            m_previous_depth = reinterpret_cast<std::uintptr_t>(::TlsGetValue(m_index));
            if (::GetLastError() != ERROR_SUCCESS || m_previous_depth == std::numeric_limits<std::uintptr_t>::max() ||
                !store_depth(m_index, m_previous_depth + 1, true))
            {
                s_scope_state.fetch_sub(1, std::memory_order_release);
                return;
            }
            m_admitted = true;
            m_active = true;
        }

        XInputRawScope::~XInputRawScope() noexcept
        {
            (void)finish();
        }

        bool XInputRawScope::finish() noexcept
        {
            if (m_active)
            {
                const LastErrorGuard preserve_error;
                m_restored = store_depth(m_index, m_previous_depth, false);
                m_active = false;
                s_scope_state.fetch_sub(1, std::memory_order_release);
            }
            return m_restored;
        }

        XInputConsumeScope::XInputConsumeScope(DWORD user, const void *state_address) noexcept
            : m_user(user), m_identity(reinterpret_cast<std::uintptr_t>(state_address))
        {
            const LastErrorGuard preserve_error;
            if (user > CONSUME_USER_MAX || m_identity == 0 || !admit_scope())
            {
                return;
            }
            if (!xinput_consume_context_healthy())
            {
                m_restored = false;
                s_scope_state.fetch_sub(1, std::memory_order_release);
                return;
            }
            m_identity_index = s_cached_identity_index.load(std::memory_order_relaxed);
            m_metadata_index = s_cached_metadata_index.load(std::memory_order_relaxed);
            if (!read_consume(m_identity_index, m_previous_identity) ||
                !read_consume(m_metadata_index, m_previous_metadata))
            {
                poison_consume_context();
                m_restored = false;
                s_scope_state.fetch_sub(1, std::memory_order_release);
                return;
            }
            const std::uint32_t previous_depth = consume_depth(m_previous_metadata);
            m_joined =
                previous_depth != 0 && m_identity == m_previous_identity && user == consume_user(m_previous_metadata);
            if (m_joined && previous_depth == CONSUME_DEPTH_MASK)
            {
                s_scope_state.fetch_sub(1, std::memory_order_release);
                return;
            }
            m_depth = m_joined ? previous_depth + 1 : 1;
            const std::uintptr_t metadata = m_joined ? m_previous_metadata + (std::uintptr_t{1} << CONSUME_DEPTH_SHIFT)
                                                     : (static_cast<std::uintptr_t>(user) << CONSUME_USER_SHIFT) |
                                                           (std::uintptr_t{1} << CONSUME_DEPTH_SHIFT);
            const bool identity_stored =
                m_joined || store_consume(m_identity_index, m_identity, ConsumeStore::EntryIdentity);
            const bool metadata_stored =
                identity_stored && store_consume(m_metadata_index, metadata, ConsumeStore::EntryMetadata);
            if (!metadata_stored)
            {
                poison_consume_context();
                const bool identity_restored =
                    store_consume(m_identity_index, m_previous_identity, ConsumeStore::Rollback);
                const bool metadata_restored =
                    store_consume(m_metadata_index, m_previous_metadata, ConsumeStore::Rollback);
                m_restored = identity_restored && metadata_restored && xinput_consume_context_healthy();
                s_scope_state.fetch_sub(1, std::memory_order_release);
                return;
            }
            m_admitted = true;
            m_active = true;
        }

        XInputConsumeScope::~XInputConsumeScope() noexcept
        {
            (void)finish();
        }

        bool XInputConsumeScope::original_buttons(WORD observed, WORD &original) noexcept
        {
            const LastErrorGuard preserve_error;
            if (!m_active || !xinput_consume_context_healthy())
            {
                return false;
            }
            std::uintptr_t identity = 0;
            std::uintptr_t metadata = 0;
            if (!read_consume(m_identity_index, identity) || !read_consume(m_metadata_index, metadata) ||
                identity != m_identity || consume_user(metadata) != m_user || consume_depth(metadata) != m_depth)
            {
                poison_consume_context();
                return false;
            }
            const auto expected = static_cast<WORD>((metadata & CONSUME_EXPECTED_MASK) >> CONSUME_EXPECTED_SHIFT);
            if ((metadata & CONSUME_VALID) == 0 || observed != expected)
            {
                metadata = (metadata & ~(CONSUME_BUTTONS_MASK | CONSUME_EXPECTED_MASK)) | observed |
                           (static_cast<std::uintptr_t>(observed) << CONSUME_EXPECTED_SHIFT) | CONSUME_VALID;
                if (!store_consume(m_metadata_index, metadata, ConsumeStore::Original))
                {
                    poison_consume_context();
                    return false;
                }
            }
            if (!xinput_consume_context_healthy())
            {
                return false;
            }
            original = static_cast<WORD>(metadata & CONSUME_BUTTONS_MASK);
            return true;
        }

        bool XInputConsumeScope::finish() noexcept
        {
            return finish_context(false, 0);
        }

        bool XInputConsumeScope::finish(WORD returned_buttons) noexcept
        {
            return finish_context(true, returned_buttons);
        }

        bool XInputConsumeScope::finish_context(bool publish_return, WORD returned_buttons) noexcept
        {
            if (m_active)
            {
                const LastErrorGuard preserve_error;
                bool identity_restored = true;
                bool metadata_restored = false;
                if (m_joined)
                {
                    std::uintptr_t identity = 0;
                    std::uintptr_t metadata = 0;
                    if (read_consume(m_identity_index, identity) && read_consume(m_metadata_index, metadata) &&
                        identity == m_identity && consume_user(metadata) == m_user &&
                        consume_depth(metadata) == m_depth)
                    {
                        if (publish_return)
                        {
                            metadata = (metadata & ~CONSUME_EXPECTED_MASK) |
                                       (static_cast<std::uintptr_t>(returned_buttons) << CONSUME_EXPECTED_SHIFT);
                        }
                        metadata_restored = store_consume(
                            m_metadata_index,
                            metadata - (std::uintptr_t{1} << CONSUME_DEPTH_SHIFT),
                            ConsumeStore::RestoreMetadata
                        );
                    }
                }
                else
                {
                    identity_restored =
                        store_consume(m_identity_index, m_previous_identity, ConsumeStore::RestoreIdentity);
                    if (!identity_restored)
                    {
                        poison_consume_context();
                    }
                    metadata_restored =
                        store_consume(m_metadata_index, m_previous_metadata, ConsumeStore::RestoreMetadata);
                }
                if (!identity_restored || !metadata_restored)
                {
                    poison_consume_context();
                }
                m_restored = identity_restored && metadata_restored && xinput_consume_context_healthy();
                m_active = false;
                s_scope_state.fetch_sub(1, std::memory_order_release);
            }
            return m_restored;
        }

#if defined(DMK_ENABLE_TEST_SEAMS)
        bool set_xinput_raw_scope_failure_for_test(XInputRawScopeFailure failure) noexcept
        {
            const std::uint64_t thread = ::GetCurrentThreadId();
            for (auto &slot : s_failures)
            {
                std::uint64_t current = slot.load(std::memory_order_acquire);
                if ((current >> 8) == thread &&
                    slot.compare_exchange_strong(
                        current,
                        failure == XInputRawScopeFailure::None ? 0 : (thread << 8) | static_cast<std::uint8_t>(failure),
                        std::memory_order_acq_rel,
                        std::memory_order_acquire
                    ))
                {
                    return true;
                }
            }
            if (failure == XInputRawScopeFailure::None)
            {
                return true;
            }
            for (auto &slot : s_failures)
            {
                std::uint64_t empty = 0;
                if (slot.compare_exchange_strong(
                        empty,
                        (thread << 8) | static_cast<std::uint8_t>(failure),
                        std::memory_order_acq_rel,
                        std::memory_order_acquire
                    ))
                {
                    return true;
                }
            }
            return false;
        }

        DWORD xinput_raw_scope_index_for_test() noexcept
        {
            return s_cached_index.load(std::memory_order_acquire);
        }

        std::uint32_t xinput_raw_scope_owners_for_test() noexcept
        {
            const LastErrorGuard preserve_error;
            ::AcquireSRWLockExclusive(&s_owner_lock);
            DWORD error = ERROR_SUCCESS;
            std::uint32_t owners = 0;
            if (s_descriptor != nullptr && lock_descriptor(*s_descriptor, error))
            {
                owners = s_descriptor->owners;
                ::ReleaseMutex(descriptor_mutex(*s_descriptor));
            }
            ::ReleaseSRWLockExclusive(&s_owner_lock);
            return owners;
        }

        std::uintptr_t xinput_raw_scope_depth_for_test() noexcept
        {
            const DWORD index = s_cached_index.load(std::memory_order_acquire);
            if (index == TLS_OUT_OF_INDEXES)
            {
                return 0;
            }
            const LastErrorGuard preserve_error;
            return reinterpret_cast<std::uintptr_t>(::TlsGetValue(index));
        }

        std::uintptr_t xinput_raw_scope_descriptor_for_test() noexcept
        {
            ::AcquireSRWLockExclusive(&s_owner_lock);
            const auto address = reinterpret_cast<std::uintptr_t>(s_descriptor);
            ::ReleaseSRWLockExclusive(&s_owner_lock);
            return address;
        }

        DWORD xinput_consume_identity_index_for_test() noexcept
        {
            return s_cached_identity_index.load(std::memory_order_relaxed);
        }

        DWORD xinput_consume_metadata_index_for_test() noexcept
        {
            return s_cached_metadata_index.load(std::memory_order_relaxed);
        }
#endif
    } // namespace detail
} // namespace DetourModKit
