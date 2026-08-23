#include "internal/win_file_stream.hpp"

#include <windows.h>
#include <algorithm>
#include <array>
#include <cassert>
#include <climits>
#include <cstddef>
#include <cstring>
#include <new>
#include <string>

namespace DetourModKit::detail
{
#if defined(DMK_ENABLE_TEST_SEAMS)
    void (*g_read_regular_file_after_size_probe)(const std::wstring &path) = nullptr;
    int (*g_win_file_write_override)(void *handle, const void *data, unsigned long size, unsigned long *written) =
        nullptr;
    int (*g_win_file_close_override)(void *handle) = nullptr;
#endif

    namespace
    {
        BOOL stream_write_file(void *handle, const void *data, DWORD size, DWORD *written) noexcept
        {
#if defined(DMK_ENABLE_TEST_SEAMS)
            if (g_win_file_write_override != nullptr)
            {
                return g_win_file_write_override(handle, data, size, written);
            }
#endif
            return WriteFile(static_cast<HANDLE>(handle), data, size, written, nullptr);
        }

        BOOL stream_close_handle(void *handle) noexcept
        {
#if defined(DMK_ENABLE_TEST_SEAMS)
            if (g_win_file_close_override != nullptr)
            {
                return g_win_file_close_override(handle);
            }
#endif
            return CloseHandle(static_cast<HANDLE>(handle));
        }
    } // namespace

    WinFileStreamBuf::WinFileStreamBuf() noexcept : m_handle(INVALID_HANDLE_VALUE), m_buffer{}
    {
        // A closed buffer has no writable put area. This routes even a one-byte write through overflow(), where the
        // closed-handle check reports failure instead of caching a byte that a later open discards.
        setp(nullptr, nullptr);
    }

    WinFileStreamBuf::~WinFileStreamBuf() noexcept
    {
        // Best-effort force path: one drain attempt, then close the handle unconditionally. A destructor has no
        // return channel, so unlike close() it cannot retain a handle for a retry.
        if (is_open())
        {
            (void)flush_buffer();
            (void)stream_close_handle(m_handle);
            m_handle = INVALID_HANDLE_VALUE;
            setp(nullptr, nullptr);
        }
    }

    bool WinFileStreamBuf::open(const std::wstring &path, std::ios_base::openmode mode)
    {
        // A current file that cannot be closed cleanly is retained, buffered bytes included, and the reopen is
        // refused: discarding the handle here would silently drop the undrained tail.
        if (is_open() && !close())
        {
            return false;
        }

        const bool append = (mode & std::ios_base::app) != 0;

        // Append mode requests FILE_APPEND_DATA so the OS positions every WriteFile at the current end of file
        // atomically; concurrent appenders then cannot interleave or overwrite each other ([B-33],
        // AppendMode_ConcurrentAppendersPreserveEveryByte). Truncating ("out") mode keeps GENERIC_WRITE +
        // CREATE_ALWAYS.
        const DWORD access = append ? FILE_APPEND_DATA : GENERIC_WRITE;
        const DWORD creation = append ? OPEN_ALWAYS : CREATE_ALWAYS;

        m_handle = CreateFileW(
            path.c_str(),
            access,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr,
            creation,
            FILE_ATTRIBUTE_NORMAL,
            nullptr
        );

        if (m_handle == INVALID_HANDLE_VALUE)
        {
            return false;
        }

        setp(m_buffer.data(), m_buffer.data() + BUFFER_SIZE);
        return true;
    }

    bool WinFileStreamBuf::open(const std::string &path, std::ios_base::openmode mode)
    {
        // Convert narrow string to wide. Try UTF-8 first, fall back to ACP.
        int wide_len = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, path.c_str(), -1, nullptr, 0);
        UINT code_page = CP_UTF8;
        if (wide_len <= 0)
        {
            code_page = CP_ACP;
            wide_len = MultiByteToWideChar(CP_ACP, 0, path.c_str(), -1, nullptr, 0);
        }
        if (wide_len <= 0)
        {
            return false;
        }

        std::wstring wide_path(static_cast<size_t>(wide_len - 1), L'\0');
        MultiByteToWideChar(code_page, 0, path.c_str(), -1, wide_path.data(), wide_len);

        return open(wide_path, mode);
    }

    bool WinFileStreamBuf::is_open() const noexcept
    {
        return m_handle != INVALID_HANDLE_VALUE;
    }

    bool WinFileStreamBuf::close() noexcept
    {
        if (!is_open())
        {
            return true;
        }

        // A failed drain keeps the handle open and the unwritten tail buffered, so nothing is lost and a retry can
        // finish the job. A failed CloseHandle likewise retains the handle rather than nulling it: only the
        // destructor discards a handle it could not close.
        if (!flush_buffer())
        {
            return false;
        }
        if (stream_close_handle(m_handle) == 0)
        {
            return false;
        }
        m_handle = INVALID_HANDLE_VALUE;
        setp(nullptr, nullptr);
        return true;
    }

    WinFileStreamBuf::int_type WinFileStreamBuf::overflow(int_type ch)
    {
        if (!is_open())
        {
            return traits_type::eof();
        }

        if (!flush_buffer())
        {
            return traits_type::eof();
        }

        if (!traits_type::eq_int_type(ch, traits_type::eof()))
        {
            *pptr() = traits_type::to_char_type(ch);
            pbump(1);
        }

        return traits_type::not_eof(ch);
    }

    int WinFileStreamBuf::sync()
    {
        if (!is_open())
        {
            return -1;
        }

        return flush_buffer() ? 0 : -1;
    }

    std::streamsize WinFileStreamBuf::xsputn(const char *s, std::streamsize count)
    {
        if (!is_open() || count <= 0)
        {
            return 0;
        }

        std::streamsize written = 0;

        while (written < count)
        {
            const auto available = static_cast<std::streamsize>(epptr() - pptr());
            const auto to_copy = std::min(count - written, available);

            if (to_copy > 0)
            {
                std::memcpy(pptr(), s + written, static_cast<size_t>(to_copy));
                assert(to_copy <= INT_MAX);
                pbump(static_cast<int>(to_copy));
                written += to_copy;
            }

            if (pptr() == epptr())
            {
                if (!flush_buffer())
                {
                    break;
                }
            }
        }

        return written;
    }

    bool WinFileStreamBuf::flush_buffer() noexcept
    {
        const auto count = static_cast<DWORD>(pptr() - pbase());
        if (count == 0)
        {
            return true;
        }

        // WriteFile may satisfy only part of the request, reporting success with bytes_written < count (a short write
        // on a near-full volume, a pipe-backed handle, or an interrupted write), so drain the remainder in a loop.
        // A hard error, zero-byte success, or impossible over-reported count aborts without advancing the cursor.
        const char *cursor = pbase();
        DWORD remaining = count;
        bool drained = true;
        while (remaining != 0)
        {
            DWORD bytes_written = 0;
            const BOOL result = stream_write_file(m_handle, cursor, remaining, &bytes_written);
            if (result == 0 || bytes_written == 0 || bytes_written > remaining)
            {
                drained = false;
                break;
            }
            cursor += bytes_written;
            remaining -= bytes_written;
        }

        // On a failed drain the unwritten tail is compacted to the buffer front and stays in the put area, so the
        // bytes remain recoverable by a later flush or close instead of being silently discarded with the reset.
        setp(m_buffer.data(), m_buffer.data() + BUFFER_SIZE);
        if (!drained && remaining != 0)
        {
            std::memmove(m_buffer.data(), cursor, remaining);
            pbump(static_cast<int>(remaining));
        }
        return drained;
    }

    WinFileStream::WinFileStream() : std::ostream(&m_buf) {}

    WinFileStream::WinFileStream(const std::string &path, std::ios_base::openmode mode) : std::ostream(&m_buf)
    {
        open(path, mode);
    }

    WinFileStream::~WinFileStream() noexcept = default;

    void WinFileStream::open(const std::string &path, std::ios_base::openmode mode)
    {
        clear();
        if (!m_buf.open(path, mode))
        {
            setstate(std::ios_base::failbit);
        }
    }

    void WinFileStream::open(const std::wstring &path, std::ios_base::openmode mode)
    {
        clear();
        if (!m_buf.open(path, mode))
        {
            setstate(std::ios_base::failbit);
        }
    }

    bool WinFileStream::is_open() const noexcept
    {
        return m_buf.is_open();
    }

    void WinFileStream::close() noexcept
    {
        // A failed drain or CloseHandle surfaces as failbit, matching std::ofstream::close; the buffer retains the
        // undrained tail and the handle, so the caller can observe the failure and retry.
        if (!m_buf.close())
        {
            try
            {
                setstate(std::ios_base::failbit);
            }
            catch (...)
            {
                // Only a caller-armed exception mask throws here; the failbit is already recorded.
            }
        }
    }

    Result<std::string> read_regular_file_bounded(const std::wstring &path, std::size_t max_bytes)
    {
        const HANDLE handle = CreateFileW(
            path.c_str(),
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN,
            nullptr
        );
        if (handle == INVALID_HANDLE_VALUE)
        {
            return std::unexpected(Error{ErrorCode::FileOpenFailed, "read_regular_file_bounded", GetLastError()});
        }
        class HandleGuard final
        {
        public:
            explicit HandleGuard(HANDLE handle) noexcept : m_handle(handle) {}
            ~HandleGuard() noexcept { CloseHandle(m_handle); }
            HandleGuard(const HandleGuard &) = delete;
            HandleGuard &operator=(const HandleGuard &) = delete;
            HandleGuard(HandleGuard &&) = delete;
            HandleGuard &operator=(HandleGuard &&) = delete;

        private:
            HANDLE m_handle;
        };
        const HandleGuard guard{handle};

        // A manifest is a regular disk file. A pipe, mailslot, console, or character device reports a non-disk type;
        // reading one blocks or streams bytes no size precheck can bound, so it is refused as unopenable rather than
        // trusted as a manifest source.
        if (GetFileType(handle) != FILE_TYPE_DISK)
        {
            return std::unexpected(Error{ErrorCode::FileOpenFailed, "read_regular_file_bounded"});
        }

        LARGE_INTEGER size{};
        if (GetFileSizeEx(handle, &size) == 0 || size.QuadPart < 0)
        {
            return std::unexpected(Error{ErrorCode::FileOpenFailed, "read_regular_file_bounded", GetLastError()});
        }
        if (static_cast<unsigned long long>(size.QuadPart) > static_cast<unsigned long long>(max_bytes))
        {
            return std::unexpected(Error{ErrorCode::SizeTooLarge, "read_regular_file_bounded"});
        }

        std::string content;
        const std::size_t expected_size = static_cast<std::size_t>(size.QuadPart);
        if (expected_size > content.max_size())
        {
            return std::unexpected(Error{ErrorCode::SizeTooLarge, "read_regular_file_bounded"});
        }
#if defined(DMK_ENABLE_TEST_SEAMS)
        if (g_read_regular_file_after_size_probe != nullptr)
        {
            g_read_regular_file_after_size_probe(path);
        }
#endif
        try
        {
            content.reserve(expected_size);
            std::array<char, std::size_t{64} * 1024> buffer{};
            std::size_t total = 0;
            for (;;)
            {
                DWORD read = 0;
                if (ReadFile(handle, buffer.data(), static_cast<DWORD>(buffer.size()), &read, nullptr) == 0)
                {
                    return std::unexpected(
                        Error{ErrorCode::FileOpenFailed, "read_regular_file_bounded", GetLastError()}
                    );
                }
                if (read == 0)
                {
                    break;
                }
                // Bound against the running total, not the stale precheck: a writer that extends the file after the
                // size query cannot push the read past the cap.
                const std::size_t bytes_read = static_cast<std::size_t>(read);
                if (bytes_read > max_bytes - total || bytes_read > content.max_size() - total)
                {
                    return std::unexpected(Error{ErrorCode::SizeTooLarge, "read_regular_file_bounded"});
                }
                if (bytes_read > expected_size - total)
                {
                    return std::unexpected(Error{ErrorCode::FileOpenFailed, "read_regular_file_bounded"});
                }
                content.append(buffer.data(), bytes_read);
                total += bytes_read;
            }
            if (total != expected_size)
            {
                return std::unexpected(Error{ErrorCode::FileOpenFailed, "read_regular_file_bounded"});
            }
        }
        catch (const std::bad_alloc &)
        {
            return std::unexpected(Error{ErrorCode::OutOfMemory, "read_regular_file_bounded"});
        }
        return content;
    }

} // namespace DetourModKit::detail
