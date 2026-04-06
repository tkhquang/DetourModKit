#include "DetourModKit/win_file_stream.hpp"

#include <windows.h>
#include <algorithm>
#include <cassert>
#include <climits>
#include <cstring>
#include <memory>

namespace DetourModKit
{
    // --- WinFileStreamBuf ---

    WinFileStreamBuf::WinFileStreamBuf() noexcept
        : handle_(INVALID_HANDLE_VALUE)
    {
        setp(buffer_.data(), buffer_.data() + BUFFER_SIZE);
    }

    WinFileStreamBuf::~WinFileStreamBuf() noexcept
    {
        close();
    }

    bool WinFileStreamBuf::open(const std::string &path, std::ios_base::openmode mode)
    {
        if (is_open())
        {
            close();
        }

        DWORD creation = CREATE_ALWAYS;
        if (mode & std::ios_base::app)
        {
            creation = OPEN_ALWAYS;
        }

        // Convert to wide string for Unicode path support.
        // Try UTF-8 first; fall back to the active code page (ACP) for callers
        // that provide ACP-encoded paths (e.g. Filesystem::get_runtime_directory).
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

        auto wide_path = std::make_unique<wchar_t[]>(static_cast<size_t>(wide_len));
        MultiByteToWideChar(code_page, 0, path.c_str(), -1, wide_path.get(), wide_len);

        handle_ = CreateFileW(
            wide_path.get(),
            GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr,
            creation,
            FILE_ATTRIBUTE_NORMAL,
            nullptr);

        if (handle_ == INVALID_HANDLE_VALUE)
        {
            return false;
        }

        if (mode & std::ios_base::app)
        {
            if (SetFilePointer(static_cast<HANDLE>(handle_), 0, nullptr, FILE_END) ==
                INVALID_SET_FILE_POINTER && GetLastError() != NO_ERROR)
            {
                CloseHandle(static_cast<HANDLE>(handle_));
                handle_ = INVALID_HANDLE_VALUE;
                return false;
            }
        }

        setp(buffer_.data(), buffer_.data() + BUFFER_SIZE);
        return true;
    }

    bool WinFileStreamBuf::is_open() const noexcept
    {
        return handle_ != INVALID_HANDLE_VALUE;
    }

    void WinFileStreamBuf::close()
    {
        if (!is_open())
        {
            return;
        }

        flush_buffer();
        CloseHandle(static_cast<HANDLE>(handle_));
        handle_ = INVALID_HANDLE_VALUE;
        setp(nullptr, nullptr);
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

    bool WinFileStreamBuf::flush_buffer()
    {
        const auto count = static_cast<DWORD>(pptr() - pbase());
        if (count == 0)
        {
            return true;
        }

        DWORD bytes_written = 0;
        const BOOL result = WriteFile(
            static_cast<HANDLE>(handle_), pbase(), count, &bytes_written, nullptr);
        setp(buffer_.data(), buffer_.data() + BUFFER_SIZE);

        return result != 0 && bytes_written == count;
    }

    // --- WinFileStream ---

    WinFileStream::WinFileStream()
        : std::ostream(&buf_)
    {
    }

    WinFileStream::WinFileStream(const std::string &path, std::ios_base::openmode mode)
        : std::ostream(&buf_)
    {
        open(path, mode);
    }

    WinFileStream::~WinFileStream() noexcept = default;

    void WinFileStream::open(const std::string &path, std::ios_base::openmode mode)
    {
        clear();
        if (!buf_.open(path, mode))
        {
            setstate(std::ios_base::failbit);
        }
    }

    bool WinFileStream::is_open() const noexcept
    {
        return buf_.is_open();
    }

    void WinFileStream::close()
    {
        buf_.close();
    }

} // namespace DetourModKit
