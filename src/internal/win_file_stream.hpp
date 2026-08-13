#ifndef DETOURMODKIT_WIN_FILE_STREAM_HPP
#define DETOURMODKIT_WIN_FILE_STREAM_HPP

#include "DetourModKit/error.hpp"

#include <array>
#include <cstddef>
#include <ios>
#include <ostream>
#include <string>

namespace DetourModKit::detail
{
    /// Opaque Win32 HANDLE type to avoid including <windows.h> in headers.
    using WinHandle = void *;

    /**
     * @brief Reads a regular disk file whole into a string, bounded by @p max_bytes, with no partial materialization.
     * @param path Wide (UTF-16) source path.
     * @param max_bytes The largest accepted encoded size; a file at or below this reads fully, a larger one is refused.
     * @return The file bytes, or an Error: FileOpenFailed (missing, locked, denied, a directory, a non-disk special
     *         file, or an observed size differing from the precheck -- growth or truncation mid-read), SizeTooLarge
     *         (the size precheck, or a read chunk's running total, exceeds @p max_bytes), or OutOfMemory.
     * @details GetFileType excludes pipes, consoles, and devices. The running total stays capped during every read,
     *          so a growing file fails closed on whichever of the size-mismatch or cap checks its chunk trips first.
     */
    [[nodiscard]] Result<std::string> read_regular_file_bounded(const std::wstring &path, std::size_t max_bytes);

#if defined(DMK_ENABLE_TEST_SEAMS)
    extern void (*g_read_regular_file_after_size_probe)(const std::wstring &path);
    /// Replaces the WriteFile call in the buffer drain. Success sets *written to at most @p size.
    extern int (*g_win_file_write_override)(void *handle, const void *data, unsigned long size, unsigned long *written);
    /// Replaces the CloseHandle call in close(). Returns nonzero for success.
    extern int (*g_win_file_close_override)(void *handle);
#endif

    /**
     * @class WinFileStreamBuf
     * @brief Custom stream buffer using Win32 CreateFile with shared access flags.
     * @details Opens files with FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
     *          allowing external processes to read log files while they are being written. Uses an internal buffer to
     *          minimize WriteFile syscalls. A failed drain keeps the unwritten bytes buffered, so a later flush or
     *          close can retry them (`WinFileStreamBuf.*` in tests/test_win_file_stream.cpp).
     */
    class WinFileStreamBuf : public std::streambuf
    {
    public:
        static constexpr size_t BUFFER_SIZE = 8192;

        WinFileStreamBuf() noexcept;
        /// Best-effort force close: one drain attempt, then the handle is closed unconditionally.
        ~WinFileStreamBuf() noexcept override;

        WinFileStreamBuf(const WinFileStreamBuf &) = delete;
        WinFileStreamBuf &operator=(const WinFileStreamBuf &) = delete;
        WinFileStreamBuf(WinFileStreamBuf &&) = delete;
        WinFileStreamBuf &operator=(WinFileStreamBuf &&) = delete;

        /**
         * @brief Opens @p path, closing any current file first.
         * @return false when the current file cannot be closed cleanly, or the new file cannot be opened. A failed
         *         close keeps the current handle and its buffered bytes, and the new file is not created.
         */
        [[nodiscard]] bool open(const std::string &path, std::ios_base::openmode mode);
        [[nodiscard]] bool open(const std::wstring &path, std::ios_base::openmode mode);
        [[nodiscard]] bool is_open() const noexcept;
        /**
         * @brief Drains the buffer and closes the handle.
         * @return true on a complete drain and close, or when no file is open. On a failed drain the handle stays
         *         open with the unwritten bytes still buffered. On a failed CloseHandle the handle is retained, so a
         *         retry can close it; only the destructor discards a handle it could not close.
         */
        [[nodiscard]] bool close() noexcept;

    protected:
        int_type overflow(int_type ch) override;
        int sync() override;
        std::streamsize xsputn(const char *s, std::streamsize count) override;

    private:
        bool flush_buffer() noexcept;

        WinHandle m_handle;
        std::array<char, BUFFER_SIZE> m_buffer;
    };

    /**
     * @class WinFileStream
     * @brief Output stream backed by Win32 file handles with shared access.
     * @details Drop-in replacement for std::ofstream that guarantees concurrent read access from external processes on
     *          Windows. Uses WinFileStreamBuf for buffered I/O through the standard streambuf interface.
     */
    class WinFileStream : public std::ostream
    {
    public:
        WinFileStream();
        explicit WinFileStream(const std::string &path, std::ios_base::openmode mode = std::ios_base::out);
        ~WinFileStream() noexcept override;

        WinFileStream(const WinFileStream &) = delete;
        WinFileStream &operator=(const WinFileStream &) = delete;
        WinFileStream(WinFileStream &&) = delete;
        WinFileStream &operator=(WinFileStream &&) = delete;

        void open(const std::string &path, std::ios_base::openmode mode = std::ios_base::out);
        void open(const std::wstring &path, std::ios_base::openmode mode = std::ios_base::out);
        [[nodiscard]] bool is_open() const noexcept;
        /// Sets failbit when the drain or CloseHandle fails; the buffer and handle are retained for a retry.
        void close() noexcept;

    private:
        WinFileStreamBuf m_buf;
    };

} // namespace DetourModKit::detail

#endif // DETOURMODKIT_WIN_FILE_STREAM_HPP
