#ifndef DETOURMODKIT_WIN_FILE_STREAM_HPP
#define DETOURMODKIT_WIN_FILE_STREAM_HPP

#include <array>
#include <ios>
#include <ostream>
#include <string>

namespace DetourModKit
{
    /**
     * @class WinFileStreamBuf
     * @brief Custom stream buffer using Win32 CreateFile with shared access flags.
     * @details Opens files with FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
     *          allowing external processes to read log files while they are being written.
     *          Uses an internal buffer to minimize WriteFile syscalls.
     */
    class WinFileStreamBuf : public std::streambuf
    {
    public:
        static constexpr size_t BUFFER_SIZE = 8192;

        WinFileStreamBuf() noexcept;
        ~WinFileStreamBuf() noexcept override;

        WinFileStreamBuf(const WinFileStreamBuf &) = delete;
        WinFileStreamBuf &operator=(const WinFileStreamBuf &) = delete;
        WinFileStreamBuf(WinFileStreamBuf &&) = delete;
        WinFileStreamBuf &operator=(WinFileStreamBuf &&) = delete;

        bool open(const std::string &path, std::ios_base::openmode mode);
        [[nodiscard]] bool is_open() const noexcept;
        void close();

    protected:
        int_type overflow(int_type ch) override;
        int sync() override;
        std::streamsize xsputn(const char *s, std::streamsize count) override;

    private:
        bool flush_buffer();

        void *handle_; // Win32 HANDLE
        std::array<char, BUFFER_SIZE> buffer_;
    };

    /**
     * @class WinFileStream
     * @brief Output stream backed by Win32 file handles with shared access.
     * @details Drop-in replacement for std::ofstream that guarantees concurrent
     *          read access from external processes on Windows. Uses WinFileStreamBuf
     *          for buffered I/O through the standard streambuf interface.
     */
    class WinFileStream : public std::ostream
    {
    public:
        WinFileStream();
        explicit WinFileStream(const std::string &path,
                               std::ios_base::openmode mode = std::ios_base::out);
        ~WinFileStream() noexcept override;

        WinFileStream(const WinFileStream &) = delete;
        WinFileStream &operator=(const WinFileStream &) = delete;
        WinFileStream(WinFileStream &&) = delete;
        WinFileStream &operator=(WinFileStream &&) = delete;

        void open(const std::string &path, std::ios_base::openmode mode = std::ios_base::out);
        [[nodiscard]] bool is_open() const noexcept;
        void close();

    private:
        WinFileStreamBuf buf_;
    };

} // namespace DetourModKit

#endif // DETOURMODKIT_WIN_FILE_STREAM_HPP
