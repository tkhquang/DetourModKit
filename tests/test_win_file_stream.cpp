#include <gtest/gtest.h>
#include <algorithm>
#include <filesystem>
#include <fstream>
#include <memory>
#include <string>
#include <thread>
#include <windows.h>

#include "internal/win_file_stream.hpp"

#include "test_alloc_probe.hpp"

using namespace DetourModKit;
// White-box access to the non-installed Win32 stream implementation.
using namespace DetourModKit::detail;

#if defined(DMK_ENABLE_TEST_SEAMS)
namespace
{
    long long s_resize_after_probe_bytes = 0;
    bool s_resize_after_probe_succeeded = false;

    void resize_after_size_probe(const std::wstring &path)
    {
        const HANDLE handle =
            CreateFileW(path.c_str(), GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (handle == INVALID_HANDLE_VALUE)
        {
            s_resize_after_probe_succeeded = false;
            return;
        }
        const std::unique_ptr<void, decltype(&CloseHandle)> handle_guard{handle, &CloseHandle};
        LARGE_INTEGER target{};
        target.QuadPart = s_resize_after_probe_bytes;
        s_resize_after_probe_succeeded =
            SetFilePointerEx(handle, target, nullptr, FILE_BEGIN) != 0 && SetEndOfFile(handle) != 0;
    }

    class ResizeAfterProbeScope final
    {
    public:
        explicit ResizeAfterProbeScope(long long bytes) noexcept
        {
            s_resize_after_probe_bytes = bytes;
            s_resize_after_probe_succeeded = false;
            g_read_regular_file_after_size_probe = &resize_after_size_probe;
        }

        ~ResizeAfterProbeScope() noexcept { g_read_regular_file_after_size_probe = nullptr; }
        ResizeAfterProbeScope(const ResizeAfterProbeScope &) = delete;
        ResizeAfterProbeScope &operator=(const ResizeAfterProbeScope &) = delete;
        ResizeAfterProbeScope(ResizeAfterProbeScope &&) = delete;
        ResizeAfterProbeScope &operator=(ResizeAfterProbeScope &&) = delete;
    };
} // namespace
#endif

class WinFileStreamBufTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        static int s_counter = 0;
        // A process-specific directory prevents concurrent ctest processes from deleting one another's files.
        m_test_dir = std::filesystem::temp_directory_path() / ("dmk_wfs_test_" + std::to_string(GetCurrentProcessId()));
        std::filesystem::create_directories(m_test_dir);
        m_test_path = m_test_dir / ("wfs_" + std::to_string(s_counter++) + ".txt");
    }

    void TearDown() override
    {
        std::error_code ec;
        std::filesystem::remove_all(m_test_dir, ec);
    }

    std::string read_file(const std::filesystem::path &path)
    {
        std::ifstream in(path, std::ios::binary);
        return {std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
    }

    std::filesystem::path m_test_dir;
    std::filesystem::path m_test_path;
};

// WinFileStreamBuf tests

TEST_F(WinFileStreamBufTest, DefaultConstruct_NotOpen)
{
    WinFileStreamBuf buf;
    EXPECT_FALSE(buf.is_open());
}

TEST_F(WinFileStreamBufTest, Open_NarrowPath_Success)
{
    WinFileStreamBuf buf;
    EXPECT_TRUE(buf.open(m_test_path.string(), std::ios_base::out));
    EXPECT_TRUE(buf.is_open());
    buf.close();
    EXPECT_FALSE(buf.is_open());
}

TEST_F(WinFileStreamBufTest, Open_WidePath_Success)
{
    WinFileStreamBuf buf;
    EXPECT_TRUE(buf.open(m_test_path.wstring(), std::ios_base::out));
    EXPECT_TRUE(buf.is_open());
    buf.close();
}

TEST_F(WinFileStreamBufTest, Open_InvalidDirectory_Fails)
{
    WinFileStreamBuf buf;
    EXPECT_FALSE(buf.open("Z:\\nonexistent_dir_xyz\\file.txt", std::ios_base::out));
    EXPECT_FALSE(buf.is_open());
}

TEST_F(WinFileStreamBufTest, Open_AppendMode_CreatesFile)
{
    {
        WinFileStreamBuf buf;
        ASSERT_TRUE(buf.open(m_test_path.string(), std::ios_base::out));
        const char msg[] = "first";
        buf.sputn(msg, 5);
        buf.close();
    }

    {
        WinFileStreamBuf buf;
        ASSERT_TRUE(buf.open(m_test_path.string(), std::ios_base::out | std::ios_base::app));
        const char msg[] = "second";
        buf.sputn(msg, 6);
        buf.close();
    }

    const auto content = read_file(m_test_path);
    EXPECT_EQ(content, "firstsecond");
}

TEST_F(WinFileStreamBufTest, AppendMode_ConcurrentAppendersPreserveEveryByte)
{
    // FILE_APPEND_DATA makes each WriteFile land at the current end of file atomically, so two handles appending to
    // one file preserve every byte regardless of interleave order. A GENERIC_WRITE handle plus a one-time
    // SetFilePointer(FILE_END) seek would let the second writer's write land at the stale opening offset and clobber
    // the first writer's region.
    constexpr int per_writer = 4000;

    auto append_run = [&](char fill)
    {
        WinFileStreamBuf buf;
        ASSERT_TRUE(buf.open(m_test_path.string(), std::ios_base::out | std::ios_base::app));
        const std::string data(per_writer, fill);
        buf.sputn(data.c_str(), static_cast<std::streamsize>(data.size()));
        buf.close();
    };

    std::thread t1([&] { append_run('A'); });
    std::thread t2([&] { append_run('B'); });
    t1.join();
    t2.join();

    const auto content = read_file(m_test_path);
    EXPECT_EQ(content.size(), static_cast<size_t>(per_writer * 2));
    EXPECT_EQ(std::count(content.begin(), content.end(), 'A'), per_writer);
    EXPECT_EQ(std::count(content.begin(), content.end(), 'B'), per_writer);
}

TEST_F(WinFileStreamBufTest, Open_AppendMode_NewFile)
{
    WinFileStreamBuf buf;
    ASSERT_TRUE(buf.open(m_test_path.string(), std::ios_base::out | std::ios_base::app));
    const char msg[] = "hello";
    buf.sputn(msg, 5);
    buf.close();

    EXPECT_EQ(read_file(m_test_path), "hello");
}

TEST_F(WinFileStreamBufTest, Reopen_ClosesExistingHandle)
{
    WinFileStreamBuf buf;
    ASSERT_TRUE(buf.open(m_test_path.string(), std::ios_base::out));

    auto second_path = m_test_path;
    second_path.replace_extension(".second.txt");
    ASSERT_TRUE(buf.open(second_path.string(), std::ios_base::out));

    EXPECT_TRUE(buf.is_open());
    buf.close();
}

TEST_F(WinFileStreamBufTest, Close_WhenAlreadyClosed_NoOp)
{
    WinFileStreamBuf buf;
    buf.close();
    buf.close();
    EXPECT_FALSE(buf.is_open());
}

TEST_F(WinFileStreamBufTest, Sync_WhenClosed_ReturnsNegative)
{
    WinFileStreamBuf buf;
    EXPECT_EQ(buf.pubsync(), -1);
}

TEST_F(WinFileStreamBufTest, Sync_WhenOpen_ReturnsZero)
{
    WinFileStreamBuf buf;
    ASSERT_TRUE(buf.open(m_test_path.string(), std::ios_base::out));
    EXPECT_EQ(buf.pubsync(), 0);
    buf.close();
}

TEST_F(WinFileStreamBufTest, Overflow_AfterClose_ReturnsEOF)
{
    WinFileStreamBuf buf;
    ASSERT_TRUE(buf.open(m_test_path.string(), std::ios_base::out));
    buf.close();

    // After close(), setp(nullptr, nullptr) is called, so the next sputc immediately invokes overflow(), which returns
    // EOF for a closed stream.
    EXPECT_EQ(buf.sputc('A'), std::char_traits<char>::eof());
}

TEST_F(WinFileStreamBufTest, Overflow_WhenOpen_WritesChar)
{
    WinFileStreamBuf buf;
    ASSERT_TRUE(buf.open(m_test_path.string(), std::ios_base::out));

    // Write BUFFER_SIZE - 1 bytes via sputn (fills buffer without flushing)
    std::string filler(WinFileStreamBuf::BUFFER_SIZE - 1, 'X');
    buf.sputn(filler.c_str(), static_cast<std::streamsize>(filler.size()));

    // sputc fills the last slot (no overflow yet, just pptr == epptr)
    buf.sputc('Z');

    // Now pptr == epptr; next sputc triggers overflow() -> flush -> insert
    auto result = buf.sputc('Y');
    EXPECT_NE(result, std::char_traits<char>::eof());

    buf.close();

    auto content = read_file(m_test_path);
    EXPECT_EQ(content.size(), WinFileStreamBuf::BUFFER_SIZE + 1);
    EXPECT_EQ(content.back(), 'Y');
}

TEST_F(WinFileStreamBufTest, Xsputn_WhenClosed_ReturnsZero)
{
    WinFileStreamBuf buf;
    const char data[] = "test";
    EXPECT_EQ(buf.sputn(data, 4), 0);
}

TEST_F(WinFileStreamBufTest, Xsputn_LargeWrite_MultipleFlushes)
{
    WinFileStreamBuf buf;
    ASSERT_TRUE(buf.open(m_test_path.string(), std::ios_base::out));

    // Write more than 2x buffer size to force multiple flushes
    const size_t size = WinFileStreamBuf::BUFFER_SIZE * 3;
    std::string data(size, 'A');
    const auto written = buf.sputn(data.c_str(), static_cast<std::streamsize>(size));
    EXPECT_EQ(static_cast<size_t>(written), size);

    buf.close();
    EXPECT_EQ(read_file(m_test_path).size(), size);
}

TEST_F(WinFileStreamBufTest, Xsputn_LargeWrite_ByteExactAcrossFlushBoundaries)
{
    // The flush_buffer drain loop: a payload several buffers long, whose length is deliberately not a buffer
    // multiple, must round-trip byte-for-byte. This pins the loop's cursor/remaining bookkeeping -- a wrong advance
    // or a dropped tail would corrupt or shorten the output -- across both full-buffer flushes and the final short
    // flush. The position-dependent pattern catches any reordering or truncation a uniform fill would hide. A
    // genuine short WriteFile (bytes_written < count within one call) only occurs on pipes or a full volume and is
    // not forced here; this verifies the common drain path stays byte-exact.
    WinFileStreamBuf buf;
    ASSERT_TRUE(buf.open(m_test_path.string(), std::ios_base::out));

    const size_t size = WinFileStreamBuf::BUFFER_SIZE * 4 + 123;
    std::string data(size, '\0');
    for (size_t i = 0; i < size; ++i)
    {
        data[i] = static_cast<char>((i * 31u + 7u) & 0xFFu);
    }

    const auto written = buf.sputn(data.c_str(), static_cast<std::streamsize>(size));
    EXPECT_EQ(static_cast<size_t>(written), size);
    buf.close();

    const auto content = read_file(m_test_path);
    ASSERT_EQ(content.size(), size);
    EXPECT_TRUE(content == data);
}

TEST_F(WinFileStreamBufTest, Xsputn_ZeroCount_ReturnsZero)
{
    WinFileStreamBuf buf;
    ASSERT_TRUE(buf.open(m_test_path.string(), std::ios_base::out));
    EXPECT_EQ(buf.sputn("test", 0), 0);
    buf.close();
}

TEST_F(WinFileStreamBufTest, DestructorFlushes_RAII)
{
    {
        WinFileStreamBuf buf;
        ASSERT_TRUE(buf.open(m_test_path.string(), std::ios_base::out));
        const char msg[] = "raii_data";
        buf.sputn(msg, 9);
        // Destructor should flush and close
    }
    EXPECT_EQ(read_file(m_test_path), "raii_data");
}

// WinFileStream (ostream wrapper) tests

class WinFileStreamTest : public WinFileStreamBufTest
{
};

TEST_F(WinFileStreamTest, DefaultConstruct_NotOpen)
{
    WinFileStream stream;
    EXPECT_FALSE(stream.is_open());
}

TEST_F(WinFileStreamTest, ConstructWithPath_OpensFile)
{
    WinFileStream stream(m_test_path.string());
    EXPECT_TRUE(stream.is_open());
    EXPECT_TRUE(stream.good());
}

TEST_F(WinFileStreamTest, ConstructWithPath_InvalidPath_SetsFailbit)
{
    WinFileStream stream("Z:\\nonexistent_dir_xyz\\file.txt");
    EXPECT_FALSE(stream.is_open());
    EXPECT_TRUE(stream.fail());
}

TEST_F(WinFileStreamTest, Open_NarrowPath_Success)
{
    WinFileStream stream;
    stream.open(m_test_path.string());
    EXPECT_TRUE(stream.is_open());
    EXPECT_TRUE(stream.good());
}

TEST_F(WinFileStreamTest, Open_WidePath_Success)
{
    WinFileStream stream;
    stream.open(m_test_path.wstring());
    EXPECT_TRUE(stream.is_open());
    EXPECT_TRUE(stream.good());
}

TEST_F(WinFileStreamTest, Open_InvalidNarrowPath_SetsFailbit)
{
    WinFileStream stream;
    stream.open("Z:\\nonexistent_dir_xyz\\file.txt");
    EXPECT_FALSE(stream.is_open());
    EXPECT_TRUE(stream.fail());
}

TEST_F(WinFileStreamTest, Open_InvalidWidePath_SetsFailbit)
{
    WinFileStream stream;
    stream.open(std::wstring(L"Z:\\nonexistent_dir_xyz\\file.txt"));
    EXPECT_FALSE(stream.is_open());
    EXPECT_TRUE(stream.fail());
}

TEST_F(WinFileStreamTest, StreamWrite_VerifyContent)
{
    {
        WinFileStream stream(m_test_path.string());
        ASSERT_TRUE(stream.is_open());
        stream << "Hello, " << 42 << "!";
        stream.flush();
    }
    EXPECT_EQ(read_file(m_test_path), "Hello, 42!");
}

TEST_F(WinFileStreamTest, Close_ExplicitClose)
{
    WinFileStream stream(m_test_path.string());
    ASSERT_TRUE(stream.is_open());
    stream.close();
    EXPECT_FALSE(stream.is_open());
}

TEST_F(WinFileStreamTest, DestructorFlushes_RAII)
{
    {
        WinFileStream stream(m_test_path.string());
        ASSERT_TRUE(stream.is_open());
        stream << "destructor_test";
    }
    EXPECT_EQ(read_file(m_test_path), "destructor_test");
}

TEST_F(WinFileStreamTest, ConcurrentRead_WhileWriting)
{
    WinFileStream stream(m_test_path.string());
    ASSERT_TRUE(stream.is_open());
    stream << "shared_access";
    stream.flush();

    // FILE_SHARE_READ should allow concurrent reads
    HANDLE h = CreateFileW(m_test_path.wstring().c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    EXPECT_NE(h, INVALID_HANDLE_VALUE);
    if (h != INVALID_HANDLE_VALUE)
    {
        CloseHandle(h);
    }
}

TEST_F(WinFileStreamTest, AppendMode_AppendsToExisting)
{
    {
        WinFileStream stream(m_test_path.string());
        stream << "part1";
    }
    {
        WinFileStream stream;
        stream.open(m_test_path.string(), std::ios_base::out | std::ios_base::app);
        ASSERT_TRUE(stream.is_open());
        stream << "part2";
    }
    EXPECT_EQ(read_file(m_test_path), "part1part2");
}

TEST_F(WinFileStreamTest, FlushBuffer_EmptyBuffer_Succeeds)
{
    WinFileStream stream(m_test_path.string());
    ASSERT_TRUE(stream.is_open());
    // Flush without writing anything
    stream.flush();
    EXPECT_TRUE(stream.good());
}

TEST_F(WinFileStreamBufTest, Open_AcpFallback_InvalidUtf8)
{
    WinFileStreamBuf buf;
    // Build a path string with invalid UTF-8 bytes directly, bypassing std::filesystem::path which throws on invalid
    // sequences.
    std::string dir = m_test_dir.string();
    std::string invalid_utf8 = dir + "\\test_\x80\x81.txt";

    // Pre-compute the ACP wide name with the same flags the fallback uses (CP_ACP, no MB_ERR_INVALID_CHARS), so the
    // assertions below can observe the created file under the identical conversion.
    std::wstring wide_invalid;
    wide_invalid.resize(MAX_PATH);
    const int len = MultiByteToWideChar(CP_ACP, 0, invalid_utf8.c_str(), -1, wide_invalid.data(), MAX_PATH);
    ASSERT_GT(len, 0);

    // MultiByteToWideChar with CP_UTF8 + MB_ERR_INVALID_CHARS fails on the byte sequence, so a successful open in an
    // existing directory proves the CP_ACP fallback ran; the file must then exist under the ACP-converted name.
    ASSERT_TRUE(buf.open(invalid_utf8, std::ios_base::out));
    EXPECT_TRUE(buf.is_open());
    buf.close();
    EXPECT_NE(GetFileAttributesW(wide_invalid.c_str()), INVALID_FILE_ATTRIBUTES);
    DeleteFileW(wide_invalid.c_str());
}

TEST_F(WinFileStreamTest, ConstructWithPath_WritesData)
{
    // Exercises constructor WinFileStream(const std::string&, openmode)
    WinFileStream stream(m_test_path.string(), std::ios_base::out);
    ASSERT_TRUE(stream.is_open());
    stream << "ctor_test";
    stream.close();
    EXPECT_EQ(read_file(m_test_path), "ctor_test");
}

TEST_F(WinFileStreamTest, DefaultConstruct_ThenOpen_ThenWrite)
{
    // Exercises default constructor + separate open
    WinFileStream stream;
    EXPECT_FALSE(stream.is_open());
    stream.open(m_test_path.string());
    ASSERT_TRUE(stream.is_open());
    stream << "default_ctor";
    stream.close();
    EXPECT_EQ(read_file(m_test_path), "default_ctor");
}

TEST_F(WinFileStreamTest, Destructor_ClosesFile)
{
    // Verify the destructor properly closes by checking no handle leak
    {
        WinFileStream stream(m_test_path.string());
        stream << "dtor_test";
    }
    // After destruction, we should be able to open and truncate the file
    WinFileStream stream2(m_test_path.string());
    EXPECT_TRUE(stream2.is_open());
    stream2 << "overwritten";
    stream2.close();
    EXPECT_EQ(read_file(m_test_path), "overwritten");
}

// read_regular_file_bounded: the bounded manifest reader.

TEST_F(WinFileStreamBufTest, ReadBounded_ReadsRegularFileWhole)
{
    const std::string payload = "manifest bytes\r\nline two\r\n";
    {
        std::ofstream out(m_test_path, std::ios::binary);
        out << payload;
    }
    const auto content = read_regular_file_bounded(m_test_path.wstring(), 4096);
    ASSERT_TRUE(content.has_value()) << content.error().message();
    EXPECT_EQ(*content, payload);
}

TEST_F(WinFileStreamBufTest, ReadBounded_ZeroByteFileReturnsEmptySuccess)
{
    {
        std::ofstream out(m_test_path, std::ios::binary);
    }
    const auto content = read_regular_file_bounded(m_test_path.wstring(), 4096);
    ASSERT_TRUE(content.has_value()) << content.error().message();
    EXPECT_TRUE(content->empty());
}

TEST_F(WinFileStreamBufTest, ReadBounded_AcceptsFileExactlyAtCap)
{
    const std::string payload(64, 'b');
    {
        std::ofstream out(m_test_path, std::ios::binary);
        out << payload;
    }
    const auto content = read_regular_file_bounded(m_test_path.wstring(), payload.size());
    ASSERT_TRUE(content.has_value()) << content.error().message();
    EXPECT_EQ(*content, payload);
}

TEST_F(WinFileStreamBufTest, ReadBounded_RejectsOversizeFile)
{
    {
        std::ofstream out(m_test_path, std::ios::binary);
        out << std::string(64, 'x');
    }
    const auto content = read_regular_file_bounded(m_test_path.wstring(), 16);
    ASSERT_FALSE(content.has_value());
    EXPECT_EQ(content.error().code, ErrorCode::SizeTooLarge);
}

TEST_F(WinFileStreamBufTest, ReadBounded_RejectsMissingFile)
{
    const auto content = read_regular_file_bounded(L"Z:\\nonexistent_dir_xyz\\missing.bin", 4096);
    ASSERT_FALSE(content.has_value());
    EXPECT_EQ(content.error().code, ErrorCode::FileOpenFailed);
}

TEST_F(WinFileStreamBufTest, ReadBounded_RejectsSpecialFile)
{
    // The NUL device is a character device, not a regular disk file; reading it would never satisfy a size precheck,
    // so GetFileType != FILE_TYPE_DISK refuses it as unopenable.
    const auto content = read_regular_file_bounded(L"\\\\.\\NUL", 4096);
    ASSERT_FALSE(content.has_value());
    EXPECT_EQ(content.error().code, ErrorCode::FileOpenFailed);
}

#if defined(DMK_ENABLE_TEST_SEAMS)
TEST_F(WinFileStreamBufTest, ReadBounded_RejectsGrowthAfterSizeProbe)
{
    {
        std::ofstream out(m_test_path, std::ios::binary);
        out << std::string(32, 'g');
    }
    const ResizeAfterProbeScope resize_scope{128};
    const auto content = read_regular_file_bounded(m_test_path.wstring(), 64);
    EXPECT_TRUE(s_resize_after_probe_succeeded);
    ASSERT_FALSE(content.has_value());
    EXPECT_EQ(content.error().code, ErrorCode::SizeTooLarge);
}

// Growth that would cross the cap only in a LATER 64 KiB read chunk is caught by the precheck-mismatch clause, not
// the running-total cap: the first chunk already exceeds the probed size, so the read fails closed as FileOpenFailed
// before the total can reach the cap. This pins the mismatch clause apart from the cap clause (the single-chunk case
// above reports SizeTooLarge): removing the mismatch clause changes this arm's code, not merely its timing.
TEST_F(WinFileStreamBufTest, ReadBounded_GrowthPastChunkedCapFailsAtSizeMismatch)
{
    {
        std::ofstream out(m_test_path, std::ios::binary);
        out << std::string(32, 'g');
    }
    const ResizeAfterProbeScope resize_scope{128 * 1024};
    const auto content = read_regular_file_bounded(m_test_path.wstring(), 100 * 1024);
    EXPECT_TRUE(s_resize_after_probe_succeeded);
    ASSERT_FALSE(content.has_value());
    EXPECT_EQ(content.error().code, ErrorCode::FileOpenFailed);
}

TEST_F(WinFileStreamBufTest, ReadBounded_RejectsShortReadAfterSizeProbe)
{
    {
        std::ofstream out(m_test_path, std::ios::binary);
        out << std::string(64, 's');
    }
    const ResizeAfterProbeScope resize_scope{16};
    const auto content = read_regular_file_bounded(m_test_path.wstring(), 128);
    EXPECT_TRUE(s_resize_after_probe_succeeded);
    ASSERT_FALSE(content.has_value());
    EXPECT_EQ(content.error().code, ErrorCode::FileOpenFailed);
}
#endif

TEST_F(WinFileStreamBufTest, ReadBounded_AllocationFailureIsTyped)
{
    DMK_REQUIRE_PROXY_FREE_STL();
    {
        std::ofstream out(m_test_path, std::ios::binary);
        out << std::string(200, 'y');
    }
    const std::wstring path = m_test_path.wstring();
    bool ok = false;
    ErrorCode code = ErrorCode::Ok;
    {
        dmk_test::AllocFailScope guard(0); // fail the content allocation
        const auto content = read_regular_file_bounded(path, 4096);
        ok = content.has_value();
        if (!ok)
        {
            code = content.error().code;
        }
    }
    EXPECT_FALSE(ok);
    EXPECT_EQ(code, ErrorCode::OutOfMemory);

    // The failed allocation left nothing behind: the identical read succeeds once memory returns.
    const auto retry = read_regular_file_bounded(path, 4096);
    ASSERT_TRUE(retry.has_value());
    EXPECT_EQ(retry->size(), 200u);
}
