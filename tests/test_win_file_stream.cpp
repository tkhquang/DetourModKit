#include <gtest/gtest.h>
#include <algorithm>
#include <filesystem>
#include <fstream>
#include <string>
#include <thread>
#include <windows.h>

#include "DetourModKit/detail/win_file_stream.hpp"

using namespace DetourModKit;

class WinFileStreamBufTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        static int s_counter = 0;
        // Key the test DIRECTORY on the process id, not just the files inside it. ctest runs each test in its own
        // process and may run several concurrently (-j); with a shared directory, TearDown's remove_all() raced --
        // one process could delete the directory out from under another process's in-flight file, which surfaced as a
        // flaky failure on the longer multi-flush write. A per-process directory isolates each process so a teardown
        // only ever removes its own files.
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

// --- WinFileStreamBuf tests ---

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
    // Regression for the flush_buffer drain loop: a payload several buffers long, whose length is deliberately not a
    // buffer multiple, must round-trip byte-for-byte. This pins the loop's cursor/remaining bookkeeping -- a wrong
    // advance or a dropped tail would corrupt or shorten the output -- across both full-buffer flushes and the final
    // short flush. The position-dependent pattern catches any reordering or truncation a uniform fill would hide. A
    // genuine short WriteFile (bytes_written < count within one call) only occurs on pipes or a full volume and is not
    // forced here; this verifies the common drain path and that the refactor preserves byte-exact output.
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

// --- WinFileStream (ostream wrapper) tests ---

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

    // MultiByteToWideChar with CP_UTF8 + MB_ERR_INVALID_CHARS should fail, triggering the CP_ACP fallback path.
    bool result = buf.open(invalid_utf8, std::ios_base::out);
    if (result)
    {
        buf.close();
        // Clean up - use Win32 API since std::filesystem can't handle the name
        std::wstring wide_invalid;
        wide_invalid.resize(MAX_PATH);
        int len = MultiByteToWideChar(CP_ACP, 0, invalid_utf8.c_str(), -1, wide_invalid.data(), MAX_PATH);
        if (len > 0)
        {
            DeleteFileW(wide_invalid.c_str());
        }
    }
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
